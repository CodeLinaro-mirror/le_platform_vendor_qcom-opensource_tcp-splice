/*
 * tcpsp_conn.c: connection tracking for tcp splicing
 *
 * Version:     $Id$
 *
 * Authors:     Wensong Zhang <wensong@linux-vs.org>
 *
 *              This program is free software; you can redistribute it and/or
 *              modify it under the terms of the GNU General Public License
 *              as published by the Free Software Foundation; either version
 *              2 of the License, or (at your option) any later version.
 *
 * Changes:
 *
 */

#include <linux/config.h>
#include <linux/module.h>
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/vmalloc.h>
#include <linux/ip.h>
#include <linux/tcp.h>                  /* for tcphdr */
#include <linux/in.h>
#include <linux/proc_fs.h>              /* for proc_net_* */
#include <asm/softirq.h>                /* for local_bh_* */
#include <net/ip.h>
#include <net/tcp.h>                    /* for csum_tcpudp_magic */
#include <net/udp.h>
#include <net/icmp.h>                   /* for icmp_send */
#include <net/route.h>                  /* for ip_route_output */

#include <linux/socket.h>

#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>

#include "tcpsp.h"
//#include <net/tcpsp.h>


EXPORT_SYMBOL(tcpsp_conn_new);

/*  SLAB cache for tcpsp connections */
static kmem_cache_t *tcpsp_conn_cachep;

/* tcpsp onnection hash tables */
#define TCPSP_NTABLES		2
static struct list_head *tcpsp_conn_tab1;
static struct list_head *tcpsp_conn_tab2;

static rwlock_t tcpsp_conn_lock = RW_LOCK_UNLOCKED;

/*  counter for current tcpsp connections */
static atomic_t tcpsp_conn_count = ATOMIC_INIT(0);


/*
 *	Returns hash value for tcpsp connection entry
 */
static inline unsigned
tcpsp_conn_hash_key(__u32 addr, __u16 port)
{
	unsigned addrh = ntohl(addr);

	return (addrh^(addrh>>TCPSP_CONN_TAB_BITS)^ntohs(port))
		& TCPSP_CONN_TAB_MASK;
}


/*
 *	Hashes tcpsp_conn in tcpsp_conn_tabs by <addr,port>.
 *	returns bool success.
 */
int tcpsp_conn_hash(struct tcpsp_conn *cp)
{
	unsigned hash;

	if (cp->flags & TCPSP_CONN_F_HASHED) {
		TCPSP_ERR("tcpsp_conn_hash(): request for already hashed, "
			  "called from %p\n", __builtin_return_address(0));
		return 0;
	}

	write_lock(&tcpsp_conn_lock);
	hash = tcpsp_conn_hash_key(cp->conn[0].raddr, cp->conn[0].rport);
	list_add(&cp->f_list, &tcpsp_conn_tab1[hash]);

	hash = tcpsp_conn_hash_key(cp->conn[1].laddr, cp->conn[1].lport);
	list_add(&cp->s_list, &tcpsp_conn_tab2[hash]);

	cp->flags |= TCPSP_CONN_F_HASHED;
	atomic_add(TCPSP_NTABLES, &cp->refcnt);
	write_unlock(&tcpsp_conn_lock);
	return 1;
}


/*
 *	UNhashes tcpsp_conn from tcpsp_conn_tabs.
 *	returns bool success.
 */
int tcpsp_conn_unhash(struct tcpsp_conn *cp)
{
	if (!(cp->flags & TCPSP_CONN_F_HASHED)) {
		TCPSP_ERR("tcpsp_conn_unhash(): request for unhash flagged, "
			  "called from %p\n", __builtin_return_address(0));
		return 0;
	}
	write_lock(&tcpsp_conn_lock);
	list_del(&cp->f_list);
	list_del(&cp->s_list);
	cp->flags &= ~TCPSP_CONN_F_HASHED;
	atomic_sub(TCPSP_NTABLES, &cp->refcnt);
	write_unlock(&tcpsp_conn_lock);
	return 1;
}


struct tcpsp_conn *
tcpsp_conn_get(__u32 saddr, __u16 sport, __u32 daddr, __u16 dport, int *dir)
{
	unsigned hash;
	struct list_head *e;
	struct tcpsp_conn *cp;
	struct conn_tuple *t;

	read_lock(&tcpsp_conn_lock);

	hash = tcpsp_conn_hash_key(saddr, sport);
	list_for_each (e, &tcpsp_conn_tab1[hash]) {
		cp = list_entry(e, struct tcpsp_conn, f_list);
		t = &cp->conn[0];
		if (saddr == t->raddr && sport == t->rport &&
		    dport == t->lport && daddr == t->laddr) {
			/* HIT */
			*dir = FROM_FIRST_CONN;
			atomic_inc(&cp->refcnt);
			read_unlock(&tcpsp_conn_lock);
			return cp;
		}
	}

	hash = tcpsp_conn_hash_key(daddr, dport);
	list_for_each (e, &tcpsp_conn_tab2[hash]) {
		cp = list_entry(e, struct tcpsp_conn, s_list);
		t = &cp->conn[1];
		if (dport == t->lport && daddr == t->laddr &&
		    saddr == t->raddr && sport == t->rport) {
			/* HIT */
			*dir = FROM_SECOND_CONN;
			atomic_inc(&cp->refcnt);
			read_unlock(&tcpsp_conn_lock);
			return cp;
		}
	}

	read_unlock(&tcpsp_conn_lock);

	return NULL;
}


/*
 *      Put back the conn and restart its timer with its timeout
 */
void tcpsp_conn_put(struct tcpsp_conn *cp)
{
	/* reset it expire in its timeout */
	mod_timer(&cp->timer, jiffies+cp->timeout);

	__tcpsp_conn_put(cp);
}


/*
 *	Timeout table[state]
 */
struct tcpsp_timeout_table tcpsp_timeout_tbl = {
	ATOMIC_INIT(0),	/* refcnt */
	0,		/* scale  */
	{
		[TCPSP_S_NONE]          =	3*60*HZ,
		[TCPSP_S_ESTABLISHED]	=	15*60*HZ,
		[TCPSP_S_SYN_SENT]	=	2*60*HZ,
		[TCPSP_S_SYN_RECV]	=	1*60*HZ,
		[TCPSP_S_FIN_WAIT]	=	2*60*HZ,
		[TCPSP_S_TIME_WAIT]	=	2*60*HZ,
		[TCPSP_S_CLOSE]         =	10*HZ,
		[TCPSP_S_CLOSE_WAIT]	=	60*HZ,
		[TCPSP_S_LAST_ACK]	=	30*HZ,
		[TCPSP_S_LISTEN]	=	2*60*HZ,
		[TCPSP_S_SYNACK]	=	120*HZ,
		[TCPSP_S_LAST]          =	2*HZ,
	},	/* timeout */
};


static const char * state_name_table[TCPSP_S_LAST+1] = {
	[TCPSP_S_NONE]          =	"NONE",
	[TCPSP_S_ESTABLISHED]	=	"ESTABLISHED",
	[TCPSP_S_SYN_SENT]	=	"SYN_SENT",
	[TCPSP_S_SYN_RECV]	=	"SYN_RECV",
	[TCPSP_S_FIN_WAIT]	=	"FIN_WAIT",
	[TCPSP_S_TIME_WAIT]	=	"TIME_WAIT",
	[TCPSP_S_CLOSE]         =	"CLOSE",
	[TCPSP_S_CLOSE_WAIT]	=	"CLOSE_WAIT",
	[TCPSP_S_LAST_ACK]	=	"LAST_ACK",
	[TCPSP_S_LISTEN]	=	"LISTEN",
	[TCPSP_S_SYNACK]	=	"SYNACK",
	[TCPSP_S_LAST]          =	"BUG!",
};

#define sNO TCPSP_S_NONE
#define sES TCPSP_S_ESTABLISHED
#define sSS TCPSP_S_SYN_SENT
#define sSR TCPSP_S_SYN_RECV
#define sFW TCPSP_S_FIN_WAIT
#define sTW TCPSP_S_TIME_WAIT
#define sCL TCPSP_S_CLOSE
#define sCW TCPSP_S_CLOSE_WAIT
#define sLA TCPSP_S_LAST_ACK
#define sLI TCPSP_S_LISTEN
#define sSA TCPSP_S_SYNACK

struct tcpsp_states_t {
	int next_state[TCPSP_S_LAST];	/* should be _LAST_TCP */
};

const char * tcpsp_state_name(int state)
{
	if (state >= TCPSP_S_LAST)
		return "ERR!";
	return state_name_table[state] ? state_name_table[state] : "?";
}

static struct tcpsp_states_t tcpsp_states[] = {
/*	INPUT */
/*        sNO, sES, sSS, sSR, sFW, sTW, sCL, sCW, sLA, sLI, sSA	*/
/*syn*/ {{sSR, sES, sES, sSR, sSR, sSR, sSR, sSR, sSR, sSR, sSR }},
/*fin*/ {{sCL, sCW, sSS, sTW, sTW, sTW, sCL, sCW, sLA, sLI, sTW }},
/*ack*/ {{sCL, sES, sSS, sES, sFW, sTW, sCL, sCW, sCL, sLI, sES }},
/*rst*/ {{sCL, sCL, sCL, sSR, sCL, sCL, sCL, sCL, sLA, sLI, sSR }},

/*	OUTPUT */
/*        sNO, sES, sSS, sSR, sFW, sTW, sCL, sCW, sLA, sLI, sSA	*/
/*syn*/ {{sSS, sES, sSS, sSR, sSS, sSS, sSS, sSS, sSS, sLI, sSR }},
/*fin*/ {{sTW, sFW, sSS, sTW, sFW, sTW, sCL, sTW, sLA, sLI, sTW }},
/*ack*/ {{sES, sES, sSS, sES, sFW, sTW, sCL, sCW, sLA, sES, sES }},
/*rst*/ {{sCL, sCL, sSS, sCL, sCL, sTW, sCL, sCL, sCL, sCL, sCL }},
};

static struct tcpsp_states_t *tcpsp_state_table = tcpsp_states;


static inline int tcp_state_idx(struct tcphdr *th, int state_off)
{
	/*
	 *	[0-3]: input states, [4-7]: output, [8-11] input only states.
	 */
	if (th->rst)
		return state_off+3;
	if (th->syn)
		return state_off+0;
	if (th->fin)
		return state_off+1;
	if (th->ack)
		return state_off+2;
	return -1;
}


static inline int set_state_timeout(struct tcpsp_conn *cp, int state)
{
	struct tcpsp_timeout_table *tt = cp->timeout_table;

	/*
	 *	Use default timeout table if no specific for this entry
	 */
	if (!tt)
		tt = &tcpsp_timeout_tbl;

	cp->timeout = tt->timeout[cp->state=state];

	if (tt->scale) {
		int scale = tt->scale;

		if (scale<0)
			cp->timeout >>= -scale;
		else if (scale > 0)
			cp->timeout <<= scale;
	}

	return state;
}


static inline int
set_state(struct tcpsp_conn *cp, int state_off, struct tcphdr *th)
{
	int state_idx;
	int new_state = TCPSP_S_CLOSE;

	if ((state_idx = tcp_state_idx(th, state_off)) < 0) {
		TCPSP_DBG(8, "tcp_state_idx(%d)=%d!!!\n",
			  state_off, state_idx);
		goto tcp_state_out;
	}

	new_state = tcpsp_state_table[state_idx].next_state[cp->state];
	TCPSP_DBG(18, "new state %s\n", tcpsp_state_name(new_state));

  tcp_state_out:

	return set_state_timeout(cp, new_state);
}


/*
 *	Handle state transitions
 */
int tcpsp_set_state(struct tcpsp_conn *cp,
		    int direction, struct iphdr *iph, struct tcphdr *th)
{
	int ret;

	spin_lock(&cp->lock);
	switch (iph->protocol) {
	case IPPROTO_TCP:
		ret = set_state(cp, direction*4, th);
		break;
	default:
		ret = -1;
	}
	spin_unlock(&cp->lock);

	return ret;
}


/*
 *	tcpsp transmitter
 */
static int tcpsp_xmit(struct sk_buff *skb)
{
	struct rtable *rt;			/* Route to the other host */
	struct iphdr  *iph = skb->nh.iph;
	u8     tos = iph->tos;
	int    mtu;

	EnterFunction(7);

	if (ip_route_output(&rt, iph->daddr, 0, RT_TOS(tos), 0)) {
		TCPSP_DBG_RL("tcpsp_xmit(): ip_route_output error, "
			     "dest: %u.%u.%u.%u\n", NIPQUAD(iph->daddr));
		goto tx_error_icmp;
	}

	/* MTU checking ??? */
	mtu = rt->u.dst.pmtu;
	if ((skb->len > mtu) && (iph->frag_off&__constant_htons(IP_DF))) {
		icmp_send(skb, ICMP_DEST_UNREACH,ICMP_FRAG_NEEDED, htonl(mtu));
		ip_rt_put(rt);
		TCPSP_DBG_RL("tcpsp_xmit(): frag needed\n");
		goto tx_error;
	}

	/* drop old route */
	dst_release(skb->dst);
	skb->dst = &rt->u.dst;

#ifdef CONFIG_NETFILTER_DEBUG
	skb->nf_debug = 1 << NF_IP_LOCAL_OUT;
#endif /* CONFIG_NETFILTER_DEBUG */
	ip_send(skb);

	LeaveFunction(7);
	return NF_STOLEN;

  tx_error_icmp:
	dst_link_failure(skb);
  tx_error:
	kfree_skb(skb);
	return NF_STOLEN;
}


/*
 *  Bind a connection entry with the corresponding packet_xmit.
 *  Called by tcpsp_conn_new.
 */
static inline void tcpsp_bind_xmit(struct tcpsp_conn *cp)
{
	cp->packet_xmit = tcpsp_xmit;
}


static inline void
tcpsp_timeout_attach(struct tcpsp_conn *cp, struct tcpsp_timeout_table *tt)
{
	atomic_inc(&tt->refcnt);
	cp->timeout_table = tt;
}

static inline void tcpsp_timeout_detach(struct tcpsp_conn *cp)
{
	struct tcpsp_timeout_table *tt = cp->timeout_table;

	if (!tt)
		return;
	cp->timeout_table = NULL;
	atomic_dec(&tt->refcnt);
}


static void tcpsp_conn_expire(unsigned long data)
{
	struct tcpsp_conn *cp = (struct tcpsp_conn *)data;

	if (cp->timeout_table)
		cp->timeout = cp->timeout_table->timeout[TCPSP_S_TIME_WAIT];
	else
		cp->timeout = tcpsp_timeout_tbl.timeout[TCPSP_S_TIME_WAIT];

	/*
	 *	hey, I'm using it
	 */
	atomic_inc(&cp->refcnt);

	/*
	 *	unhash it if it is hashed in the conn table
	 */
	tcpsp_conn_unhash(cp);

	/*
	 *	refcnt==1 implies I'm the only one referrer
	 */
	if (atomic_read(&cp->refcnt) == 1) {
		/* make sure that there is no timer on it now */
		if (timer_pending(&cp->timer))
			del_timer(&cp->timer);

		tcpsp_timeout_detach(cp);
		atomic_dec(&tcpsp_conn_count);

		kmem_cache_free(tcpsp_conn_cachep, cp);
		goto expire_out;
	}

	TCPSP_DBG(5, "delayed: refcnt-1=%d\n", atomic_read(&cp->refcnt)-1);
	tcpsp_conn_put(cp);

  expire_out:
}

static void tcp_reset_timer(unsigned long data)
{
	struct sock *sk = (struct sock *)data;

	TCPSP_DBG(5, "set sock ECONNRESET\n");
	sk->err = ECONNRESET;
	if (!sk->dead)
		sk->error_report(sk);

	tcp_done(sk);
}

static inline void
tcpsp_add_reset_timer(struct timer_list *timer, struct sock *sk,
		      unsigned long when)
{
	init_timer(timer);
	timer->function = tcp_reset_timer;
	timer->data = (unsigned long) sk;
	timer->expires = jiffies + when;
	add_timer(timer);
}

static inline void fill_conn_tuple(struct conn_tuple *t, struct sock *sk)
{
	struct tcp_opt *tp = &(sk->tp_pinfo.af_tcp);

	t->laddr = sk->rcv_saddr;
	t->lport = sk->sport;
	t->raddr = sk->daddr;
	t->rport = sk->dport;

	t->splice_iss = tp->snd_nxt;
	t->splice_irs = tp->rcv_nxt;
}

/*
 *  Create and hash a new tcpsp into the tcpsp_conn_tabs.
 */
struct tcpsp_conn *
tcpsp_conn_new(struct socket *sock1, struct socket *sock2, int n)
{
	struct tcp_opt *tp1, *tp2;
	struct tcpsp_conn *cp;

	cp = kmem_cache_alloc(tcpsp_conn_cachep, GFP_ATOMIC);
	if (cp == NULL) {
		TCPSP_ERR_RL("tcpsp_conn_new: no memory available.\n");
		return NULL;
	}

	memset(cp, 0, sizeof(*cp));
	cp->lock = SPIN_LOCK_UNLOCKED;
	init_timer(&cp->timer);
	cp->timer.data = (unsigned long) cp;
	cp->timer.function = tcpsp_conn_expire;
	tcpsp_timeout_attach(cp, &tcpsp_timeout_tbl);

	fill_conn_tuple(&cp->conn[0], sock1->sk);
	fill_conn_tuple(&cp->conn[1], sock2->sk);

	cp->conn[1].splice_iss += n;

	atomic_inc(&tcpsp_conn_count);

	/* Set its state and timeout */
	if (sock1->sk->state == TCP_ESTABLISHED
	    && sock2->sk->state == TCP_ESTABLISHED)
		set_state_timeout(cp, TCPSP_S_ESTABLISHED);
	else /* probably need to consider other states here */
		set_state_timeout(cp, TCPSP_S_NONE);

	/* Bind its packet transmitter */
	tcpsp_bind_xmit(cp);

	atomic_set(&cp->refcnt, 1);

	/* Hash it in the tcpsp_conn_tab finally */
	tcpsp_conn_hash(cp);

	tp1 = &(sock1->sk->tp_pinfo.af_tcp);
	tp2 = &(sock2->sk->tp_pinfo.af_tcp);
	TCPSP_DBG(5, "sock1: rcv_nxt %u snd_nxt %u snd_una %u\n",
		  tp1->rcv_nxt, tp1->snd_nxt, tp1->snd_una);
	TCPSP_DBG(5, "sock2: rcv_nxt %u snd_nxt %u snd_una %u\n",
		  tp2->rcv_nxt, tp2->snd_nxt, tp2->snd_una);
	TCPSP_DBG(5, "sock2: iss %u  irs %u\n",
		  cp->conn[1].splice_iss, cp->conn[1].splice_irs);

	tcp_reset_timer((unsigned long)sock1->sk);
#if 0
	/* give the user-space program a second to send data */
	tcpsp_add_reset_timer(&cp->rst_timer[1], sock2->sk, HZ);
#endif

	return cp;
}


/*
 *	/proc/net/tcpsp_conn entries
 */
static int
tcpsp_conn_getinfo(char *buffer, char **start, off_t offset, int length)
{
	off_t pos=0;
	int idx, len=0;
	char temp[70];
	struct tcpsp_conn *cp;
	struct list_head *l, *e;

	pos = 128;
	if (pos > offset) {
		len += sprintf(buffer+len, "%-127s\n",
			       "FromIP   FPrt ToIP     TPrt LocalIP  LPrt DestIP   DPrt State       Expires");
	}

	for(idx = 0; idx < TCPSP_CONN_TAB_SIZE; idx++) {
		/*
		 *	Lock is actually only need in next loop
		 *	we are called from uspace: must stop bh.
		 */
		read_lock_bh(&tcpsp_conn_lock);

		l = &tcpsp_conn_tab1[idx];
		for (e=l->next; e!=l; e=e->next) {
			cp = list_entry(e, struct tcpsp_conn, f_list);
			pos += 128;
			if (pos <= offset)
				continue;
			sprintf(temp,
				"%08X %04X %08X %04X %08X %04X %08X %04X %-11s %7lu",
				ntohl(cp->conn[0].raddr),
				ntohs(cp->conn[0].rport),
				ntohl(cp->conn[0].laddr),
				ntohs(cp->conn[0].lport),
				ntohl(cp->conn[1].laddr),
				ntohs(cp->conn[1].lport),
				ntohl(cp->conn[1].raddr),
				ntohs(cp->conn[1].rport),
				tcpsp_state_name(cp->state),
				cp->timer.expires-jiffies);
			len += sprintf(buffer+len, "%-127s\n", temp);
			if (pos >= offset+length) {
				read_unlock_bh(&tcpsp_conn_lock);
				goto done;
			}
		}
		read_unlock_bh(&tcpsp_conn_lock);
	}

  done:
	*start = buffer+len-(pos-offset);       /* Start of wanted data */
	len = pos-offset;
	if (len > length)
		len = length;
	if (len < 0)
		len = 0;
	return len;
}


/*
 *      Flush all the connection entries in the tcpsp_conn_tab
 */
static void tcpsp_conn_flush(void)
{
	int idx;
	struct tcpsp_conn *cp;
	struct list_head *l,*e;

 flush_again:
	for (idx=0; idx<TCPSP_CONN_TAB_SIZE; idx++) {
		/*
		 *  Lock is actually needed in this loop.
		 */
		write_lock(&tcpsp_conn_lock);

		l = &tcpsp_conn_tab1[idx];
		for (e=l->next; e!=l; e=e->next) {
			cp = list_entry(e, struct tcpsp_conn, f_list);
			write_unlock(&tcpsp_conn_lock);
			TCPSP_DBG(4, "del splicing connection\n");
			if (del_timer(&cp->timer))
				tcpsp_conn_expire_now(cp);

			write_lock(&tcpsp_conn_lock);
		}
		write_unlock(&tcpsp_conn_lock);
	}

	/* the counter may be not NULL, because maybe some conn entries
	   are run by slow timer handler or unhashed but still referred */
	if (atomic_read(&tcpsp_conn_count) != 0) {
		schedule();
		goto flush_again;
	}
}


int tcpsp_conn_init(void)
{
	int idx;

	/*
	 * Allocate the connection hash table and initialize its list heads
	 */
	if (!(tcpsp_conn_tab1 =
	      vmalloc(TCPSP_CONN_TAB_SIZE * sizeof(struct list_head))))
		return -ENOMEM;

	if (!(tcpsp_conn_tab2 =
	      vmalloc(TCPSP_CONN_TAB_SIZE * sizeof(struct list_head)))) {
		vfree(tcpsp_conn_tab1);
		return -ENOMEM;
	}

	/* Allocate tcpsp_conn slab cache */
	tcpsp_conn_cachep = kmem_cache_create("tcpsp_conn",
					      sizeof(struct tcpsp_conn), 0,
					      SLAB_HWCACHE_ALIGN, NULL, NULL);
	if (!tcpsp_conn_cachep) {
		vfree(tcpsp_conn_tab1);
		vfree(tcpsp_conn_tab2);
		return -ENOMEM;
	}

	TCPSP_INFO("Connection hash table configured "
		   "(size=%d, memory=%ldKbytes)\n",
		   TCPSP_CONN_TAB_SIZE,
		   (long)(TCPSP_CONN_TAB_SIZE*sizeof(struct list_head))/1024);
	TCPSP_DBG(0, "Each connection entry needs %d bytes at least\n",
		  sizeof(struct tcpsp_conn));

	for (idx = 0; idx < TCPSP_CONN_TAB_SIZE; idx++) {
		INIT_LIST_HEAD(&tcpsp_conn_tab1[idx]);
		INIT_LIST_HEAD(&tcpsp_conn_tab2[idx]);
	}

	proc_net_create("tcpsp_conn", 0, tcpsp_conn_getinfo);

	return 0;
}

void tcpsp_conn_cleanup(void)
{
	/* flush all the connection entries first */
	tcpsp_conn_flush();

	/* Release the empty cache */
	kmem_cache_destroy(tcpsp_conn_cachep);
	proc_net_remove("tcpsp_conn");
	vfree(tcpsp_conn_tab1);
	vfree(tcpsp_conn_tab2);
}
