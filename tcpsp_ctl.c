/*
 * tcpsp_ctl.c: control handling ([gs]setsockopt and /proc/sys/net/tcpsp)
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
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/types.h>
#include <linux/errno.h>
#include <linux/fs.h>
#include <linux/sysctl.h>
#include <linux/proc_fs.h>
#include <linux/timer.h>
#include <linux/swap.h>
#include <linux/proc_fs.h>
#include <linux/file.h>

#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>

#include <net/ip.h>
#include <net/sock.h>

#include <asm/uaccess.h>

#include "tcpsp.h"
//#include <net/tcpsp.h>

/* semaphore for TCPSP sockopts. And, [gs]etsockopt may sleep. */
static DECLARE_MUTEX(__tcpsp_mutex);

/* sysctl variables */

#ifdef CONFIG_TCPSP_DEBUG
static int sysctl_tcpsp_debug_level = 0;

int tcpsp_get_debug_level(void)
{
	return sysctl_tcpsp_debug_level;
}
#endif


/*
 *      TCPSP sysctl variables under the /proc/sys/net/tcpsp/
 */
#define NET_TCPSP              21

enum {
	NET_TCPSP_DEBUG_LEVEL=1,
	NET_TCPSP_TO_ES=7,
	NET_TCPSP_TO_SS=8,
	NET_TCPSP_TO_SR=9,
	NET_TCPSP_TO_FW=10,
	NET_TCPSP_TO_TW=11,
	NET_TCPSP_TO_CL=12,
	NET_TCPSP_TO_CW=13,
	NET_TCPSP_TO_LA=14,
	NET_TCPSP_TO_LI=15,
	NET_TCPSP_TO_SA=16,
	NET_TCPSP_LAST
};


/*
 *      TCPSP sysctl table
 */
struct tcpsp_sysctl_table {
	struct ctl_table_header *sysctl_header;
	ctl_table tcpsp_vars[NET_TCPSP_LAST];
	ctl_table tcpsp_dir[2];
	ctl_table root_dir[2];
};


static struct tcpsp_sysctl_table tcpsp_table = {
	NULL,
	{{NET_TCPSP_TO_ES, "timeout_established",
	  &tcpsp_timeout_tbl.timeout[TCPSP_S_ESTABLISHED],
	  sizeof(int), 0644, NULL, &proc_dointvec_jiffies},
	 {NET_TCPSP_TO_SS, "timeout_synsent",
	  &tcpsp_timeout_tbl.timeout[TCPSP_S_SYN_SENT],
	  sizeof(int), 0644, NULL, &proc_dointvec_jiffies},
	 {NET_TCPSP_TO_SR, "timeout_synrecv",
	  &tcpsp_timeout_tbl.timeout[TCPSP_S_SYN_RECV],
	  sizeof(int), 0644, NULL, &proc_dointvec_jiffies},
	 {NET_TCPSP_TO_FW, "timeout_finwait",
	  &tcpsp_timeout_tbl.timeout[TCPSP_S_FIN_WAIT],
	  sizeof(int), 0644, NULL, &proc_dointvec_jiffies},
	 {NET_TCPSP_TO_TW, "timeout_timewait",
	  &tcpsp_timeout_tbl.timeout[TCPSP_S_TIME_WAIT],
	  sizeof(int), 0644, NULL, &proc_dointvec_jiffies},
	 {NET_TCPSP_TO_CL, "timeout_close",
	  &tcpsp_timeout_tbl.timeout[TCPSP_S_CLOSE],
	  sizeof(int), 0644, NULL, &proc_dointvec_jiffies},
	 {NET_TCPSP_TO_CW, "timeout_closewait",
	  &tcpsp_timeout_tbl.timeout[TCPSP_S_CLOSE_WAIT],
	  sizeof(int), 0644, NULL, &proc_dointvec_jiffies},
	 {NET_TCPSP_TO_LA, "timeout_lastack",
	  &tcpsp_timeout_tbl.timeout[TCPSP_S_LAST_ACK],
	  sizeof(int), 0644, NULL, &proc_dointvec_jiffies},
	 {NET_TCPSP_TO_LI, "timeout_listen",
	  &tcpsp_timeout_tbl.timeout[TCPSP_S_LISTEN],
	  sizeof(int), 0644, NULL, &proc_dointvec_jiffies},
	 {NET_TCPSP_TO_SA, "timeout_synack",
	  &tcpsp_timeout_tbl.timeout[TCPSP_S_SYNACK],
	  sizeof(int), 0644, NULL, &proc_dointvec_jiffies},
#ifdef CONFIG_TCPSP_DEBUG
	 {NET_TCPSP_DEBUG_LEVEL, "debug_level",
	  &sysctl_tcpsp_debug_level, sizeof(int), 0644, NULL,
	  &proc_dointvec},
#endif
	 {0}},
	{{NET_TCPSP, "tcpsp", NULL, 0, 0555, tcpsp_table.tcpsp_vars},
	 {0}},
	{{CTL_NET, "net", NULL, 0, 0555, tcpsp_table.tcpsp_dir},
	 {0}}
};


#if 0
static inline struct socket *socki_lookup(struct inode *inode)
{
	return &inode->u.socket_i;
}

static struct socket *sockfd_lookup(int fd, int *err)
{
	struct file *file;
	struct inode *inode;
	struct socket *sock;

	if (!(file = fget(fd))) {
		*err = -EBADF;
		return NULL;
	}

	inode = file->f_dentry->d_inode;
	if (!inode->i_sock || !(sock = socki_lookup(inode))) {
		*err = -ENOTSOCK;
		fput(file);
		return NULL;
	}

	if (sock->file != file) {
		printk(KERN_ERR "socki_lookup: socket file changed!\n");
		sock->file = file;
	}
	return sock;
}
#endif

static inline void sockfd_put(struct socket *sock)
{
	fput(sock->file);
}


int sys_tcpsplicing(int fd1, int fd2, int n)
{
	struct socket *sock1, *sock2;
	struct tcpsp_conn *cp;
	int err = 0;

	if (!(sock1 = sockfd_lookup(fd1, &err)))
		goto out;
	if (!(sock2 = sockfd_lookup(fd2, &err)))
		goto out_put_sock1;

	if (!(cp = tcpsp_conn_new(sock1, sock2, n)))
		err = -ENOMEM;
	else
		tcpsp_conn_put(cp);

	sockfd_put(sock2);
  out_put_sock1:
	sockfd_put(sock1);
  out:
	return err;
}


/* this interface is ugly, will be changed to system call */
static int
do_tcpsp_set_ctl(struct sock *sk, int cmd, void *user, unsigned int len)
{
	int ret;
	splice_conn_t sp;

	if (!capable(CAP_NET_ADMIN))
		return -EPERM;

	if (len != sizeof(sp)) {
		TCPSP_ERR("set_ctl: len %u != %u\n", len, sizeof(sp));
		return -EINVAL;
	} else if (copy_from_user(&sp, user, len) != 0)
		return -EFAULT;

	MOD_INC_USE_COUNT;
	if (down_interruptible(&__tcpsp_mutex)) {
		ret = -ERESTARTSYS;
		goto out_dec;
	}

	switch (cmd) {
	case TCPSP_SO_SET_ADD:
		ret = sys_tcpsplicing(sp.s1, sp.s2, sp.n);
		break;
	default:
		ret = -EINVAL;
	}

	up(&__tcpsp_mutex);
  out_dec:
	MOD_DEC_USE_COUNT;
	return ret;
}


static int
do_tcpsp_get_ctl(struct sock *sk, int cmd, void *user, int *len)
{
	int ret = 0;

	if (!capable(CAP_NET_ADMIN))
		return -EPERM;

	if (down_interruptible(&__tcpsp_mutex))
		return -ERESTARTSYS;

	switch (cmd) {
	case TCPSP_SO_GET_VERSION:
	{
		char buf[64];

		sprintf(buf, "TCP Splicing version %d.%d.%d (size=%d)",
			NVERSION(TCPSP_VERSION_CODE), TCPSP_CONN_TAB_SIZE);
		if (*len < strlen(buf)+1)
			return -EINVAL;
		if (copy_to_user(user, buf, strlen(buf)+1) != 0)
			return -EFAULT;
		*len = strlen(buf)+1;
	}
	break;

	default:
		ret = -EINVAL;
	}

	up(&__tcpsp_mutex);
	return ret;
}


static struct nf_sockopt_ops tcpsp_sockopts = {
	{ NULL, NULL }, PF_INET,
	TCPSP_BASE_CTL, TCPSP_SO_SET_MAX+1, do_tcpsp_set_ctl,
	TCPSP_BASE_CTL, TCPSP_SO_GET_MAX+1, do_tcpsp_get_ctl
};


int tcpsp_control_init(void)
{
	int ret;

	EnterFunction(2);

	ret = nf_register_sockopt(&tcpsp_sockopts);
	if (ret) {
		TCPSP_ERR("cannot register sockopt.\n");
		return ret;
	}

	tcpsp_table.sysctl_header =
		register_sysctl_table(tcpsp_table.root_dir, 0);

	LeaveFunction(2);
	return 0;
}

void tcpsp_control_cleanup(void)
{
	EnterFunction(2);
	unregister_sysctl_table(tcpsp_table.sysctl_header);
	nf_unregister_sockopt(&tcpsp_sockopts);
	LeaveFunction(2);
}
