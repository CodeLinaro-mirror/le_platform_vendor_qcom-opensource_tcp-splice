/***************************************************************************
*
* Copyright (c) 2017, The Linux Foundation. All rights reserved.
*
* This program is free software; you can redistribute it and/or modify
* it under the terms of the GNU General Public License version 2 and
* only version 2 as published by the Free Software Foundation.
*
* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
* GNU General Public License for more details.
*
***************************************************************************/

/***************************************************************************
*
* Copyright (C) 2002 Wensong Zhang <wensong@linux-vs.org>
*
* This program is free software; you can redistribute it and/or
* modify it under the terms of the GNU General Public License
* as published by the Free Software Foundation; either version
* 2 of the License, or (at your option) any later version.
*
***************************************************************************/

/***************************************************************************
*
* File: tcp-splice-interface.c
*
* Description: Provides functions to interfacing with userspace.
*
***************************************************************************/

#include "tcp-splice-interface.h"

extern int debug_mode;
extern struct sock* nl_socket;
extern struct sockaddr_nl userspace_addr;
extern struct hlist_head tcp_splice_ht[1 << TCP_SPLICE_HASH_INDEX_SHIFT_SIZE];
extern spinlock_t ht_lock;
extern struct hlist_head tcp_splice_pdn_ht[1 << TCP_SPLICE_PDN_HASH_INDEX_SHIFT_SIZE];
extern unsigned int pdn_offload_size;
extern spinlock_t ht_pdn_lock;
/***************************************************************************
*
* Function: listenFromUserspace
*
* Description: callback for listening to netlink msgs from userspace
*
* Parameters: struct sk_buff* skb; //skb for netlink msg
*
* Return: none
*
***************************************************************************/
void listenFromUserspace(struct sk_buff* skb)
{
  struct nlmsghdr* nlh;

  if(NULL == skb)
  {
    pr_debug(MODULE_NAME": %s skb NULL!\n", __func__);
    return;
  }

  nlh = (struct nlmsghdr*)skb->data;

  pr_info(MODULE_NAME": %s received netlink msg from userspace pid: %u\n", __func__,
          nlh->nlmsg_pid);

  userspace_addr.nl_pid = nlh->nlmsg_pid;

  return;
}

/***************************************************************************
*
* Function: sendToUserspace
*
* Description: send netlink msg to userspace that the socket pair fd has
*              seen a FIN or RST
*
* Parameters: struct tcp_splice_hash_entry* hash_entry; //socket pair fd
*
* Return: none
*
***************************************************************************/
void sendToUserspace(struct tcp_splice_hash_entry* hash_entry)
{
  struct nlmsghdr* nlmhdr;
  struct sk_buff* skb;
  struct userspace_relay_session* data_ptr;

  if(NULL == hash_entry)
  {
    pr_debug(MODULE_NAME": %s hash_entry NULL!\n", __func__);
    return;
  }

  //allocate new skb, nlmsg_unicast takes care of the freeing
  if((skb = nlmsg_new(sizeof(struct userspace_relay_session), GFP_ATOMIC)) == NULL)
  {
    pr_debug(MODULE_NAME": %s skb NULL!\n", __func__);
    return;
  }

  //attach the payload to the skb
  if((nlmhdr = nlmsg_put(skb, 0, 0, NLMSG_DONE, sizeof(struct userspace_relay_session), 0)) == NULL)
  {
    pr_debug(MODULE_NAME": %s nlmhdr NULL!\n", __func__);
    kfree_skb(skb);
    return;
  }

  //we're not multicast
  NETLINK_CB(skb).dst_group = 0;

  //ptr to the head of the payload
  if((data_ptr = (struct userspace_relay_session*)NLMSG_DATA(nlmhdr)) == NULL)
  {
    pr_debug(MODULE_NAME": %s data_ptr NULL!\n", __func__);
    kfree_skb(skb);
    return;
  }

  *data_ptr = hash_entry->session_info.r_session;

  if(nlmsg_unicast(nl_socket, skb, userspace_addr.nl_pid) < 0)
  {
    pr_err(MODULE_NAME": %s error sending netlink msg to userspace\n", __func__);
  }

  pr_debug(MODULE_NAME": %s notification of FIN socket pair sent to userspace\n",__func__);

  return;
}

/***************************************************************************
*
* Function: tcp_splice_socket
*
* Description: callback for setsockopt SO_TCP_SPLICE
*
* Parameters: struct sock* sk; //socket fd
*             int optval; option value
*             void __user *user; user data
*             unsigned int len; option length
*
* Return: 0, success
*        -1, otherwise
*
***************************************************************************/
#ifdef ISKERNEL5_15
int tcp_splice_socket(struct sock* sk, int optval, sockptr_t arg, unsigned int len)
#else
int tcp_splice_socket(struct sock* sk, int optval, void __user *user, unsigned int len)
#endif
{
  int err = 0;
  struct tcp_splice_session_info splice_session_info;

  if(NULL == sk)
  {
    pr_err(MODULE_NAME": %s sock NULL!\n", __func__);
    return -EINVAL;
#ifdef ISKERNEL5_15
  } else if(NULL == arg.user)
#else
  } else if(NULL == user)
#endif
  {
    pr_err(MODULE_NAME": %s user NULL!\n", __func__);
    return -EINVAL;
  }

  //not checking for capabilities of user
  switch(optval)
  {
    case SO_TCP_SPLICE:
    {
      //copy_from_user and not using netlink socket because filling out the socket
      //splice info needs to be scheduled now
#ifdef ISKERNEL5_15
      if(copy_from_user(&(splice_session_info.r_session), arg.user, len) != 0)
#else
      if(copy_from_user(&(splice_session_info.r_session), user, len) != 0)
#endif
      {
        pr_err(MODULE_NAME": %s error copying from userspace\n", __func__);
        return -EINVAL;
      }

      if((splice_session_info.cli_socket = sockfd_lookup(splice_session_info.r_session.cli_fd,
                                                          &err)) == NULL)
      {
        pr_err(MODULE_NAME": %s error looking up client socket from given userspace fd: "
              "%d\n", __func__, err);
        return -EBADF;
      }
      sockfd_put(splice_session_info.cli_socket);

      if((splice_session_info.req_socket = sockfd_lookup(splice_session_info.r_session.req_fd,
                                                          &err)) == NULL)
      {

        pr_err(MODULE_NAME": %s error looking up req socket from given userspace fd: "
              "%d\n", __func__, err);
        return -EBADF;
      }
      sockfd_put(splice_session_info.req_socket);

      if(debug_mode)
      {
        printSessionInfo(&splice_session_info);
      }

      if(insertSpliceInfoTuple(&splice_session_info) != 0)
      {
        pr_debug(MODULE_NAME": %s error with inserting tcp splice info tuple setsockopt\n",
                 __func__);
        return -EBADF;
      }

      pr_debug(MODULE_NAME": %s setsockopt tcpsplice successful\n", __func__);
      break;
    }
    default:
    {
      pr_err(MODULE_NAME": %s error, wrong tcpsplice setsockopt\n",__func__);
      return -EBADF;
    }
  }

  return 0;

}

/***************************************************************************
*
* Function: insertSpliceInfoTuple
*
* Description: inserts tcp splice info into global hash table
*
* Parameters: struct tcp_splice_session_info* sp_session; //ptr to tcp splice session
*
* Return: 0, success
*        -1, otherwise
*
***************************************************************************/
int insertSpliceInfoTuple(struct tcp_splice_session_info* sp_session)
{
  unsigned char i;
  int j, ipa_handle = TCP_SPLICE_MIN_IPA_HANDLE;
  unsigned int rcv_queue_bytes;
  unsigned int key[2]; //first key will be for client, second key for req
  struct nf_conntrack_tuple conn_tuple[2]; //index 0 for client, index 1 for req
  struct sk_buff* skb;
  struct nf_conntrack_tuple_hash* cli_conn_hash = NULL;
  struct nf_conntrack_tuple_hash* req_conn_hash = NULL;
  struct nf_conn* cli_ct = NULL;
  struct nf_conn* req_ct = NULL;
  struct tcp_sock* cli_tcp_sock = NULL;
  struct tcp_sock* req_tcp_sock = NULL;
  struct tcp_splice_hash_entry* hash_entry = NULL;
  unsigned int pdn_hash_key = 0;

  if(NULL == sp_session)
  {
    pr_err(MODULE_NAME": %s splice session NULL!\n", __func__);
    return -EINVAL;
  }

  cli_tcp_sock = tcp_sk(sp_session->cli_socket->sk);
  req_tcp_sock = tcp_sk(sp_session->req_socket->sk);

  memset(conn_tuple, 0, sizeof(conn_tuple));

  //generate cli direction key
  switch(sp_session->cli_socket->sk->sk_family)
  {
    case AF_INET:
    {
      conn_tuple[0].src.l3num = AF_INET;
      conn_tuple[0].src.u3.ip = sp_session->cli_socket->sk->sk_rcv_saddr;
      conn_tuple[0].src.u.tcp.port = htons(sp_session->cli_socket->sk->sk_num);
      conn_tuple[0].dst.u3.ip = sp_session->cli_socket->sk->sk_daddr;
      conn_tuple[0].dst.u.tcp.port = sp_session->cli_socket->sk->sk_dport;
      conn_tuple[0].dst.protonum = sp_session->cli_socket->sk->sk_protocol;
      conn_tuple[0].dst.dir = IP_CT_DIR_ORIGINAL;
#ifdef ISKERNELABOVE_4_9
      if((cli_conn_hash = nf_conntrack_find_get(sock_net(sp_session->cli_socket->sk),
                                                NF_CT_DEFAULT_ZONE_ID, &conn_tuple[0])) == NULL)
      {
        pr_debug(MODULE_NAME": %s couldn't find get the client socket conntrack hash\n",
                 __func__);
        return -EBADF;
      }
#else
      if((cli_conn_hash = nf_conntrack_find_get(sock_net(sp_session->cli_socket->sk),
                                                NF_CT_DEFAULT_ZONE, &conn_tuple[0])) == NULL)
      {
        pr_debug(MODULE_NAME": %s couldn't find get the client socket conntrack hash\n",
                 __func__);
        return -EBADF;
      }
#endif
      if((cli_ct = nf_ct_tuplehash_to_ctrack(cli_conn_hash)) == NULL)
      {
        pr_debug(MODULE_NAME": %s couldn't convert client hash to "
                 "conntrack entry\n", __func__);
        return -EBADF;
      }

      key[0] = sp_session->cli_socket->sk->sk_daddr ^ sp_session->cli_socket->sk->sk_dport ^
               htons(sp_session->cli_socket->sk->sk_num);

      break;
    }
    case AF_INET6:
    {
      conn_tuple[0].src.l3num = AF_INET6;
      memcpy((void*)&conn_tuple[0].src.u3.in6,
             (void*)&sp_session->cli_socket->sk->sk_v6_rcv_saddr.in6_u, sizeof(struct in6_addr));
      conn_tuple[0].src.u.tcp.port = htons(sp_session->cli_socket->sk->sk_num);
      memcpy((void*)&conn_tuple[0].dst.u3.in6,
             (void*)&sp_session->cli_socket->sk->sk_v6_daddr.in6_u, sizeof(struct in6_addr));
      conn_tuple[0].dst.u.tcp.port = sp_session->cli_socket->sk->sk_dport;
      conn_tuple[0].dst.protonum = sp_session->cli_socket->sk->sk_protocol;
      conn_tuple[0].dst.dir = IP_CT_DIR_ORIGINAL;
#ifdef ISKERNELABOVE_4_9
      if((cli_conn_hash = nf_conntrack_find_get(sock_net(sp_session->cli_socket->sk),
                                            NF_CT_DEFAULT_ZONE_ID, &conn_tuple[0])) == NULL)
      {
        pr_debug(MODULE_NAME": %s couldn't find get the client socket conntrack hash\n",
                 __func__);
        return -EBADF;
      }
#else
      if((cli_conn_hash = nf_conntrack_find_get(sock_net(sp_session->cli_socket->sk),
                                            NF_CT_DEFAULT_ZONE, &conn_tuple[0])) == NULL)
      {
        pr_debug(MODULE_NAME": %s couldn't find get the client socket conntrack hash\n",
                 __func__);
        return -EBADF;
      }
#endif
      if((cli_ct = nf_ct_tuplehash_to_ctrack(cli_conn_hash)) == NULL)
      {
        pr_debug(MODULE_NAME": %s couldn't convert client hash to conntrack entry\n",
                 __func__);
        return -EBADF;
      }

      key[0] = sp_session->cli_socket->sk->sk_v6_daddr.in6_u.u6_addr32[0] ^
               sp_session->cli_socket->sk->sk_dport ^ htons(sp_session->cli_socket->sk->sk_num);
      break;
    }
    default:
    {
      pr_err(MODULE_NAME": %s cli socket not AF_INET or AF_INET6 family\n", __func__);
      break;
    }
  }

  //generate req direction key
  switch(sp_session->req_socket->sk->sk_family)
  {
    case AF_INET:
    {
      conn_tuple[1].src.l3num = AF_INET;
      conn_tuple[1].src.u3.ip = sp_session->req_socket->sk->sk_rcv_saddr;
      conn_tuple[1].src.u.tcp.port = htons(sp_session->req_socket->sk->sk_num);
      conn_tuple[1].dst.u3.ip = sp_session->req_socket->sk->sk_daddr;
      conn_tuple[1].dst.u.tcp.port = sp_session->req_socket->sk->sk_dport;
      conn_tuple[1].dst.protonum = sp_session->req_socket->sk->sk_protocol;
      conn_tuple[1].dst.dir = IP_CT_DIR_ORIGINAL;
#ifdef ISKERNELABOVE_4_9
      if((req_conn_hash = nf_conntrack_find_get(sock_net(sp_session->req_socket->sk),
                                                NF_CT_DEFAULT_ZONE_ID, &conn_tuple[1])) == NULL)
      {
        pr_debug(MODULE_NAME": %s couldn't find get the req socket conntrack hash\n",
                 __func__);
        nf_ct_put(cli_ct); //clean up
        return -EBADF;
      }
#else
      if((req_conn_hash = nf_conntrack_find_get(sock_net(sp_session->req_socket->sk),
                                                NF_CT_DEFAULT_ZONE, &conn_tuple[1])) == NULL)
      {
        pr_debug(MODULE_NAME": %s couldn't find get the req socket conntrack hash\n",
                 __func__);
        nf_ct_put(cli_ct); //clean up
        return -EBADF;
      }
#endif
      if((req_ct = nf_ct_tuplehash_to_ctrack(req_conn_hash)) == NULL)
      {
        pr_debug(MODULE_NAME": %s couldn't convert req hash to conntrack entry\n",
                 __func__);
        nf_ct_put(cli_ct); //clean up
        return -EBADF;
      }

      key[1] = sp_session->req_socket->sk->sk_daddr ^ sp_session->req_socket->sk->sk_dport ^
               htons(sp_session->req_socket->sk->sk_num);
      break;
    }
    case AF_INET6:
    {
      conn_tuple[1].src.l3num = AF_INET6;
      memcpy((void*)&conn_tuple[1].src.u3.in6,
             (void*)&sp_session->req_socket->sk->sk_v6_rcv_saddr.in6_u, sizeof(struct in6_addr));
      conn_tuple[1].src.u.tcp.port = htons(sp_session->req_socket->sk->sk_num);
      memcpy((void*)&conn_tuple[1].dst.u3.in6,
             (void*)&sp_session->req_socket->sk->sk_v6_daddr.in6_u, sizeof(struct in6_addr));
      conn_tuple[1].dst.u.tcp.port = sp_session->req_socket->sk->sk_dport;
      conn_tuple[1].dst.protonum = sp_session->req_socket->sk->sk_protocol;
      conn_tuple[1].dst.dir = IP_CT_DIR_ORIGINAL;
#ifdef ISKERNELABOVE_4_9
      if((req_conn_hash = nf_conntrack_find_get(sock_net(sp_session->req_socket->sk),
                                            NF_CT_DEFAULT_ZONE_ID, &conn_tuple[1])) == NULL)
      {
        pr_debug(MODULE_NAME": %s couldn't find get the req socket conntrack hash\n",
                 __func__);
        nf_ct_put(cli_ct); //clean up
        return -EBADF;
      }
#else
      if((req_conn_hash = nf_conntrack_find_get(sock_net(sp_session->req_socket->sk),
                                            NF_CT_DEFAULT_ZONE, &conn_tuple[1])) == NULL)
      {
        pr_debug(MODULE_NAME": %s couldn't find get the req socket conntrack hash\n",
                 __func__);
        nf_ct_put(cli_ct); //clean up
        return -EBADF;
      }
#endif
      if((req_ct = nf_ct_tuplehash_to_ctrack(req_conn_hash)) == NULL)
      {
        pr_debug(MODULE_NAME": %s couldn't convert req hash to conntrack entry\n",
                 __func__);
        nf_ct_put(cli_ct); //clean up
        return -EBADF;
      }

      key[1] = sp_session->req_socket->sk->sk_v6_daddr.in6_u.u6_addr32[0] ^
               sp_session->req_socket->sk->sk_dport ^ htons(sp_session->req_socket->sk->sk_num);
      break;
    }
    default:
    {
      pr_err(MODULE_NAME": %s req socket not AF_INET or AF_INET6 family\n", __func__);
      break;
    }
  }

  pr_debug(MODULE_NAME": insertSpliceInfoTuple: hash_key[0] = %u\n", key[0]);
  pr_debug(MODULE_NAME": insertSpliceInfoTuple: hash_key[1] = %u\n", key[1]);

  //adding two hastable entries: one for cli->req and req->cli
  for(i = 0; i < 2; i++)
  {
    hash_entry = NULL;

    if((hash_entry = kzalloc(sizeof(struct tcp_splice_hash_entry), GFP_ATOMIC)) == NULL)
    {
      pr_err(MODULE_NAME": %s kzalloc failed!\n", __func__);
      if(i)
      {
        //delete and free the other previous hash_entry
        pr_debug(MODULE_NAME": %s deleting previous hash_entry\n", __func__);
        spin_lock_bh(&ht_lock);
        hash_for_each_possible_rcu(tcp_splice_ht, hash_entry, hash_node, key[0])
        {
          if((hash_entry->splice_tuple.cli_dport == sp_session->cli_socket->sk->sk_dport) &&
            (hash_entry->splice_tuple.cli_sk_num_ct == cli_ct->tuplehash[0].tuple.dst.u.tcp.port) &&
            (hash_entry->splice_tuple.cli_iss == cli_tcp_sock->snd_nxt) &&
            (hash_entry->splice_tuple.req_dport == sp_session->req_socket->sk->sk_dport) &&
            (hash_entry->splice_tuple.req_sk_num_ct == req_ct->tuplehash[1].tuple.dst.u.tcp.port))
          {
            hash_del_rcu(&(hash_entry->hash_node));
          }
        }
        spin_unlock_bh(&ht_lock);
        synchronize_rcu();
        kfree(hash_entry);
      }

      return -ENOMEM;
    }

    //load client socket FD info
    //depending on IPv4 or IPv6 socket
    switch(sp_session->cli_socket->sk->sk_family)
    {
      case AF_INET:
      {
        hash_entry->splice_tuple.cli_daddr.v4_addr = sp_session->cli_socket->sk->sk_daddr;
        hash_entry->splice_tuple.cli_saddr.v4_addr = sp_session->cli_socket->sk->sk_rcv_saddr;
        break;
      }
      case AF_INET6:
      {
        hash_entry->splice_tuple.cli_daddr.v6_addr = sp_session->cli_socket->sk->sk_v6_daddr;
        hash_entry->splice_tuple.cli_saddr.v6_addr = sp_session->cli_socket->sk->sk_v6_rcv_saddr;
        break;

      }
      default:
      {
        pr_debug(MODULE_NAME": %s cli_sk_family = 0x%x\n", __func__,
              sp_session->cli_socket->sk->sk_family);
        break;
      }
    }
    hash_entry->splice_tuple.cli_family = sp_session->cli_socket->sk->sk_family;
    hash_entry->splice_tuple.cli_dport = sp_session->cli_socket->sk->sk_dport;
    hash_entry->splice_tuple.cli_sk_num = htons(sp_session->cli_socket->sk->sk_num);
    hash_entry->splice_tuple.cli_sk_num_ct = cli_ct->tuplehash[0].tuple.dst.u.tcp.port;
    hash_entry->splice_tuple.cli_iss = cli_tcp_sock->snd_nxt;
    hash_entry->splice_tuple.cli_irs = cli_tcp_sock->rcv_nxt;

    //do a routing table lookup now
    if((hash_entry->splice_tuple.cli_dst = sk_dst_get(sp_session->cli_socket->sk)) == NULL)
    {
      pr_err(MODULE_NAME": sk_dst_get returned NULL for cli socket\n");
      nf_ct_put(cli_ct); //clean up
      nf_ct_put(req_ct); //clean up

      if(i)
      {
        //delete and free the other previous hash_entry
        pr_debug(MODULE_NAME": %s deleting previous hash_entry\n", __func__);
        spin_lock_bh(&ht_lock);
        hash_for_each_possible_rcu(tcp_splice_ht, hash_entry, hash_node, key[0])
        {
          if((hash_entry->splice_tuple.cli_dport == sp_session->cli_socket->sk->sk_dport) &&
            (hash_entry->splice_tuple.cli_sk_num_ct == cli_ct->tuplehash[0].tuple.dst.u.tcp.port) &&
            (hash_entry->splice_tuple.cli_iss == cli_tcp_sock->snd_nxt) &&
            (hash_entry->splice_tuple.req_dport == sp_session->req_socket->sk->sk_dport) &&
            (hash_entry->splice_tuple.req_sk_num_ct == req_ct->tuplehash[1].tuple.dst.u.tcp.port))
          {
            hash_del_rcu(&(hash_entry->hash_node));
          }
        }
        spin_unlock_bh(&ht_lock);
        synchronize_rcu();
        kfree(hash_entry);
      } else {
        kfree(hash_entry);
      }
      return -EBADF;
    }

    //load req socket FD info
    //depending on IPv4 or IPv6 socket
    switch(sp_session->req_socket->sk->sk_family)
    {
      case AF_INET:
      {
        hash_entry->splice_tuple.req_daddr.v4_addr = sp_session->req_socket->sk->sk_daddr;
        hash_entry->splice_tuple.req_saddr.v4_addr = sp_session->req_socket->sk->sk_rcv_saddr;
        break;
      }
      case AF_INET6:
      {
        hash_entry->splice_tuple.req_daddr.v6_addr = sp_session->req_socket->sk->sk_v6_daddr;
        hash_entry->splice_tuple.req_saddr.v6_addr = sp_session->req_socket->sk->sk_v6_rcv_saddr;
        break;

      }
      default:
      {
        pr_debug(MODULE_NAME": %s req_sk_family = 0x%x\n", __func__,
                sp_session->req_socket->sk->sk_family);
        break;
      }
    }
    hash_entry->splice_tuple.req_family = sp_session->req_socket->sk->sk_family;

    hash_entry->splice_tuple.req_dport = sp_session->req_socket->sk->sk_dport;
    hash_entry->splice_tuple.req_sk_num = htons(sp_session->req_socket->sk->sk_num);
    hash_entry->splice_tuple.req_sk_num_ct = req_ct->tuplehash[1].tuple.dst.u.tcp.port;

    j = sp_session->cli_socket->sk->sk_receive_queue.qlen;
    rcv_queue_bytes = 0;
    skb = sp_session->cli_socket->sk->sk_receive_queue.next;
    //iterate through the receive queue
    while((NULL != skb) && (j > 0))
    {
      rcv_queue_bytes += skb->len;
      skb = skb->next;
      j--;
    }

    hash_entry->splice_tuple.req_iss = req_tcp_sock->snd_nxt + rcv_queue_bytes;
    //hash_entry->splice_tuple.req_iss = req_tcp_sock->snd_nxt;
    hash_entry->splice_tuple.req_irs = req_tcp_sock->rcv_nxt;

    //do a routing table lookup now
    if((hash_entry->splice_tuple.req_dst = sk_dst_get(sp_session->req_socket->sk)) == NULL)
    {
      pr_err(MODULE_NAME": %s sk_dst_get returned NULL for req socket\n", __func__);
      nf_ct_put(cli_ct); //clean up
      nf_ct_put(req_ct); //clean up

      if(i)
      {
        //delete and free the other previous hash_entry
        pr_debug(MODULE_NAME": %s deleting previous hash_entry\n", __func__);
        spin_lock_bh(&ht_lock);
        hash_for_each_possible_rcu(tcp_splice_ht, hash_entry, hash_node, key[0])
        {
          if((hash_entry->splice_tuple.cli_dport == sp_session->cli_socket->sk->sk_dport) &&
            (hash_entry->splice_tuple.cli_sk_num_ct == cli_ct->tuplehash[0].tuple.dst.u.tcp.port) &&
            (hash_entry->splice_tuple.cli_iss == cli_tcp_sock->snd_nxt) &&
            (hash_entry->splice_tuple.req_dport == sp_session->req_socket->sk->sk_dport) &&
            (hash_entry->splice_tuple.req_sk_num_ct == req_ct->tuplehash[1].tuple.dst.u.tcp.port))
          {
            hash_del_rcu(&(hash_entry->hash_node));
          }
        }
        spin_unlock_bh(&ht_lock);
        synchronize_rcu();
        kfree(hash_entry);
      } else {
        kfree(hash_entry);
      }
      return -EBADF;
    }

    //handling TCP options

    //Timestamp
    if(cli_tcp_sock->rx_opt.tstamp_ok && req_tcp_sock->rx_opt.tstamp_ok)
    {
      //we must splice Timestamps
      hash_entry->session_info.rx_opt_timestamp_ok = 1;

      hash_entry->splice_tuple.tstamp_option.cli_ircv_tsval = cli_tcp_sock->rx_opt.rcv_tsval;
      hash_entry->splice_tuple.tstamp_option.cli_ircv_tsecr = cli_tcp_sock->rx_opt.rcv_tsecr;

      hash_entry->splice_tuple.tstamp_option.req_ircv_tsval = req_tcp_sock->rx_opt.rcv_tsval;
      hash_entry->splice_tuple.tstamp_option.req_ircv_tsecr = req_tcp_sock->rx_opt.rcv_tsecr;

    } else {
      hash_entry->session_info.rx_opt_timestamp_ok = 0;
    }

    //Window Scaling
    memset(&hash_entry->splice_tuple.wscale_option, 0, sizeof(struct window_scale_splice_tuple));

    if(cli_tcp_sock->rx_opt.wscale_ok)
    {
      //we need to window size splice
      hash_entry->session_info.rx_opt_wscale_ok |= CLIENT_SUPPORTS_WINDOW_SCALING;
      hash_entry->splice_tuple.wscale_option.cli_isnd_wscale = cli_tcp_sock->rx_opt.snd_wscale;
      hash_entry->splice_tuple.wscale_option.cli_ircv_wscale = cli_tcp_sock->rx_opt.rcv_wscale;
    }

    if(req_tcp_sock->rx_opt.wscale_ok)
    {
      //we need to window size splice
      hash_entry->session_info.rx_opt_wscale_ok |= REMOTE_SUPPORTS_WINDOW_SCALING;
      hash_entry->splice_tuple.wscale_option.req_isnd_wscale = req_tcp_sock->rx_opt.snd_wscale;
      hash_entry->splice_tuple.wscale_option.req_ircv_wscale = req_tcp_sock->rx_opt.rcv_wscale;
    }

    //SACK
    if(cli_tcp_sock->rx_opt.sack_ok & req_tcp_sock->rx_opt.sack_ok & TCP_SACK_SEEN)
    {
      //we must splice SACKs
      hash_entry->session_info.rx_opt_sack_ok = 1;

    } else {
      hash_entry->session_info.rx_opt_sack_ok = 0;
    }

    //load session info
    hash_entry->session_info.r_session.cli_fd = sp_session->r_session.cli_fd;
    hash_entry->session_info.r_session.req_fd = sp_session->r_session.req_fd;
    hash_entry->session_info.cli_socket = sp_session->cli_socket;
    hash_entry->session_info.req_socket = sp_session->req_socket;

    //add keys to opposing directions
    if(i)
    {
      hash_entry->opp_key = key[0];
    } else {
      hash_entry->opp_key = key[1];
    }
#ifdef IPA_SOCKsv5_ADD_COM_ID
    if(!i){
      if((ipa_handle = AddIPASOCKSSession(&hash_entry->splice_tuple,
                                          &hash_entry->session_info,
                                          &pdn_hash_key)) == TCP_SPLICE_MIN_IPA_HANDLE)
      {
        pr_err(MODULE_NAME": failed adding SOCKSv5 session to IPA\n");
      }
    }
#endif
    pr_debug(MODULE_NAME":Insert hash entry with ipa handle %d",ipa_handle);
    hash_entry->ipa_handle = ipa_handle;
    hash_entry->pdn_hash_key = pdn_hash_key;
    hash_entry->fin_recvd = 0;
    spin_lock_bh(&ht_lock);
    hash_add_rcu(tcp_splice_ht, &(hash_entry->hash_node), key[i]);
    spin_unlock_bh(&ht_lock);


  }

  return 0;
}

/***************************************************************************
*
* Function: printSessionInfo
*
* Description: prints tcp splice info
*
* Parameters: struct tcp_splice_session_info* sp_session; //ptr to tcp splice session
*
* Return: none
*
***************************************************************************/
void printSessionInfo(struct tcp_splice_session_info* sp_session)
{
  struct tcp_sock* cli_tcp_sock = NULL;
  struct tcp_sock* req_tcp_sock = NULL;

  if(NULL == sp_session)
  {
    pr_err(MODULE_NAME": %s : %d sp_session is NULL\n", __func__, __LINE__);
    return;
  }

  cli_tcp_sock = tcp_sk(sp_session->cli_socket->sk);
  req_tcp_sock = tcp_sk(sp_session->req_socket->sk);

  //depending on IPv4 or IPv6 socket
  switch(sp_session->cli_socket->sk->sk_family)
  {
    case AF_INET:
    {
      pr_info(MODULE_NAME": cli_sk_family = AF_INET\n");
      pr_info(MODULE_NAME": cli_daddr = 0x%x\n", ntohl(sp_session->cli_socket->sk->sk_daddr));
      pr_info(MODULE_NAME": cli_saddr = 0x%x\n", ntohl(sp_session->cli_socket->sk->sk_rcv_saddr));
      break;
    }
    case AF_INET6:
    {
      pr_info(MODULE_NAME": cli_sk_family = AF_INET6\n");
      pr_info(MODULE_NAME": cli_v6_daddr = ");
      PRINTK_IPV6_ADDR(sp_session->cli_socket->sk->sk_v6_daddr);
      pr_info(MODULE_NAME": cli_v6_rcv_saddr = ");
      PRINTK_IPV6_ADDR(sp_session->cli_socket->sk->sk_v6_rcv_saddr);
      break;
    }
    default:
    {
      pr_info(MODULE_NAME": cli_sk_family = 0x%x\n", sp_session->cli_socket->sk->sk_family);
      break;
    }
  }

  pr_info(MODULE_NAME": cli_dport = 0x%x\n", ntohs(sp_session->cli_socket->sk->sk_dport));
  pr_info(MODULE_NAME": cli_sk_num = 0x%x\n", sp_session->cli_socket->sk->sk_num);
  pr_info(MODULE_NAME": cli_splice_iss = 0x%x\n", cli_tcp_sock->snd_nxt);
  pr_info(MODULE_NAME": cli_splice_irs = 0x%x\n", cli_tcp_sock->rcv_nxt);
  pr_info(MODULE_NAME": cli_rx_opt.tstamp_ok = %u\n", cli_tcp_sock->rx_opt.tstamp_ok);
  pr_info(MODULE_NAME": cli_rx_opt.splice_rcv_tsval = %u\n", cli_tcp_sock->rx_opt.rcv_tsval);
  pr_info(MODULE_NAME": cli_rx_opt.splice_rcv_tsecr = %u\n", cli_tcp_sock->rx_opt.rcv_tsecr);
  pr_info(MODULE_NAME": cli_rx_opt.wscale_ok = %u\n", cli_tcp_sock->rx_opt.wscale_ok);
  pr_info(MODULE_NAME": cli_rx_opt.splice_snd_wscale = %u\n", cli_tcp_sock->rx_opt.snd_wscale);
  pr_info(MODULE_NAME": cli_rx_opt.splice_rcv_wscale = %u\n", cli_tcp_sock->rx_opt.rcv_wscale);
  pr_info(MODULE_NAME": cli_rx_opt.sack_ok = %u\n", cli_tcp_sock->rx_opt.sack_ok & TCP_SACK_SEEN);

  //depending on IPv4 or IPv6 socket
  switch(sp_session->req_socket->sk->sk_family)
  {
    case AF_INET:
    {
      pr_info(MODULE_NAME": req_sk_family = AF_INET\n");
      pr_info(MODULE_NAME": req_daddr = 0x%x\n", ntohl(sp_session->req_socket->sk->sk_daddr));
      pr_info(MODULE_NAME": req_saddr = 0x%x\n", ntohl(sp_session->req_socket->sk->sk_rcv_saddr));
      break;
    }
    case AF_INET6:
    {
      pr_info(MODULE_NAME": req_sk_family = AF_INET6\n");
      pr_info(MODULE_NAME": req_v6_daddr = ");
      PRINTK_IPV6_ADDR(sp_session->req_socket->sk->sk_v6_daddr);
      pr_info(MODULE_NAME": req_v6_rcv_saddr = ");
      PRINTK_IPV6_ADDR(sp_session->req_socket->sk->sk_v6_rcv_saddr);
      break;
    }
    default:
    {
      pr_info(MODULE_NAME": req_sk_family = 0x%x\n", sp_session->req_socket->sk->sk_family);
      break;
    }
  }

  pr_info(MODULE_NAME": req_dport = 0x%x\n", ntohs(sp_session->req_socket->sk->sk_dport));
  pr_info(MODULE_NAME": req_sk_num = 0x%x\n", sp_session->req_socket->sk->sk_num);
  pr_info(MODULE_NAME": req_splice_iss = 0x%x\n", req_tcp_sock->snd_nxt);
  pr_info(MODULE_NAME": req_splice_irs = 0x%x\n", req_tcp_sock->rcv_nxt);
  pr_info(MODULE_NAME": req_rx_opt.tstamp_ok = %u\n", req_tcp_sock->rx_opt.tstamp_ok);
  pr_info(MODULE_NAME": req_rx_opt.splice_rcv_tsval = %u\n", req_tcp_sock->rx_opt.rcv_tsval);
  pr_info(MODULE_NAME": req_rx_opt.splice_rcv_tsecr = %u\n", req_tcp_sock->rx_opt.rcv_tsecr);
  pr_info(MODULE_NAME": req_rx_opt.wscale_ok = %u\n", req_tcp_sock->rx_opt.wscale_ok);
  pr_info(MODULE_NAME": req_rx_opt.splice_snd_wscale = %u\n", req_tcp_sock->rx_opt.snd_wscale);
  pr_info(MODULE_NAME": req_rx_opt.splice_rcv_wscale = %u\n", req_tcp_sock->rx_opt.rcv_wscale);
  pr_info(MODULE_NAME": req_rx_opt.sack_ok = %u\n", req_tcp_sock->rx_opt.sack_ok & TCP_SACK_SEEN);
}
#ifdef IPA_SOCKsv5_ADD_COM_ID
/***************************************************************************
*
* Function: AddIPASOCKSSession
*
* Description: Configures IPA with SOCKSv5 session info
*
* Parameters: struct tcp_splice_tuple splice_tuple //ptr to tcp splice tuple
* struct tcp_splice_session_info *session_info //ptr to session info
* unsigned int pdn_hash_key // pointer to pdn hash key to store in hash entry
*
* Return: ipa handle
*
***************************************************************************/
int AddIPASOCKSSession(struct tcp_splice_tuple *splice_tuple,
                       struct tcp_splice_session_info *session_info,
                       unsigned int *pdn_hash_key)
{

  struct ipa_socksv5_info ipa_socks_session_info;
  int ipa_handle = TCP_SPLICE_MIN_IPA_HANDLE, pdn_found = 0, ipa_return_val = -1;
  struct tcp_splice_pdn_hash_entry* pdn_hash_entry = NULL;

  if (splice_tuple == NULL){
    pr_err(MODULE_NAME": %s : %d splice_tuple is NULL\n", __func__, __LINE__);
    return TCP_SPLICE_MIN_IPA_HANDLE;
  }
  memset((void *)&ipa_socks_session_info, 0, sizeof(ipa_socks_session_info));

  /*fill IPA uC DL template*/
  ipa_socks_session_info.dl_out.ipa_sockv5_mask |= IPA_SOCKSv5_ENTRY_VALID;

  if (splice_tuple->cli_family == AF_INET6 && splice_tuple->req_family == AF_INET){
    pr_info(MODULE_NAME":v4 <-> v6 translation, call IPA offload\n");
    ipa_socks_session_info.ul_out.cmd_id = IPA_SOCKsv5_ADD_COM_ID;
    ipa_socks_session_info.ul_out.cmd_param = IPA_SOCKsv5_ADD_V6_V4_COM_PM;
    ipa_socks_session_info.dl_out.cmd_id = IPA_SOCKsv5_ADD_COM_ID;
    ipa_socks_session_info.dl_out.cmd_param = IPA_SOCKsv5_ADD_V4_V6_COM_PM;
  }
  else if (splice_tuple->cli_family == AF_INET6 && splice_tuple->req_family == AF_INET6){
    pr_info(MODULE_NAME":v6 <-> v6 translation, call IPA offload\n");
    ipa_socks_session_info.ul_out.cmd_id = IPA_SOCKsv5_ADD_COM_ID;
    ipa_socks_session_info.ul_out.cmd_param = IPA_SOCKsv5_ADD_V6_V6_COM_PM;
    ipa_socks_session_info.dl_out.cmd_id = IPA_SOCKsv5_ADD_COM_ID;
    ipa_socks_session_info.dl_out.cmd_param = IPA_SOCKsv5_ADD_V6_V6_COM_PM;
  }
  else{
    pr_err(MODULE_NAME":IPA offload not supported for this translation\n");
    return TCP_SPLICE_MIN_IPA_HANDLE;
  }
  /* Update uC IP header template information*/
  switch(splice_tuple->cli_family){
    case AF_INET:
    {
      ipa_socks_session_info.dl_out.ipa_sockv5_mask |= IPA_SOCKSv5_IPV4;
      ipa_socks_session_info.dl_out.ip_hdr.ipv4_rsv.ipv4_temp.daddr = splice_tuple->cli_daddr.v4_addr;
      ipa_socks_session_info.dl_out.ip_hdr.ipv4_rsv.ipv4_temp.saddr = splice_tuple->cli_saddr.v4_addr;
      ipa_socks_session_info.dl_out.ip_hdr.ipv4_rsv.ipv4_temp.ihl = 5;
      ipa_socks_session_info.dl_out.ip_hdr.ipv4_rsv.ipv4_temp.protocol = IPPROTO_TCP;
      ipa_socks_session_info.dl_out.ip_hdr.ipv4_rsv.ipv4_temp.version = 4;
    }
    break;
    case AF_INET6:
    {
      ipa_socks_session_info.dl_out.ipa_sockv5_mask |= IPA_SOCKSv5_IPV6;
      ipa_socks_session_info.dl_out.ip_hdr.ipv6_temp.daddr = splice_tuple->cli_daddr.v6_addr;
      ipa_socks_session_info.dl_out.ip_hdr.ipv6_temp.saddr = splice_tuple->cli_saddr.v6_addr;
      ipa_socks_session_info.dl_out.ip_hdr.ipv6_temp.version = 6;
      ipa_socks_session_info.dl_out.ip_hdr.ipv6_temp.nexthdr = IPPROTO_TCP;
    }
    break;
    default:
    {
      pr_err(MODULE_NAME": %s : %d Invalid client family\n", __func__, __LINE__);
      return TCP_SPLICE_MIN_IPA_HANDLE;
    }
    break;
  }
  ipa_socks_session_info.dl_out.dst_port = ntohs(splice_tuple->cli_dport);
  ipa_socks_session_info.dl_out.src_port = ntohs(splice_tuple->cli_sk_num_ct);

  ipa_socks_session_info.dl_out.in_irs = splice_tuple->req_irs;
  ipa_socks_session_info.dl_out.in_iss = splice_tuple->req_iss;
  ipa_socks_session_info.dl_out.out_irs = splice_tuple->cli_irs;
  ipa_socks_session_info.dl_out.out_iss = splice_tuple->cli_iss;

  if (session_info->rx_opt_timestamp_ok){
    ipa_socks_session_info.dl_out.ipa_sockv5_mask |= IPA_SOCKSv5_OPT_TS;
    ipa_socks_session_info.dl_out.out_ircv_tsval = splice_tuple->tstamp_option.cli_ircv_tsval;
    ipa_socks_session_info.dl_out.out_ircv_tsecr = splice_tuple->tstamp_option.cli_ircv_tsecr;
    ipa_socks_session_info.dl_out.in_ircv_tsecr = splice_tuple->tstamp_option.req_ircv_tsecr;
    ipa_socks_session_info.dl_out.in_ircv_tsval = splice_tuple->tstamp_option.req_ircv_tsval;
  }

  if (session_info->rx_opt_wscale_ok){
    ipa_socks_session_info.dl_out.ipa_sockv5_mask |= IPA_SOCKSv5_OPT_WS_DMC;
    ipa_socks_session_info.dl_out.in_ircv_wscale = splice_tuple->wscale_option.req_ircv_wscale;
    ipa_socks_session_info.dl_out.in_isnd_wscale = splice_tuple->wscale_option.req_isnd_wscale;
    ipa_socks_session_info.dl_out.out_ircv_wscale = splice_tuple->wscale_option.cli_ircv_wscale;
    ipa_socks_session_info.dl_out.out_isnd_wscale = splice_tuple->wscale_option.cli_isnd_wscale;
  }

  if (session_info->rx_opt_sack_ok)
    ipa_socks_session_info.dl_out.ipa_sockv5_mask |= IPA_SOCKSv5_OPT_SACK;

  /*fill IPA uC DL template*/
  ipa_socks_session_info.ul_out.ipa_sockv5_mask |= IPA_SOCKSv5_ENTRY_VALID;
  /* Update uC IP header template information*/
  switch(splice_tuple->req_family){
    case AF_INET:
    {
      /*Check PDN hash table and update accordingly*/
      spin_lock_bh(&ht_pdn_lock);
      hash_for_each_possible_rcu(tcp_splice_pdn_ht, pdn_hash_entry, hash_node, splice_tuple->req_daddr.v4_addr)
      {
        pdn_found = 1;
        break;
      }
      if (!pdn_found && pdn_offload_size >= TCP_SPLICE_MAX_PDN_OFFLOAD) {
        pr_err(MODULE_NAME": Max number of PDNs are offloaded. Not offloading this PDN\n");
        return TCP_SPLICE_MIN_IPA_HANDLE;
      }
      if((pdn_hash_entry = kzalloc(sizeof(struct tcp_splice_pdn_hash_entry), GFP_ATOMIC)) == NULL)
      {
        pr_err(MODULE_NAME": %s kzalloc failed!\n", __func__);
        spin_unlock_bh(&ht_pdn_lock);
        return TCP_SPLICE_MIN_IPA_HANDLE;
      }
      pdn_hash_entry->daddr_family = splice_tuple->req_family;
      pdn_hash_entry->daddr.v4_addr = splice_tuple->req_daddr.v4_addr;
      pdn_hash_entry->req_dport = splice_tuple->req_dport;
      pdn_hash_entry->req_sk_num = splice_tuple->req_sk_num;
      hash_add_rcu(tcp_splice_pdn_ht, &(pdn_hash_entry->hash_node),splice_tuple->req_daddr.v4_addr);
      pr_info(MODULE_NAME": inserted for key = 0x%x into PDN hash table\n", splice_tuple->req_daddr.v4_addr);
      *pdn_hash_key = splice_tuple->req_daddr.v4_addr;
      if (!pdn_found){
        pdn_offload_size ++;
      }
      spin_unlock_bh(&ht_pdn_lock);

      ipa_socks_session_info.ul_out.ipa_sockv5_mask |= IPA_SOCKSv5_IPV4;
      ipa_socks_session_info.ul_out.ip_hdr.ipv4_rsv.ipv4_temp.daddr = splice_tuple->req_daddr.v4_addr;
      ipa_socks_session_info.ul_out.ip_hdr.ipv4_rsv.ipv4_temp.saddr = splice_tuple->req_saddr.v4_addr;
      ipa_socks_session_info.ul_out.ip_hdr.ipv4_rsv.ipv4_temp.ihl = 5;
      ipa_socks_session_info.ul_out.ip_hdr.ipv4_rsv.ipv4_temp.protocol = IPPROTO_TCP;
      ipa_socks_session_info.ul_out.ip_hdr.ipv4_rsv.ipv4_temp.version = 4;

    }
    break;
    case AF_INET6:
    {
    ipa_socks_session_info.ul_out.ipa_sockv5_mask |= IPA_SOCKSv5_IPV6;
      ipa_socks_session_info.ul_out.ip_hdr.ipv6_temp.daddr = splice_tuple->req_daddr.v6_addr;
      ipa_socks_session_info.ul_out.ip_hdr.ipv6_temp.saddr = splice_tuple->req_saddr.v6_addr;
      ipa_socks_session_info.ul_out.ip_hdr.ipv6_temp.version = 6;
      ipa_socks_session_info.ul_out.ip_hdr.ipv6_temp.nexthdr = IPPROTO_TCP;
    }
    break;
    default:
    {
      pr_err(MODULE_NAME": %s : %d Invalid client family\n", __func__, __LINE__);
      return TCP_SPLICE_MIN_IPA_HANDLE;
    }
    break;
  }
  ipa_socks_session_info.ul_out.dst_port = ntohs(splice_tuple->req_dport);
  ipa_socks_session_info.ul_out.src_port = ntohs(splice_tuple->req_sk_num_ct);

  ipa_socks_session_info.ul_out.in_irs = splice_tuple->cli_irs;
  ipa_socks_session_info.ul_out.in_iss = splice_tuple->cli_iss;
  ipa_socks_session_info.ul_out.out_irs = splice_tuple->req_irs;
  ipa_socks_session_info.ul_out.out_iss = splice_tuple->req_iss;

  if (session_info->rx_opt_timestamp_ok){
    ipa_socks_session_info.ul_out.ipa_sockv5_mask |= IPA_SOCKSv5_OPT_TS;
    ipa_socks_session_info.ul_out.out_ircv_tsval = splice_tuple->tstamp_option.req_ircv_tsval;
    ipa_socks_session_info.ul_out.out_ircv_tsecr = splice_tuple->tstamp_option.req_ircv_tsecr;
    ipa_socks_session_info.ul_out.in_ircv_tsecr = splice_tuple->tstamp_option.cli_ircv_tsecr;
    ipa_socks_session_info.ul_out.in_ircv_tsval = splice_tuple->tstamp_option.cli_ircv_tsval;
  }

  if (session_info->rx_opt_wscale_ok){
    ipa_socks_session_info.ul_out.ipa_sockv5_mask |= IPA_SOCKSv5_OPT_WS_DMC;
    ipa_socks_session_info.ul_out.in_ircv_wscale = splice_tuple->wscale_option.cli_ircv_wscale;
    ipa_socks_session_info.ul_out.in_isnd_wscale = splice_tuple->wscale_option.cli_isnd_wscale;
    ipa_socks_session_info.ul_out.out_ircv_wscale = splice_tuple->wscale_option.req_ircv_wscale;
    ipa_socks_session_info.ul_out.out_isnd_wscale = splice_tuple->wscale_option.req_isnd_wscale;
  }

  if(session_info->rx_opt_sack_ok)
    ipa_socks_session_info.ul_out.ipa_sockv5_mask |= IPA_SOCKSv5_OPT_SACK;

  /*Fill IPACM info*/
  switch(splice_tuple->req_family){
    case AF_INET:
    {
      ipa_socks_session_info.dl_in.ip_type = IPA_IP_v4;
      ipa_socks_session_info.dl_in.ipv4_dst = splice_tuple->req_saddr.v4_addr;
      ipa_socks_session_info.dl_in.ipv4_src = splice_tuple->req_daddr.v4_addr;
    }
    break;
    case AF_INET6:
    {
      ipa_socks_session_info.dl_in.ip_type = IPA_IP_v6;
      memcpy(&ipa_socks_session_info.dl_in.ipv6_dst,&splice_tuple->req_saddr.v6_addr,sizeof(ipa_socks_session_info.dl_in.ipv6_dst));
      memcpy(&ipa_socks_session_info.dl_in.ipv6_src,&splice_tuple->req_daddr.v6_addr,sizeof(ipa_socks_session_info.ul_in.ipv6_src));
    }
    break;
    default:
    {
      pr_err(MODULE_NAME": %s : %d Invalid client family\n", __func__, __LINE__);
      return TCP_SPLICE_MIN_IPA_HANDLE;
    }
    break;
  }
  ipa_socks_session_info.dl_in.src_port = ntohs(splice_tuple->req_dport);
  ipa_socks_session_info.dl_in.dst_port = ntohs(splice_tuple->req_sk_num_ct);

  switch(splice_tuple->cli_family){
    case AF_INET:
    {
      ipa_socks_session_info.ul_in.ip_type = IPA_IP_v4;
      ipa_socks_session_info.ul_in.ipv4_dst = splice_tuple->cli_saddr.v4_addr;
      ipa_socks_session_info.ul_in.ipv4_src = splice_tuple->cli_daddr.v4_addr;
    }
    break;
    case AF_INET6:
    {
      ipa_socks_session_info.ul_in.ip_type = IPA_IP_v6;
      memcpy(&ipa_socks_session_info.ul_in.ipv6_dst,&splice_tuple->cli_saddr.v6_addr,sizeof(ipa_socks_session_info.ul_in.ipv6_dst));
      memcpy(&ipa_socks_session_info.ul_in.ipv6_src,&splice_tuple->cli_daddr.v6_addr,sizeof(ipa_socks_session_info.ul_in.ipv6_src));
    }
    break;
    default:
    {
      pr_err(MODULE_NAME": %s : %d Invalid client family\n", __func__, __LINE__);
      return TCP_SPLICE_MIN_IPA_HANDLE;
    }
    break;
  }
  ipa_socks_session_info.ul_in.src_port = ntohs(splice_tuple->cli_dport);
  ipa_socks_session_info.ul_in.dst_port = ntohs(splice_tuple->cli_sk_num);

  /*Call IPA add function to add SOCKSv5 conn info*/
  ipa_return_val = ipa_add_socksv5_conn(&ipa_socks_session_info);
  if(ipa_return_val == TCP_SPLICE_IPA_OFFLOAD_SUCCESS){
    ipa_handle = ipa_socks_session_info.handle;
  }
  else{
    pr_debug(MODULE_NAME":returned failure from ipa_add_socksv5_conn() %d",ipa_return_val);
  }

  pr_debug(MODULE_NAME":Returning ipa_handle %d from AddIPASOCKSSession()",ipa_handle);
  return ipa_handle;
}

/***************************************************************************
*
* Function: DeleteIPASOCKSSession
*
* Description: Configures IPA with SOCKSv5 session info
*
* Parameters: struct tcp_splice_tuple splice_tuple; //ptr to tcp splice tuple
*
* Return: void
*
***************************************************************************/
int DeleteIPASOCKSSession(int ipa_handle)
{
  if (ipa_handle <= TCP_SPLICE_MIN_IPA_HANDLE){
      pr_err(MODULE_NAME": %s : %d ipa_handle is 0\n", __func__, __LINE__);
      return -1;
  }
    return ipa_del_socksv5_conn(ipa_handle);
}
#endif
