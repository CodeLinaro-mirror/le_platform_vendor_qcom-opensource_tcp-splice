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
* File: tcp-splice-util.h
*
* Description: Provides utility functions for tcp splice.
*
***************************************************************************/

#define MODULE_NAME "Code Aurora TCP Splice"

#define SIZE_OF_TCP_V6_PSEUDO_HDR 40

#define TCPOLEN_SACK_PERBLOCK_SHIFT 3

#include <net/tcp.h>

#include <uapi/linux/tcp.h>
#include <uapi/linux/ipv6.h>

/***************************************************************************
*
* Function: tcp_fast_parse_options_for_splice
*
* Description: ripped off of kernel mainline 3.18 but stripped of
*              unnecessary information for tcp splice
*
* Parameters: struct tcphdr* tcp_hdr; //ptr to tcp_hdr
*             unsigned int** timestamp; //double ptr for timestamp opt
*             struct tcp_sack_block** sacks; //double ptr for sack opt
*             unsigned char timestamp_ok; //check for timestamp
*             unsigned char sack_ok; //check for sack
*
* Return: 0, success
*        -1, otherwise
*
***************************************************************************/
int qti_tcp_fast_parse_options(struct tcphdr* tcp_hdr, unsigned int** timestamp,
                               struct tcp_sack_block** sacks, unsigned char* num_sacks,
                               unsigned char timestamp_ok, unsigned char sack_ok);

/***************************************************************************
*
* Function: qti_tcp_v6_check
*
* Description: calculates the tcp checksum based on IPv6
*
* Parameters: struct sk_buff* skb; //skb to calculate the tcp checksum
*
* Return: tcp checksum based on IPv6
*
***************************************************************************/
__sum16 qti_tcp_v6_check(struct sk_buff* skb);
