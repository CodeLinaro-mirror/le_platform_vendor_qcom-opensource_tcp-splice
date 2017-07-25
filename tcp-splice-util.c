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
* File: tcp-splice-util.c
*
* Description: Provides utility functions for tcp splice.
*
***************************************************************************/

#include "tcp-splice-util.h"

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
                               unsigned char timestamp_ok, unsigned char sack_ok)
{
  unsigned int* fast_ptr;
  unsigned char* slow_ptr;
  int length;
  int opcode;
  int opsize;

  if(NULL == tcp_hdr)
  {
    pr_err(MODULE_NAME": %s tcp_hdr NULL!\n", __func__);
    return -EINVAL;
  } else if(NULL == timestamp)
  {
    pr_err(MODULE_NAME": %s timestamp NULL!\n", __func__);
    return -EINVAL;
  } else if(NULL == sacks)
  {
    pr_err(MODULE_NAME": %s sacks NULL!\n", __func__);
    return -EINVAL;
  } else if(NULL == num_sacks)
  {
    pr_err(MODULE_NAME": %s num_sacks NULL!\n", __func__);
    return -EINVAL;
  }

  *timestamp = NULL;
  *num_sacks = 0;

  if((timestamp_ok) && (tcp_hdr->doff == ((sizeof(struct tcphdr) >> 2) +
                                          (TCPOLEN_TSTAMP_ALIGNED >> 2))))
  {
    fast_ptr = (unsigned int*)(tcp_hdr + 1);
    if (*fast_ptr == htonl((TCPOPT_NOP << 24) | (TCPOPT_NOP << 16) | (TCPOPT_TIMESTAMP << 8) |
                            TCPOLEN_TIMESTAMP))
    {
      ++fast_ptr;
      *timestamp = fast_ptr;
      //pr_debug(MODULE_NAME": took fast timestamp lookup path\n");

      //no point to move on if no SACKs enabled
      if(!(sack_ok))
      {
        return 0;
      }
    }
  }

  //now the slow path
  slow_ptr = (unsigned char*)(tcp_hdr + 1);
  length = ((tcp_hdr->doff) << 2) - sizeof(struct tcphdr);

  //we are slow parsing the brute force way...
  while(length > 0)
  {
    opcode = *slow_ptr++;

    switch(opcode)
    {
      case(TCPOPT_EOL): //we've reached end of options
      {
        return 0;
      }
      case(TCPOPT_NOP): //skip padding
      {
        length--;
        continue;
      }
      default:
      {
        opsize = *slow_ptr++;
        if(opsize < 2)
        {
          pr_err(MODULE_NAME": %s Recevied a bad TCP option size less than 2!\n",
                __func__);
          return -EINVAL;
        }

        if(opsize > length)
        {
          pr_err(MODULE_NAME": %s Recevied a bad TCP option size greater than length!\n",
                 __func__);
          return -EINVAL;
        }

        switch(opcode)
        {
          case(TCPOPT_TIMESTAMP):
          {
            if((timestamp_ok) && (TCPOLEN_TIMESTAMP == opsize))
            {
              *timestamp = (unsigned int*)slow_ptr;
            }
            break;

          }

          case(TCPOPT_SACK):
          {
            if((sack_ok) && (opsize >= (TCPOLEN_SACK_BASE + TCPOLEN_SACK_PERBLOCK)) &&
              !((opsize - TCPOLEN_SACK_BASE) % TCPOLEN_SACK_PERBLOCK))
            {
              *sacks = (struct tcp_sack_block*)slow_ptr;
              *num_sacks = (unsigned char)((opsize - TCPOLEN_SACK_BASE) >>
                                            TCPOLEN_SACK_PERBLOCK_SHIFT);
            }
            break;
          }

          default:
          {
            break;
          }
        }
        slow_ptr += opsize - 2;
        length -= opsize;
      }
    }
  }

  return 0;
}

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
__sum16 qti_tcp_v6_check(struct sk_buff* skb)
{
  unsigned int total_len; //total length in bytes
  unsigned int i;
  unsigned int num_of_hextet;
  unsigned int checksum = 0;
  unsigned short* hextet;
  unsigned short* buffer;
  unsigned char* octet;
  unsigned char* skb_byte_ptr;
  struct ipv6hdr* ip_hdr;

  if(NULL == skb)
  {
    pr_err(MODULE_NAME": %s skb NULL!\n", __func__);
    return 0;
  }

  ip_hdr = (struct ipv6hdr*)skb_network_header(skb);

  //sanity check to prevent overflow
  if(ntohs(ip_hdr->payload_len) > (skb->len - sizeof(struct ipv6hdr)))
  {
    pr_err(MODULE_NAME": %s bad payload_len = %d\n", __func__, ntohs(ip_hdr->payload_len));
    return 0;
  }

  total_len = SIZE_OF_TCP_V6_PSEUDO_HDR + ntohs(ip_hdr->payload_len);

  if(total_len & 0x00000001) //faster than % 2
  {
    num_of_hextet = (total_len >> 1) + 1; //plan on zero padding
  } else {
    num_of_hextet = (total_len >> 1);
  }

  if((buffer = (unsigned short*)kzalloc(num_of_hextet *
                sizeof(unsigned short), GFP_ATOMIC)) == NULL)
  {
    pr_err(MODULE_NAME": %s couldn't kzalloc\n", __func__);
    return 0;
  }

  //construct pseudo hdr
  hextet = buffer;
  for(i = 0; i < 8; i++)
  {
    *hextet = ip_hdr->saddr.in6_u.u6_addr16[i];
    hextet++;
  }
  for(i = 0; i < 8; i++)
  {
    *hextet = ip_hdr->daddr.in6_u.u6_addr16[i];
    hextet++;
  }
  hextet++; //skip over the next hextet because RFC 2460 would never be larger than 16 bits
  *hextet = (ip_hdr->payload_len);
  hextet++;
  octet = (unsigned char*)hextet;
  octet += 3; //skip over the zeros field
  *octet = IPPROTO_TCP;
  octet++;

  //fill in tcp hdr
  //skb_byte_ptr = (unsigned char*)skb_transport_header(skb);
  skb_byte_ptr = (unsigned char*)(skb->data + sizeof(struct ipv6hdr));
  for(i = 0; i < ntohs(ip_hdr->payload_len); i++)
  {
    *octet = *skb_byte_ptr;
    octet++;
    skb_byte_ptr++;
  }

  hextet = buffer;

  checksum = *hextet;
  hextet++;

  for(i = 1; i < num_of_hextet; i++)
  {
    checksum += *hextet;

    //was there a carry?
    if(checksum & 0xffff0000)
    {
      checksum = (checksum + 1) & 0x0000ffff;
    }
    hextet++;
  }

  kfree(buffer);

  return ((~checksum) & 0x0000ffff);

}
