/*
 *  Copyright (c) 2009 Roger Liao <rogliao@cs.stanford.edu>
 *  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 */
#include "sr_arpcache.h"
#include "sr_router.h"
#include "sr_if.h"
#include "sr_protocol.h"
#include "sr_rt.h"
#ifndef SR_UTILS_H
#define SR_UTILS_H

uint16_t cksum(const void *_data, int len);

uint16_t ethertype(uint8_t *buf);
uint8_t ip_protocol(uint8_t *buf);

void print_addr_eth(uint8_t *addr);
void print_addr_ip(struct in_addr address);
void print_addr_ip_int(uint32_t ip);

void print_hdr_eth(uint8_t *buf);
void print_hdr_ip(uint8_t *buf);
void print_hdr_icmp(uint8_t *buf);
void print_hdr_arp(uint8_t *buf);

/* prints all headers, starting from eth */
void print_hdrs(uint8_t *buf, uint32_t length);


////////////////////////////////////////////////////////////////////////////////////////////////////////////////
sr_ethernet_hdr_t get_eth_hdr(const uint8_t * dst, struct sr_if * out_if, uint16_t type);
sr_ip_hdr_t get_ip_hdr(uint16_t len, uint8_t protocol, uint32_t dst, uint32_t src);
sr_icmp_t3_hdr_t get_icmp_type_3_hdr(uint8_t type, uint8_t code, const uint8_t * buf);
uint8_t * get_icmp_hdr_and_data(uint8_t type, uint8_t code, const uint8_t * icmp_start, unsigned int total_len);
sr_arp_hdr_t get_arp_hdr(unsigned short opcode, const unsigned char * sha, uint32_t sip, const unsigned char * tha, uint32_t tip);
void handle_arpreq(struct sr_instance* sr, struct sr_arpreq *request);

struct LPM_result
{
  int found;    // 0 = no matching in rt, 1 = match found
  uint32_t next_hop_ip;     // In network byte order
  char  interface[sr_IFACE_NAMELEN];
};
typedef struct LPM_result LPM_result_t;

LPM_result_t LPM(struct sr_rt * rt, uint32_t dst_ip);

////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#endif /* -- SR_UTILS_H -- */
