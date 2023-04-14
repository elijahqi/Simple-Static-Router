#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "sr_utils.h"

#ifndef __LITTLE_ENDIAN
#define __LITTLE_ENDIAN 1
#endif

#ifndef __BIG_ENDIAN
#define __BIG_ENDIAN 2
#endif

#ifndef __BYTE_ORDER
  #ifdef _CYGWIN_
  #define __BYTE_ORDER __LITTLE_ENDIAN
  #endif
  #ifdef _LINUX_
  #define __BYTE_ORDER __LITTLE_ENDIAN
  #endif
  #ifdef _SOLARIS_
  #define __BYTE_ORDER __BIG_ENDIAN
  #endif
  #ifdef _DARWIN_
  #define __BYTE_ORDER __BIG_ENDIAN
  #endif
#endif


uint16_t cksum (const void *_data, int len) {
  const uint8_t *data = _data;
  uint32_t sum;

  for (sum = 0;len >= 2; data += 2, len -= 2)
    sum += data[0] << 8 | data[1];
  if (len > 0)
    sum += data[0] << 8;
  while (sum > 0xffff)
    sum = (sum >> 16) + (sum & 0xffff);
  sum = htons (~sum);
  return sum ? sum : 0xffff;
}


uint16_t ethertype(uint8_t *buf) {
  sr_ethernet_hdr_t *ehdr = (sr_ethernet_hdr_t *)buf;
  return ntohs(ehdr->ether_type);
}

uint8_t ip_protocol(uint8_t *buf) {
  sr_ip_hdr_t *iphdr = (sr_ip_hdr_t *)(buf);
  return iphdr->ip_p;
}


/* Prints out formatted Ethernet address, e.g. 00:11:22:33:44:55 */
void print_addr_eth(uint8_t *addr) {
  int pos = 0;
  uint8_t cur;
  for (; pos < ETHER_ADDR_LEN; pos++) {
    cur = addr[pos];
    if (pos > 0)
      fprintf(stderr, ":");
    fprintf(stderr, "%02X", cur);
  }
  fprintf(stderr, "\n");
}

/* Prints out IP address as a string from in_addr */
void print_addr_ip(struct in_addr address) {
  char buf[INET_ADDRSTRLEN];
  if (inet_ntop(AF_INET, &address, buf, 100) == NULL)
    fprintf(stderr,"inet_ntop error on address conversion\n");
  else
    fprintf(stderr, "%s\n", buf);
}

/* Prints out IP address from integer value */
void print_addr_ip_int(uint32_t ip) {
  uint32_t curOctet = ip >> 24;
  fprintf(stderr, "%d.", curOctet);
  curOctet = (ip << 8) >> 24;
  fprintf(stderr, "%d.", curOctet);
  curOctet = (ip << 16) >> 24;
  fprintf(stderr, "%d.", curOctet);
  curOctet = (ip << 24) >> 24;
  fprintf(stderr, "%d\n", curOctet);
}


/* Prints out fields in Ethernet header. */
void print_hdr_eth(uint8_t *buf) {
  sr_ethernet_hdr_t *ehdr = (sr_ethernet_hdr_t *)buf;
  fprintf(stderr, "ETHERNET header:\n");
  fprintf(stderr, "\tdestination: ");
  print_addr_eth(ehdr->ether_dhost);
  fprintf(stderr, "\tsource: ");
  print_addr_eth(ehdr->ether_shost);
  fprintf(stderr, "\ttype: %d\n", ntohs(ehdr->ether_type));
}

/* Prints out fields in IP header. */
void print_hdr_ip(uint8_t *buf) {
  sr_ip_hdr_t *iphdr = (sr_ip_hdr_t *)(buf);
  fprintf(stderr, "IP header:\n");
  fprintf(stderr, "\tversion: %d\n", iphdr->ip_v);
  fprintf(stderr, "\theader length: %d\n", iphdr->ip_hl);
  fprintf(stderr, "\ttype of service: %d\n", iphdr->ip_tos);
  fprintf(stderr, "\tlength: %d\n", ntohs(iphdr->ip_len));
  fprintf(stderr, "\tid: %d\n", ntohs(iphdr->ip_id));

  if (ntohs(iphdr->ip_off) & IP_DF)
    fprintf(stderr, "\tfragment flag: DF\n");
  else if (ntohs(iphdr->ip_off) & IP_MF)
    fprintf(stderr, "\tfragment flag: MF\n");
  else if (ntohs(iphdr->ip_off) & IP_RF)
    fprintf(stderr, "\tfragment flag: R\n");

  fprintf(stderr, "\tfragment offset: %d\n", ntohs(iphdr->ip_off) & IP_OFFMASK);
  fprintf(stderr, "\tTTL: %d\n", iphdr->ip_ttl);
  fprintf(stderr, "\tprotocol: %d\n", iphdr->ip_p);

  /*Keep checksum in NBO*/
  fprintf(stderr, "\tchecksum: %d\n", iphdr->ip_sum);

  fprintf(stderr, "\tsource: ");
  print_addr_ip_int(ntohl(iphdr->ip_src));

  fprintf(stderr, "\tdestination: ");
  print_addr_ip_int(ntohl(iphdr->ip_dst));
}

/* Prints out ICMP header fields */
void print_hdr_icmp(uint8_t *buf) {
  sr_icmp_hdr_t *icmp_hdr = (sr_icmp_hdr_t *)(buf);
  fprintf(stderr, "ICMP header:\n");
  fprintf(stderr, "\ttype: %d\n", icmp_hdr->icmp_type);
  fprintf(stderr, "\tcode: %d\n", icmp_hdr->icmp_code);
  /* Keep checksum in NBO */
  fprintf(stderr, "\tchecksum: %d\n", icmp_hdr->icmp_sum);
}


/* Prints out fields in ARP header */
void print_hdr_arp(uint8_t *buf) {
  sr_arp_hdr_t *arp_hdr = (sr_arp_hdr_t *)(buf);
  fprintf(stderr, "ARP header\n");
  fprintf(stderr, "\thardware type: %d\n", ntohs(arp_hdr->ar_hrd));
  fprintf(stderr, "\tprotocol type: %d\n", ntohs(arp_hdr->ar_pro));
  fprintf(stderr, "\thardware address length: %d\n", arp_hdr->ar_hln);
  fprintf(stderr, "\tprotocol address length: %d\n", arp_hdr->ar_pln);
  fprintf(stderr, "\topcode: %d\n", ntohs(arp_hdr->ar_op));

  fprintf(stderr, "\tsender hardware address: ");
  print_addr_eth(arp_hdr->ar_sha);
  fprintf(stderr, "\tsender ip address: ");
  print_addr_ip_int(ntohl(arp_hdr->ar_sip));

  fprintf(stderr, "\ttarget hardware address: ");
  print_addr_eth(arp_hdr->ar_tha);
  fprintf(stderr, "\ttarget ip address: ");
  print_addr_ip_int(ntohl(arp_hdr->ar_tip));
}

/* Prints out all possible headers, starting from Ethernet */
void print_hdrs(uint8_t *buf, uint32_t length) {

  /* Ethernet */
  int minlength = sizeof(sr_ethernet_hdr_t);
  if (length < minlength) {
    fprintf(stderr, "Failed to print ETHERNET header, insufficient length\n");
    return;
  }

  uint16_t ethtype = ethertype(buf);
  print_hdr_eth(buf);

  if (ethtype == ethertype_ip) { /* IP */
    minlength += sizeof(sr_ip_hdr_t);
    if (length < minlength) {
      fprintf(stderr, "Failed to print IP header, insufficient length\n");
      return;
    }

    print_hdr_ip(buf + sizeof(sr_ethernet_hdr_t));
    uint8_t ip_proto = ip_protocol(buf + sizeof(sr_ethernet_hdr_t));

    if (ip_proto == ip_protocol_icmp) { /* ICMP */
      minlength += sizeof(sr_icmp_hdr_t);
      if (length < minlength)
        fprintf(stderr, "Failed to print ICMP header, insufficient length\n");
      else
        print_hdr_icmp(buf + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
    }
  }
  else if (ethtype == ethertype_arp) { /* ARP */
    minlength += sizeof(sr_arp_hdr_t);
    if (length < minlength)
      fprintf(stderr, "Failed to print ARP header, insufficient length\n");
    else
      print_hdr_arp(buf + sizeof(sr_ethernet_hdr_t));
  }
  else {
    fprintf(stderr, "Unrecognized Ethernet Type: %d\n", ethtype);
  }
}






///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////// Utility Functions /////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
/* 
  This function creates Ethernet header
    -- dst ->  pointer to dest MAC address
    -- out_if -> outgoing interface
    -- type -> ethernet type (icmp/arp)
*/
sr_ethernet_hdr_t get_eth_hdr(const uint8_t * dst, struct sr_if * out_if, uint16_t type) {
    // Initialize Ethernet frame
    sr_ethernet_hdr_t eth_hdr;
    // Destination MAC address
    if (dst != NULL) {
        memcpy(eth_hdr.ether_dhost, dst, ETHER_ADDR_LEN);
    } else {
        memset(eth_hdr.ether_dhost, 0xff, ETHER_ADDR_LEN);
    }
    // Source ethernet address
    if (out_if) {
        memcpy(eth_hdr.ether_shost, out_if->addr, ETHER_ADDR_LEN);      // TODO: double check
    } else {
        printf("ERROR: no matching outgoing interface for the ARP request sender");
    }
    // Set the ethernet type to be ip
    eth_hdr.ether_type = type;
    return eth_hdr;
}

/* 
  This function creates IP header
    -- len -> length of payload
    -- protocol -> icmp (or not)
    -- dst -> dest IP address
    -- src -> source IP address
*/
sr_ip_hdr_t get_ip_hdr(uint16_t len, uint8_t protocol, uint32_t dst, uint32_t src) {
    // Initialize IP header
    sr_ip_hdr_t ip_hdr;
    ip_hdr.ip_tos = 0;
    ip_hdr.ip_len = len;   // length of datagram (including both IP header and IP data)
    ip_hdr.ip_id = 0;
    ip_hdr.ip_hl =sizeof(sr_ip_hdr_t)/4; // header length (in 32-bit words)
    // Set ip_v to 4 (IPv4)
    ip_hdr.ip_v = 4 ; 
    ip_hdr.ip_off = 0;
    ip_hdr.ip_ttl = 64;     // no need to use htons because it's 8-bit
    ip_hdr.ip_p = protocol;
    ip_hdr.ip_dst = dst;
    ip_hdr.ip_src = src;
    ip_hdr.ip_sum = 0;
    ip_hdr.ip_sum = cksum(&ip_hdr, sizeof(sr_ip_hdr_t));    // already in network order
    return ip_hdr;
}

/* 
  This function creates ICMP type 3 header
    -- type -> ICMP type
    -- code -> ICMP code
    -- buf -> pointer to the original packet
*/
sr_icmp_t3_hdr_t get_icmp_type_3_hdr(uint8_t type, uint8_t code, const uint8_t * buf) {
    sr_icmp_t3_hdr_t icmp_hdr;
    icmp_hdr.icmp_type = type;
    icmp_hdr.icmp_code = code;
    icmp_hdr.unused = 0;
    icmp_hdr.next_mtu = 0;
    // Copy data over (start from IP header)
    memcpy(icmp_hdr.data, buf + sizeof(sr_ethernet_hdr_t), ICMP_DATA_SIZE);    // TODO: double check
    icmp_hdr.icmp_sum = 0;
    icmp_hdr.icmp_sum = cksum(&icmp_hdr, sizeof(sr_icmp_t3_hdr_t));     // TODO: double check
    return icmp_hdr;
}

// TODO: Double check
/* 
  This function return a pointer to ICMP header and data
    -- type -> ICMP type
    -- code -> ICMP code
    -- icmp_start -> A pointer to the start of the ICMP header
    -- total_len -> Length of ICMP header plus length of ICMP data
*/
uint8_t * get_icmp_hdr_and_data(uint8_t type, uint8_t code, const uint8_t * icmp_start, unsigned int total_len) {
    uint8_t * buf = (uint8_t *)malloc(total_len);
    sr_icmp_hdr_t icmp_hdr;
    icmp_hdr.icmp_type = type;
    icmp_hdr.icmp_code = code;
    icmp_hdr.icmp_sum = 0;

    memcpy(buf, &icmp_hdr, sizeof(sr_icmp_hdr_t));
    memcpy(buf + sizeof(sr_icmp_hdr_t), icmp_start + sizeof(sr_icmp_hdr_t), total_len - sizeof(sr_icmp_hdr_t));

    sr_icmp_hdr_t * tmp_icmp_hdr = (sr_icmp_hdr_t *)buf;
    tmp_icmp_hdr->icmp_sum = cksum(buf, total_len);

    return buf;
}

/* 
  This function creates ARP header
    -- opcode -> request/reply
    -- sha -> sender hardware (MAC) address
    -- sip -> sender IP address
    -- tha -> target hardware (MAC) address
    -- tip -> target IP address
*/
sr_arp_hdr_t get_arp_hdr(unsigned short opcode, const unsigned char * sha, uint32_t sip, const unsigned char * tha, uint32_t tip) {
    sr_arp_hdr_t arp_hdr;
    arp_hdr.ar_hrd = htons(0x0001);  // TODO: double check
    arp_hdr.ar_pro = htons(0x0800);  // TODO: double check
    arp_hdr.ar_hln = ETHER_ADDR_LEN;  // TODO: double check
    arp_hdr.ar_pln = 4;   // TODO: double check
    arp_hdr.ar_op = opcode;
    memcpy(arp_hdr.ar_sha, sha, ETHER_ADDR_LEN);
    arp_hdr.ar_sip = sip;   // TODO: double check, not sure if we need htonl
    if (tha != NULL) {
        memcpy(arp_hdr.ar_tha, tha, ETHER_ADDR_LEN);
    } else {
        memset(arp_hdr.ar_tha, 0xff, ETHER_ADDR_LEN);
    }
    arp_hdr.ar_tip = tip;    // TODO: double check, not sure if we need htonl
    return arp_hdr;
}

/* 
  This function handles sending ARP requests if necessary
*/
void handle_arpreq(struct sr_instance* sr, struct sr_arpreq *request) {
    struct sr_arpcache * cache = &(sr->cache);
    time_t now;
    time(&now);

    if (difftime(now, request->sent) >= 1.0) {
        struct sr_packet * packet = request->packets;
        // Send ICMP host unreachable to source addr of all pkts waiting on this request
        if (request->times_sent >= 7) {
            // Send ICMP msg to all packets of this ARP request
            while (packet) {
                // Ethernet and IP header of the packet
                sr_ethernet_hdr_t * pkt_eth_hdr = (sr_ethernet_hdr_t *)(packet->buf);
                sr_ip_hdr_t * pkt_ip_hdr = (sr_ip_hdr_t *)(packet->buf + sizeof(sr_ethernet_hdr_t));
                // Outgoing interface of the packet
                LPM_result_t lpm_result = LPM(sr->routing_table, pkt_ip_hdr->ip_src);
                struct sr_if * out_if = sr_get_interface(sr, lpm_result.interface);

                // Construct ICMP msg (use htons and htonl here to convert any 16-bit and 32-bit integers)
                unsigned int total_len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t);
                uint8_t * icmp_msg = (uint8_t *)malloc(total_len);

                // Initialize Ethernet frame
                sr_ethernet_hdr_t eth_hdr = get_eth_hdr(pkt_eth_hdr->ether_shost, out_if, htons(ethertype_ip));

                // Initialize IP header
                sr_ip_hdr_t ip_hdr = get_ip_hdr(htons(sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t)), ip_protocol_icmp, pkt_ip_hdr->ip_src, out_if->ip);

                // Initialize ICMP type 3 header
                sr_icmp_t3_hdr_t icmp_hdr = get_icmp_type_3_hdr(3, 1, packet->buf);

                memcpy(icmp_msg, &eth_hdr, sizeof(sr_ethernet_hdr_t));
                memcpy(icmp_msg + sizeof(sr_ethernet_hdr_t), &ip_hdr, sizeof(sr_ip_hdr_t));
                memcpy(icmp_msg + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t), &icmp_hdr, sizeof(sr_icmp_t3_hdr_t));

                // Send out msg 
                sr_send_packet(sr, icmp_msg, total_len, out_if->name);      // TODO: double check iface argument
                free(icmp_msg);
                packet = packet->next;
            }
            // Destory the request
            sr_arpreq_destroy(cache, request);
        // Resend (Broadcast) ARP request and update the request
        } else {
            // Outgoing interface of the packet
            struct sr_if * out_if = sr_get_interface(sr, packet->iface);

            // Construct an ARP request
            unsigned int total_len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t);
            uint8_t * arp_req = (uint8_t *)malloc(total_len);

            // Initialize Ethernet frame
            sr_ethernet_hdr_t eth_hdr = get_eth_hdr(NULL, out_if, htons(ethertype_arp));

            // Initialize ARP header
            sr_arp_hdr_t arp_hdr = get_arp_hdr(htons(arp_op_request), out_if->addr, out_if->ip, NULL, request->ip);

            memcpy(arp_req, &eth_hdr, sizeof(sr_ethernet_hdr_t));
            memcpy(arp_req + sizeof(sr_ethernet_hdr_t), &arp_hdr, sizeof(sr_arp_hdr_t));

            // Send out ARP request
            sr_send_packet(sr, arp_req, total_len, out_if->name);      // TODO: double check iface argument
            free(arp_req);

            // Update request
            time_t current;
            time(&current);
            request->sent = current;
            request->times_sent += 1;
        }
    }
}

/* 
  This function return the result of longest prefix match
    -- rt -> a routing table instance
    -- dst_ip -> destination ip (in network byte order)
*/
LPM_result_t LPM(struct sr_rt * rt, uint32_t dst_ip) {
  LPM_result_t result;
  int found = 0;
  struct sr_rt * rt_ptr = rt;
  uint32_t target_ip = ntohl(dst_ip);   // Convert into host byte order
  unsigned long longest_mask;

  while (rt_ptr) {
    unsigned long prefix_ip = ntohl(rt_ptr->dest.s_addr);
    unsigned long next_hop = ntohl(rt_ptr->gw.s_addr);
    unsigned long mask = ntohl(rt_ptr->mask.s_addr);
    if ((target_ip & mask) == prefix_ip) {
      // First match found
      if (found == 0) {
        found = 1;
        longest_mask = mask;
        result.found = 1;
        result.next_hop_ip = htonl(next_hop);
        memcpy(result.interface, rt_ptr->interface, sr_IFACE_NAMELEN);
      // Longer match found
      } else if (mask > longest_mask) {
        longest_mask = mask;
        result.next_hop_ip = htonl(next_hop);
        memcpy(result.interface, rt_ptr->interface, sr_IFACE_NAMELEN);
      }
    }
    rt_ptr = rt_ptr->next;
  }
  
  return result;
}
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////