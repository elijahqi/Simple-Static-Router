/**********************************************************************
 * file:  sr_router.c
 * date:  Mon Feb 18 12:50:42 PST 2002
 * Contact: casado@stanford.edu
 *
 * Description:
 *
 * This file contains all the functions that interact directly
 * with the routing table, as well as the main entry method
 * for routing.
 *
 **********************************************************************/

#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <stdlib.h>


#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"

/*---------------------------------------------------------------------
 * Method: sr_init(void)
 * Scope:  Global
 *
 * Initialize the routing subsystem
 *
 *---------------------------------------------------------------------*/

void sr_init(struct sr_instance* sr)
{
    /* REQUIRES */
    assert(sr);

    /* Initialize cache and cache cleanup thread */
    sr_arpcache_init(&(sr->cache));

    pthread_attr_init(&(sr->attr));
    pthread_attr_setdetachstate(&(sr->attr), PTHREAD_CREATE_JOINABLE);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_t thread;

    pthread_create(&thread, &(sr->attr), sr_arpcache_timeout, sr);
    
    /* Add initialization code here! */

} /* -- sr_init -- */

/*---------------------------------------------------------------------
 * Method: sr_handlepacket(uint8_t* p,char* interface)
 * Scope:  Global
 *
 * This method is called each time the router receives a packet on the
 * interface.  The packet buffer, the packet length and the receiving
 * interface are passed in as parameters. The packet is complete with
 * ethernet headers.
 *
 * Note: Both the packet buffer and the character's memory are handled
 * by sr_vns_comm.c that means do NOT delete either.  Make a copy of the
 * packet instead if you intend to keep it around beyond the scope of
 * the method call.
 *
 *---------------------------------------------------------------------*/

void sr_handlepacket(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */)
{
  /* REQUIRES */
  assert(sr);
  assert(packet);
  assert(interface);

  //printf("*** -> Received packet of length %d \n",len);

  // Get headers and receiving interface
  sr_ethernet_hdr_t * eth_hdr = (sr_ethernet_hdr_t *)packet;
  sr_ip_hdr_t * ip_hdr = 0;
  sr_arp_hdr_t * arp_hdr = 0;
  struct sr_if * recv_if = sr_get_interface(sr, interface);

  // Check whether it's IP or ARP
  int is_ip = 1;
  if (ntohs(eth_hdr->ether_type) == ethertype_arp) {
    is_ip = 0;
  }

  // Get IP or ARP header
  if (is_ip) {
    ip_hdr = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
  } else {
    arp_hdr = (sr_arp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
  }

  // If this is an ARP packet
  if (!is_ip) {
    //printf("-----------------MSG: receive an ARP packet, header below-----------------");
    //print_hdrs(packet, len);
    //printf("--------------------------------------------------------------------------");
    // If it is an ARP reply
    if (ntohs(arp_hdr->ar_op) == arp_op_reply) {
      
      //printf("-----------------MSG: ARP reply received-----------------");
      // Cache the (IP, MAC) pair
      struct sr_arpreq * req = sr_arpcache_insert(&(sr->cache), arp_hdr->ar_sha, arp_hdr->ar_sip);
      // Send outstanding packets on the request queue
      if (req) {
        struct sr_packet * otsd_packet = req->packets;
        while (otsd_packet) {
          // Make a copy of the packet buffer
          uint8_t * buf_copy = (uint8_t *)malloc(otsd_packet->len);
          struct sr_if* outface = sr_get_interface(sr, interface);
          memcpy(buf_copy, otsd_packet->buf, otsd_packet->len);
          // Modify the dest MAC address in the Ethernet header of the buffer copy
          sr_ethernet_hdr_t * tmp_eth_hdr = (sr_ethernet_hdr_t *)buf_copy;
          memcpy(tmp_eth_hdr->ether_dhost, arp_hdr->ar_sha, ETHER_ADDR_LEN);
          memcpy(tmp_eth_hdr->ether_shost, outface->addr, ETHER_ADDR_LEN);
          tmp_eth_hdr->ether_type = htons(ethertype_ip);
          // Send out packet
          sr_send_packet(sr, buf_copy, otsd_packet->len, interface);
          free(buf_copy);
          otsd_packet = otsd_packet->next;
        }
        // Destory the request queue
        sr_arpreq_destroy(&(sr->cache), req);
      }
    // Else if it is an ARP request
    } else {
      //printf("-----------------MSG: ARP request received-----------------");
      // If this ARP request is for me, send an ARP reply
      if (arp_hdr->ar_tip == recv_if->ip) {
        // Initialize the ARP reply
        unsigned int total_len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t);
        uint8_t * arp_reply = (uint8_t *)malloc(total_len);
        // Initialize Ethernet frame
        sr_ethernet_hdr_t tmp_eth_hdr = get_eth_hdr(eth_hdr->ether_shost, recv_if, htons(ethertype_arp));   // TODO: double check the first parameter
        // Initialize ARP header
        sr_arp_hdr_t tmp_arp_hdr = get_arp_hdr(htons(arp_op_reply), recv_if->addr, recv_if->ip, arp_hdr->ar_sha, arp_hdr->ar_sip);
        // Consturct the reply
        memcpy(arp_reply, &tmp_eth_hdr, sizeof(sr_ethernet_hdr_t));
        memcpy(arp_reply + sizeof(sr_ethernet_hdr_t), &tmp_arp_hdr, sizeof(sr_arp_hdr_t));
        // Send out ARP reply
        sr_send_packet(sr, arp_reply, total_len, interface);
        free(arp_reply);
      }
    }
  // Else if this is an IP packet
  } else {
    //printf("-----------------MSG: receive an IP packet, header below-----------------");
    //print_hdrs(packet, len);
    //printf("-------------------------------------------------------------------------");
    // TODO: handle packet accordingly
    // First verify its checksum is valid
    int valid = 0;
    // Create a copy of the ip header and calculate its checksum
    uint8_t * ip_hdr_buf = (uint8_t *)malloc(sizeof(sr_ip_hdr_t));
    memcpy(ip_hdr_buf, packet + sizeof(sr_ethernet_hdr_t), sizeof(sr_ip_hdr_t));
    sr_ip_hdr_t * ip_hdr_copy = (sr_ip_hdr_t *)ip_hdr_buf;
    ip_hdr_copy->ip_sum = 0;
    if (cksum(ip_hdr_copy, sizeof(sr_ip_hdr_t)) == ip_hdr->ip_sum) {
      valid = 1;
    }
    free(ip_hdr_buf);
    // Only proceed when checksum is valid, otherwise ignore the packet
    if (valid) {
      //printf("-----------------MSG: this IP packet's checksum is valid-----------------");
      // Check whether this packet is for me by iterating through if_list
      int for_me = 0;
      struct sr_if * curr_if = sr->if_list;
      while (!for_me && curr_if) {
        if (ip_hdr->ip_dst == curr_if->ip) {
          for_me = 1;
          break;
        }
        curr_if = curr_if->next;
      }
      // If this packet is for me
      if (for_me) {
        //printf("-----------------MSG: this IP packet is for me-----------------");
        // If this is an ICMP message
        if (ip_hdr->ip_p == ip_protocol_icmp) {
          // TODO: double check this, what if it is a type 3 ICMP msg?
          sr_icmp_hdr_t * icmp_hdr = (sr_icmp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
          // If this is an ICMP request, verify its checksum and send out echo reply
          if (icmp_hdr->icmp_type == 8 && icmp_hdr->icmp_code == 0) {
            int icmp_len = ntohs(ip_hdr->ip_len) - sizeof(sr_ip_hdr_t);
            uint8_t * icmp_buf_copy = (uint8_t *)malloc(icmp_len);
            memcpy(icmp_buf_copy, packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t), icmp_len);
            sr_icmp_hdr_t * icmp_hdr_copy = (sr_icmp_hdr_t *)icmp_buf_copy;
            icmp_hdr_copy->icmp_sum = 0;
            // If checksum is valid
            if (cksum(icmp_buf_copy, icmp_len) == icmp_hdr->icmp_sum) {
              //printf("-----------------MSG: ICMP request, checksum valid, send echo reply-----------------");
              icmp_hdr_copy->icmp_sum = icmp_hdr->icmp_sum;
              // Create and send out echo reply;
              uint8_t * echo_reply = (uint8_t *)malloc(len);
              // Initialize Ethernet frame
              sr_ethernet_hdr_t tmp_eth = get_eth_hdr(eth_hdr->ether_shost, recv_if, htons(ethertype_ip));
              // Initialize IP header
              sr_ip_hdr_t tmp_ip = get_ip_hdr(ip_hdr->ip_len, ip_protocol_icmp, ip_hdr->ip_src, recv_if->ip);
              // Get ICMP header and data
              uint8_t * tmp_icmp = get_icmp_hdr_and_data(0, 0, packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t), icmp_len);

              memcpy(echo_reply, &tmp_eth, sizeof(sr_ethernet_hdr_t));
              memcpy(echo_reply + sizeof(sr_ethernet_hdr_t), &tmp_ip, sizeof(sr_ip_hdr_t));
              memcpy(echo_reply + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t), tmp_icmp, icmp_len);

              // Send out echo reply 
              sr_send_packet(sr, echo_reply, len, interface); 
              free(echo_reply);
              free(tmp_icmp);
            }
            free(icmp_buf_copy);
          }
        // Else if this is an TCP/UDP packet, send ICMP port unreachable
        } else {
          //printf("-----------------MSG: TDP/DUP packet, send ICMP port unreachable-----------------");
          unsigned int total_len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t);
          uint8_t * icmp_port_unreachable_msg = (uint8_t *)malloc(total_len);
          // Initialize Ethernet frame
          sr_ethernet_hdr_t tmp_eth_hdr = get_eth_hdr(eth_hdr->ether_shost, recv_if, htons(ethertype_ip));
          // Initialize IP header
          sr_ip_hdr_t tmp_ip_hdr = get_ip_hdr(htons(sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t)), ip_protocol_icmp, ip_hdr->ip_src, recv_if->ip);
          // Initialize ICMP type 3 header
          sr_icmp_t3_hdr_t tmp_icmp_hdr = get_icmp_type_3_hdr(3, 3, packet);
          
          memcpy(icmp_port_unreachable_msg, &tmp_eth_hdr, sizeof(sr_ethernet_hdr_t));
          memcpy(icmp_port_unreachable_msg + sizeof(sr_ethernet_hdr_t), &tmp_ip_hdr, sizeof(sr_ip_hdr_t));
          memcpy(icmp_port_unreachable_msg + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t), &tmp_icmp_hdr, sizeof(sr_icmp_t3_hdr_t));

          // Send out msg 
          sr_send_packet(sr, icmp_port_unreachable_msg, total_len, interface);
          free(icmp_port_unreachable_msg);
        }
      // Else if this packet is not for me, forward it
      } else {
        //printf("-----------------MSG: this IP packet is NOT for me-----------------");
        // Decrement the header's TTL by 1 and recompute checksum
        ip_hdr->ip_ttl -= 1;
        ip_hdr->ip_sum = 0;
        ip_hdr->ip_sum = cksum(ip_hdr, sizeof(sr_ip_hdr_t));
        // If TTL <= 0, send time exceeded ICMP message
        if (ip_hdr->ip_ttl <= 0) {
          printf("-----------------MSG: TTL expired, send time exceeded ICMP message-----------------");
          unsigned int total_len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t);
          uint8_t * icmp_time_exceeded_msg = (uint8_t *)malloc(total_len);
          // Initialize Ethernet frame
          sr_ethernet_hdr_t tmp_eth_hdr = get_eth_hdr(eth_hdr->ether_shost, recv_if, htons(ethertype_ip));
          // Initialize IP header
          sr_ip_hdr_t tmp_ip_hdr = get_ip_hdr(htons(sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t)), ip_protocol_icmp, ip_hdr->ip_src, recv_if->ip);
          // Initialize ICMP type 11 header
          sr_icmp_t3_hdr_t tmp_icmp_hdr = get_icmp_type_3_hdr(11, 0, packet);

          memcpy(icmp_time_exceeded_msg, &tmp_eth_hdr, sizeof(sr_ethernet_hdr_t));
          memcpy(icmp_time_exceeded_msg + sizeof(sr_ethernet_hdr_t), &tmp_ip_hdr, sizeof(sr_ip_hdr_t));
          memcpy(icmp_time_exceeded_msg + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t), &tmp_icmp_hdr, sizeof(sr_icmp_t3_hdr_t));

          // Send out msg 
          sr_send_packet(sr, icmp_time_exceeded_msg, total_len, interface);
          print_hdrs(icmp_time_exceeded_msg, total_len);
          free(icmp_time_exceeded_msg);
          
        // Else if TTL > 0, do the longest prefix match, if there is a match, decrement TTL by 1 and forward, otherwise send ICMP net unreachable
        } else {
          //printf("-----------------MSG: start executing LPM-----------------");
          LPM_result_t lpm_result = LPM(sr->routing_table, ip_hdr->ip_dst);
          // If no prefix match found
          if (!lpm_result.found) {
            //printf("-----------------MSG: no LPM found, send destination net unreachable ICMP message-----------------");
            unsigned int total_len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t);
            uint8_t * icmp_net_unreachable_msg = (uint8_t *)malloc(total_len);
            // Initialize Ethernet frame
            sr_ethernet_hdr_t tmp_eth_hdr = get_eth_hdr(eth_hdr->ether_shost, recv_if, htons(ethertype_ip));
            // Initialize IP header
            sr_ip_hdr_t tmp_ip_hdr = get_ip_hdr(htons(sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t)), ip_protocol_icmp, ip_hdr->ip_src, recv_if->ip);
            // Initialize ICMP type 3 header
            sr_icmp_t3_hdr_t tmp_icmp_hdr = get_icmp_type_3_hdr(3, 0, packet);

            memcpy(icmp_net_unreachable_msg, &tmp_eth_hdr, sizeof(sr_ethernet_hdr_t));
            memcpy(icmp_net_unreachable_msg + sizeof(sr_ethernet_hdr_t), &tmp_ip_hdr, sizeof(sr_ip_hdr_t));
            memcpy(icmp_net_unreachable_msg + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t), &tmp_icmp_hdr, sizeof(sr_icmp_t3_hdr_t));

            // Send out msg 
            sr_send_packet(sr, icmp_net_unreachable_msg, total_len, interface);
            free(icmp_net_unreachable_msg);
            
          // Else if match found
          } else {
            //printf("-----------------MSG: LPM found-----------------");
            // TODO: double check, not sure if we need to make a copy of the packet, currently I am modifying the packet
            // Check ARP cache for next hop MAC address
            struct sr_arpentry * entry = sr_arpcache_lookup(&(sr->cache), lpm_result.next_hop_ip);
            // If cache exists
            if (entry) {
              //printf("-----------------MSG: next-hop IP found in ARP cache, forward the packet-----------------");
              // Modify the source and dest MAC address in Ethernet header
              memcpy(eth_hdr->ether_dhost, entry->mac, ETHER_ADDR_LEN);
              memcpy(eth_hdr->ether_shost, sr_get_interface(sr, lpm_result.interface)->addr, ETHER_ADDR_LEN);
              // Forward the packet
              sr_send_packet(sr, packet, len, lpm_result.interface);
              free(entry);
            } else {
              //printf("-----------------MSG: no record found in ARP cache, add to queue and send ARP request-----------------");
              struct sr_arpreq * req = sr_arpcache_queuereq(&(sr->cache), lpm_result.next_hop_ip, packet, len, lpm_result.interface);
              handle_arpreq(sr, req);
            }
          }
        }
      }
    }
  }
}/* end sr_ForwardPacket */

