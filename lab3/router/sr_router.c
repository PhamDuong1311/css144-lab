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

  printf("*** -> Received packet of length %d \n",len);

  /* fill in code here */
  if (len < sizeof(sr_ethernet_hdr_t)) {
    fprintf(stderr, "error: len of eth header");
    return;
  }
  sr_ethernet_hdr_t* eth_hdr = (sr_ethernet_hdr_t* )packet;
  if (eth_hdr->ether_type == ethertype_arp) {
    handle_arp_packet(sr, packet, len, interface);
  } else if (eth_hdr->ether_type == ethertype_ip) {
    handle_ip_packet();
  } else {
    fprintf(stderr, "error: eth type");
    return;
  }
}/* end sr_ForwardPacket */

void handle_arp_packet(struct sr_instance* sr, uint8_t* packet, uint32_t len, char* iface) {
  sr_arp_hdr_t* arp_hdr = (sr_arp_hdr_t* )(packet + sizeof(sr_ethernet_hdr_t);
  if (ntohs(arp_hdr->ar_op) == arp_op_reply) {
    struct sr_arpreq *req = sr_arpcache_insert(sr->cache, arp_hdr->ar_sha, ntohl(arp_hdr->ar_sip)); 
    if (req) {
      // Gửi tất cả các packet trong req->packets
      struct sr_packet* pkt = req->packets;
      while (pkt) {
        sr_ethernet_hdr_t* eth_hdr_pkt = (sr_ethernet_hdr_t* )(pkt->buf);
        sr_ip_hdr_t* ip_hdr_pkt = (sr_ip_hdr_t* )(pkt->buf + sizeof(sr_ethernet_hdr_t));
        if (ip_hdr_pkt->ip_dst == ntohl(arp_hdr->ar_sip)) {
          if (sr_send_packet(sr, pkt->buf, pkt->len, iface)) {
            continue;
          }
        }
        pkt = pkt->next;
      }
      sr_arpreq_destroy(sr->cache, req);
    }
  } else if (ntohs(arp_hdr->ar_op) == arp_op_request) {
    struct sr_if* if = sr->if_list;
    while (if) {
      if (ntohl(arp_hdr->ar_tip) == if->ip) {
        send_arp_reply()
      }
      if = if->next;
    }
  } else {
    fprintf(stderr, "error opcode arp");
    return;
  }
}

// Xử lý nếu là IP packet
void handle_ip_packet(struct sr_instance* sr, uint8_t* packet, uint32_t len, char* iface) {
  sr_ip_hdr_t* ip_hdr = (sr_ip_hdr_t* )(packet + sizeof(sr_ip_hdr_t));
  struct sr_if* if = sr_get_interface(sr, iface);

  // Packet gửi tới chính router
  if (if->ip == ntohl(ip_hdr->ip_dst) {
    if (ip_hdr->ip_p == ip_protol_icmp) { // Nhận được ICMP echo request (ping)
      // Gửi ICMP echo reply
    } else {
      // Gửi ICMP port unreachable
    }
  } else { // Packet cần forwarding tới next-hop

  }
}

void send_arp_reply(struct sr_instance* sr, char* iface, uint8_t* t_mac, uint32_t t_ip) {
  if ((sr->sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP)) < 0) {
    fprintf(stderr, "failed socket arp");
    return -1;
  }

  sr_ethernet_hdr_t* eth_hdr
}

void send_icmp() {

} // về xem các loại gửi arp, icmp, raw eth, 