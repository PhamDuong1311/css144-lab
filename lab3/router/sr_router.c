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
#include <stdlib.h>
#include <string.h>

#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"

/* Bonus */
void handle_arp_packet(struct sr_instance* sr, uint8_t* packet, uint32_t len, char* iface);
void handle_ip_packet(struct sr_instance* sr, uint8_t* packet, uint32_t len, char* iface);
void send_icmp_echo_reply(struct sr_instance* sr, uint8_t* recv_packet, uint32_t recv_len, char* iface_name);
void send_icmp_error(struct sr_instance* sr, uint8_t* recv_packet, uint32_t len, char* iface_name, uint8_t type, uint8_t code);
struct sr_rt* get_match_rt_entry(struct sr_instance* sr, uint32_t dest_ip);
void handle_arpreq(struct sr_instance* sr, struct sr_arpreq* req);
void send_arp_reply(struct sr_instance* sr, uint32_t target_ip, uint8_t* target_mac, char* iface);
void send_arp_request(struct sr_instance* sr, uint32_t target_ip, char* iface);
int is_valid_packet(struct sr_instance* sr, uint8_t* packet, uint32_t len);
int is_icmp_echo_request(struct sr_instance* sr, uint8_t* packet, uint32_t len);

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
  /* Kiểm tra kích thước packet có chứa đủ ethernet header không */
  if (len < sizeof(sr_ethernet_hdr_t)) {
    return;
  }
  sr_ethernet_hdr_t* eth_hdr = (sr_ethernet_hdr_t* )packet;
  if (ntohs(eth_hdr->ether_type) == ethertype_arp) { /* Nhận được ARP packet */
    handle_arp_packet(sr, packet, len, interface);
  } else if (ntohs(eth_hdr->ether_type) == ethertype_ip) { /* Nhận được IP packet */
    handle_ip_packet(sr, packet, len, interface);
  } else { /* Bỏ qua nếu khác loại */
    fprintf(stderr, "error: eth type");
    return;
  }
}/* end sr_ForwardPacket */

/* Hàm xử lý ARP packet */
void handle_arp_packet(struct sr_instance* sr, uint8_t* packet, uint32_t len, char* iface) {
  sr_arp_hdr_t* arp_hdr = (sr_arp_hdr_t* )(packet + sizeof(sr_ethernet_hdr_t));
  if (ntohs(arp_hdr->ar_op) == arp_op_reply) { /* Nhận được ARP reply */
    /* Xóa node ARP request nhận được reply trong queue (nhưng chưa free vì các packet trong ARP request cần gửi đi trước), lưu IP-MAC vào cache*/
    struct sr_arpreq *req = sr_arpcache_insert(&(sr->cache), arp_hdr->ar_sha, ntohl(arp_hdr->ar_sip)); 
    if (req) {
      struct sr_packet* pkt = req->packets;
      while (pkt) { /* Gửi tất cả các packet trong ARP request đi */
        sr_ethernet_hdr_t* eth_hdr_pkt = (sr_ethernet_hdr_t* )(pkt->buf);
        sr_ip_hdr_t* ip_hdr_pkt = (sr_ip_hdr_t* )(pkt->buf + sizeof(sr_ethernet_hdr_t));
        if (ip_hdr_pkt->ip_dst == ntohl(arp_hdr->ar_sip)) {
          memcpy(eth_hdr_pkt->ether_dhost, arp_hdr->ar_sha, ETHER_ADDR_LEN);
          if (sr_send_packet(sr, pkt->buf, pkt->len, iface)) {
            continue;
          }
        }
        pkt = pkt->next;
      }
      sr_arpreq_destroy(&(sr->cache), req);
    }
  } else if (ntohs(arp_hdr->ar_op) == arp_op_request) { /* Nhận được ARP request */
    struct sr_if* ifa = sr->if_list;
    while (ifa) { /* Kiểm tra xem IP đích của packet có phải là 1 trong các IP của router không*/
      if (ntohl(arp_hdr->ar_tip) == ifa->ip) {
        send_arp_reply(sr, arp_hdr->ar_sip, arp_hdr->ar_sha, iface);
      }
      ifa = ifa->next;
    }
  } else {
    fprintf(stderr, "error opcode arp");
    return;
  }
}

/* Hàm xử lý IP packet */
void handle_ip_packet(struct sr_instance* sr, uint8_t* packet, uint32_t len, char* iface) {
  /* Check packet có hợp lệ không */
  if (!is_valid_packet) return;

  sr_ip_hdr_t* ip_hdr = (sr_ip_hdr_t* )(packet + sizeof(sr_ethernet_hdr_t));
  struct sr_if* ifa = sr_get_interface(sr, iface);

  /* Trường hợp packet có đích chỉ tới router */
  if (ifa->ip == ntohl(ip_hdr->ip_dst)) {
    if (ip_hdr->ip_p == ip_protocol_icmp) { /* Packet là ICMP */
      /* Kiểm tra nếu nhận được ICMP echo request */
      if (is_icmp_echo_request) {
        /* Gửi ICMP echo reply */
        send_icmp_echo_reply(sr, packet, len, iface);
      }
    } else { /* Packet là TCP|UDP */
      /* Gửi ICMP port unreachable */
      send_icmp_error(sr, packet, len, iface, 3, 3); 
      return;
    }
  } else { /* Trường hợp packet tới router cần forward tiếp tới next-hop */
      /* Tính là TTL và cksum */
      ip_hdr->ip_ttl--;
      ip_hdr->ip_sum = 0;
      ip_hdr->ip_sum = cksum((uint16_t* )ip_hdr, sizeof(sr_ip_hdr_t));
      if (ip_hdr->ip_ttl <= 0) { /* Hết TTL */
        /* Gửi ICMP time exceeded */
        send_icmp_error(sr, packet, len, iface, 11, 0);
        return;
      } else { /* Chưa hết TTL */
        if (sr_load_rt(sr, "rtable") != 0) return;
        struct sr_rt* rt_entry = get_match_rt_entry(sr, ip_hdr->ip_dst);
        /* Kiểm tra có entry phù hợp trong routing table không */
        if (!rt_entry) {
          /* Gửi ICMP destination network unreachable */
          send_icmp_error(sr, packet, len, iface, 3, 0);
          return;
        } else { /* Tìm thất entry phù hợp trong routing table */
          struct sr_arpentry* arp_entry = sr_arpcache_lookup(&(sr->cache), ip_hdr->ip_dst);
          if (arp_entry) { /* Kiểm tra có entry phù hợp trong ARP cache không*/
            sr_ethernet_hdr_t* eth_hdr = (sr_ethernet_hdr_t*)packet;
            struct sr_if* iface_info = sr_get_interface(sr, rt_entry->interface);
            memcpy(eth_hdr->ether_shost, iface_info->addr, ETHER_ADDR_LEN);
            memcpy(eth_hdr->ether_dhost, arp_entry->mac, ETHER_ADDR_LEN);

            /* Gửi cả frame tới next-hop */
            sr_send_packet(sr, packet, len, iface_info->name);
            free(arp_entry);
          } else { /* Không có entry phù hợp trong ARP cache */
            /* Gửi ARP request */
            struct sr_if* iface_info = sr_get_interface(sr, rt_entry->interface);
            struct sr_arpreq* req = sr_arpcache_queuereq(&(sr->cache), ip_hdr->ip_dst, packet, len, iface_info->name);
            handle_arpreq(sr, req);
          } 
        }
      }
  }
}

void send_icmp_echo_reply(struct sr_instance* sr, uint8_t* recv_packet, uint32_t recv_len, char* iface_name) {
  sr_ethernet_hdr_t* recv_eth_hdr = (sr_ethernet_hdr_t* )recv_packet;
  sr_ip_hdr_t* recv_ip_hdr = (sr_ip_hdr_t* )(recv_packet + sizeof(sr_ethernet_hdr_t));

  uint32_t send_len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_hdr_t);
  uint8_t* send_packet = malloc(send_len);

  sr_ethernet_hdr_t* send_eth_hdr = (sr_ethernet_hdr_t*)send_packet;
  sr_ip_hdr_t* send_ip_hdr = (sr_ip_hdr_t*)(send_packet + sizeof(sr_ethernet_hdr_t));
  sr_icmp_hdr_t* send_icmp_hdr = (sr_icmp_hdr_t*)(send_packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));

  memcpy(send_eth_hdr->ether_dhost, recv_eth_hdr->ether_shost, ETHER_ADDR_LEN);
  memcpy(send_eth_hdr->ether_shost, recv_eth_hdr->ether_dhost, ETHER_ADDR_LEN);
  send_eth_hdr->ether_type = htons(ethertype_ip);

  send_ip_hdr->ip_hl = recv_ip_hdr->ip_hl;            
  send_ip_hdr->ip_v = recv_ip_hdr->ip_v;         
  send_ip_hdr->ip_tos = 0;    
  send_ip_hdr->ip_len = htons(sizeof(sr_icmp_hdr_t) + sizeof(sr_ip_hdr_t));
  send_ip_hdr->ip_id = recv_ip_hdr->ip_id;
  send_ip_hdr->ip_off = htons(IP_DF);
  send_ip_hdr->ip_ttl = INIT_TTL;
  send_ip_hdr->ip_p = ip_protocol_icmp;
  send_ip_hdr->ip_src = recv_ip_hdr->ip_dst;
  send_ip_hdr->ip_dst = recv_ip_hdr->ip_src;
  send_ip_hdr->ip_sum = 0;
  send_ip_hdr->ip_sum = cksum(send_ip_hdr, sizeof(sr_ip_hdr_t));

  send_icmp_hdr->icmp_type = 0;
  send_icmp_hdr->icmp_code = 0;
  send_icmp_hdr->icmp_sum = 0;
  send_icmp_hdr->icmp_sum = cksum(send_icmp_hdr, sizeof(sr_icmp_hdr_t));

  sr_send_packet(sr, send_packet, send_len, iface_name);

  free(send_packet);

} 

void send_icmp_error(struct sr_instance* sr, uint8_t* recv_packet, uint32_t len, char* iface_name, uint8_t type, uint8_t code) {
  sr_ethernet_hdr_t* recv_eth_hdr = (sr_ethernet_hdr_t* )recv_packet;
  sr_ip_hdr_t* recv_ip_hdr = (sr_ip_hdr_t* )(recv_packet + sizeof(sr_ethernet_hdr_t));

  uint32_t send_len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_hdr_t);
  uint8_t* send_packet = malloc(send_len);

  sr_ethernet_hdr_t* send_eth_hdr = (sr_ethernet_hdr_t*)send_packet;
  sr_ip_hdr_t* send_ip_hdr = (sr_ip_hdr_t*)(send_packet + sizeof(sr_ethernet_hdr_t));
  sr_icmp_t3_hdr_t* send_icmp_hdr = (sr_icmp_t3_hdr_t*)(send_packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));

  memcpy(send_eth_hdr->ether_dhost, recv_eth_hdr->ether_shost, ETHER_ADDR_LEN);
  memcpy(send_eth_hdr->ether_shost, recv_eth_hdr->ether_dhost, ETHER_ADDR_LEN);
  send_eth_hdr->ether_type = htons(ethertype_ip);

  send_ip_hdr->ip_hl = 5;            
  send_ip_hdr->ip_v = 4;         
  send_ip_hdr->ip_tos = 0;    
  send_ip_hdr->ip_len = htons(sizeof(sr_icmp_hdr_t) + sizeof(sr_ip_hdr_t));
  send_ip_hdr->ip_id = htons(0);
  send_ip_hdr->ip_off = htons(IP_DF);
  send_ip_hdr->ip_ttl = INIT_TTL;
  send_ip_hdr->ip_p = ip_protocol_icmp;
  send_ip_hdr->ip_src = recv_ip_hdr->ip_dst;
  send_ip_hdr->ip_dst = recv_ip_hdr->ip_src;
  send_ip_hdr->ip_sum = 0;
  send_ip_hdr->ip_sum = cksum(send_ip_hdr, sizeof(sr_ip_hdr_t));

  send_icmp_hdr->icmp_code = code;
  send_icmp_hdr->icmp_type = type;
  send_icmp_hdr->unused = 0;
  send_icmp_hdr->next_mtu = 0;
  memcpy(send_icmp_hdr->data, recv_ip_hdr, ICMP_DATA_SIZE);
  send_icmp_hdr->icmp_sum = 0;
  send_icmp_hdr->icmp_sum = cksum(send_icmp_hdr, sizeof(sr_icmp_t3_hdr_t));

  sr_send_packet(sr, send_packet, send_len, iface_name);
}

/* Lấy entry phù hợp nhất (LPM) trong routing table*/
struct sr_rt* get_match_rt_entry(struct sr_instance* sr, uint32_t dest_ip) {
  struct sr_rt* rt_entry = sr->routing_table;
  struct sr_rt* best_rt_entry = NULL;
  uint32_t best_mask_len = 0;
  while (rt_entry) {
    uint32_t mask_entry = ntohl(rt_entry->mask.s_addr);
    uint32_t dest_entry = ntohl(rt_entry->dest.s_addr);

    /* LPM */
    if ((ntohl(dest_ip) & mask_entry) == (dest_entry & mask_entry)) {
      uint32_t mask_len = __builtin_popcount(mask_entry);

      if (mask_len > best_mask_len) {
        best_mask_len = mask_len;
        best_rt_entry = rt_entry;
      }
    }
    rt_entry = rt_entry->next;
  }

  return best_rt_entry;
}

void handle_arpreq(struct sr_instance* sr, struct sr_arpreq* req) {
  time_t now = time(NULL);
  if (difftime(now, req->sent) >= 1.0) {
      if (req->times_sent >= 5) {
          struct sr_packet* pkt = req->packets;
          while (pkt) {
              send_icmp_error(sr, pkt->buf, pkt->len, pkt->iface, 3, 1); 
              pkt = pkt->next;
          }
          sr_arpreq_destroy(&(sr->cache), req); 
      } else {
          send_arp_request(sr, req->ip, req->packets->iface);
          req->sent = now;
          req->times_sent++;
      }
  }
}

void send_arp_reply(struct sr_instance* sr, uint32_t target_ip, uint8_t* target_mac, char* iface) {
  uint32_t packet_len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t);
  uint8_t* packet = (uint8_t* )malloc(packet_len);
  sr_ethernet_hdr_t* eth_hdr = (sr_ethernet_hdr_t* )packet;
  sr_arp_hdr_t* arp_hdr = (sr_arp_hdr_t* )(packet + sizeof(sr_arp_hdr_t));

  struct sr_if* iface_info = sr_get_interface(sr, iface);

  memcpy(eth_hdr->ether_shost, iface_info->addr, ETHER_ADDR_LEN);
  memcpy(eth_hdr->ether_dhost, target_mac, ETHER_ADDR_LEN);
  eth_hdr->ether_type = ethertype_arp;

  arp_hdr->ar_hrd = htons(1);
  arp_hdr->ar_pro = ethertype_ip;
  arp_hdr->ar_hln = ETHER_ADDR_LEN;
  arp_hdr->ar_pln = 4;
  arp_hdr->ar_op = arp_op_reply;
  memcpy(arp_hdr->ar_sha, iface_info->addr, ETHER_ADDR_LEN);
  arp_hdr->ar_sip = iface_info->ip;
  memcpy(arp_hdr->ar_tha, target_mac, ETHER_ADDR_LEN);
  arp_hdr->ar_tip = target_ip;

  sr_send_packet(sr, packet, packet_len, iface);
  free(packet);
}

void send_arp_request(struct sr_instance* sr, uint32_t target_ip, char* iface) {
  uint32_t packet_len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t);
  uint8_t* packet = (uint8_t* )malloc(packet_len);
  sr_ethernet_hdr_t* eth_hdr = (sr_ethernet_hdr_t* )packet;
  sr_arp_hdr_t* arp_hdr = (sr_arp_hdr_t* )(packet + sizeof(sr_arp_hdr_t));

  struct sr_if* iface_info = sr_get_interface(sr, iface);

  memcpy(eth_hdr->ether_shost, iface_info->addr, ETHER_ADDR_LEN);
  memset(eth_hdr->ether_dhost, 0xFF, ETHER_ADDR_LEN);
  eth_hdr->ether_type = ethertype_arp;

  arp_hdr->ar_hrd = htons(1);
  arp_hdr->ar_pro = ethertype_ip;
  arp_hdr->ar_hln = ETHER_ADDR_LEN;
  arp_hdr->ar_pln = 4;
  arp_hdr->ar_op = arp_op_request;
  memcpy(arp_hdr->ar_sha, iface_info->addr, ETHER_ADDR_LEN);
  arp_hdr->ar_sip = iface_info->ip;
  memset(arp_hdr->ar_tha, 0x00, ETHER_ADDR_LEN);
  arp_hdr->ar_tip = target_ip;

  sr_send_packet(sr, packet, packet_len, iface);
  free(packet);
}

/* Check that the packet is valid (is large enough to hold an IP header and has a correct checksum) */
int is_valid_packet(struct sr_instance* sr, uint8_t* packet, uint32_t len) {
  if (len < sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t)) {
    return 0; 
  }
  
  sr_ip_hdr_t* ip_hdr = (sr_ip_hdr_t* )(packet + sizeof(sr_ethernet_hdr_t));
  uint32_t ip_hdr_len = ip_hdr->ip_hl * 4;
  if ((ip_hdr_len < sizeof(sr_ip_hdr_t)) || (ntohs(ip_hdr->ip_len) > sizeof(sr_ip_hdr_t))) {
    return 0;
  }

  uint16_t origin_cksum = ip_hdr->ip_sum;
  ip_hdr->ip_sum = 0;
  uint16_t cal_cksum = cksum((uint16_t* )ip_hdr, ip_hdr_len);

  if (origin_cksum != cal_cksum) {
    return 0;
  }

  return 1;
}

int is_icmp_echo_request(struct sr_instance* sr, uint8_t* packet, uint32_t len) {
  sr_icmp_hdr_t* icmp_hdr = (sr_icmp_hdr_t* )(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_icmp_hdr_t));
  if (icmp_hdr->icmp_type != 8) return 0;

  uint16_t recv_cksum = icmp_hdr->icmp_sum;
  icmp_hdr->icmp_sum = 0;
  uint16_t cal_cksum = cksum((uint16_t* )icmp_hdr, sizeof(sr_icmp_hdr_t));
  if (cal_cksum != recv_cksum) {
    return 0;
  }
  return 1;
}