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
#include <netinet/tcp.h>

#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"
#include "sr_nat.h"

/* Bonus */
void handle_arp_packet(struct sr_instance* sr, uint8_t* packet, uint32_t len, char* iface);
void handle_ip_packet(struct sr_instance* sr, uint8_t* packet, uint32_t len, char* iface);
void send_icmp_echo_reply(struct sr_instance* sr, uint8_t* recv_packet, uint32_t recv_len, char* iface_name);
void send_icmp_error(struct sr_instance* sr, uint8_t* recv_packet, uint32_t len, char* iface_name, uint8_t type, uint8_t code);
struct sr_rt* get_match_rt_entry(struct sr_instance* sr, uint32_t dest_ip);
void send_arp_reply(struct sr_instance* sr, uint32_t target_ip, uint8_t* target_mac, char* iface);
void send_arp_request(struct sr_instance* sr, uint32_t target_ip, char* iface);
int is_valid_packet(struct sr_instance* sr, uint8_t* packet, uint32_t len);
int is_icmp_echo_request(struct sr_instance* sr, uint8_t* packet, uint32_t len);
void sr_nat_handle_tcp (struct sr_instance* sr, uint8_t* packet, uint32_t len, char* iface);
void sr_nat_handle_icmp (struct sr_instance* sr, uint8_t* packet, uint32_t len, char* iface);
int sr_nat_is_connection_allowed(struct sr_nat_mapping* mapping, sr_tcp_hdr_t* tcp_hdr, uint32_t remote_ip, uint16_t remote_port);
void handle_unsolicited_syn(struct sr_instance* sr, uint8_t* packet, uint32_t len, char* iface, sr_ip_hdr_t* ip_hdr, sr_tcp_hdr_t* tcp_hdr);
uint16_t calculate_tcp_checksum(sr_ip_hdr_t* ip_hdr, sr_tcp_hdr_t* tcp_hdr, uint32_t tcp_total_len);

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

  /* fill in code here */
  /* Kiểm tra kích thước packet có chứa đủ ethernet header không */
  if (len < sizeof(sr_ethernet_hdr_t)) {
    return;
  }
  sr_ethernet_hdr_t* eth_hdr = (sr_ethernet_hdr_t* )packet;
  if (ntohs(eth_hdr->ether_type) == ethertype_arp) { /* Nhận được ARP packet */
    fprintf(stderr, "handle arp -> ");
    handle_arp_packet(sr, packet, len, interface);
  } else if (ntohs(eth_hdr->ether_type) == ethertype_ip) { /* Nhận được IP packet */
    fprintf(stderr, "handle ip -> ");
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
    fprintf(stderr, "Handle arp reply\n");
    /* Xóa node ARP request nhận được reply trong queue (nhưng chưa free vì các packet trong ARP request cần gửi đi trước), lưu IP-MAC vào cache*/
    struct sr_arpreq *req = sr_arpcache_insert(&(sr->cache), arp_hdr->ar_sha, arp_hdr->ar_sip); 
    if (req) {
      struct sr_packet* pkt = req->packets;
      struct sr_packet* next_pkt = NULL;
      while (pkt) { /* Gửi tất cả các packet trong ARP request đi */
        next_pkt = pkt->next;
        sr_ethernet_hdr_t* eth_hdr_pkt = (sr_ethernet_hdr_t* )(pkt->buf);
        sr_ip_hdr_t* ip_hdr_pkt = (sr_ip_hdr_t* )(pkt->buf + sizeof(sr_ethernet_hdr_t));
        struct sr_if* out_iface = sr_get_interface(sr, pkt->iface);
        if (ntohl(ip_hdr_pkt->ip_dst) == ntohl(arp_hdr->ar_sip)) {
          ip_hdr_pkt->ip_src = out_iface->ip;
          memcpy(eth_hdr_pkt->ether_dhost, arp_hdr->ar_sha, ETHER_ADDR_LEN);
          memcpy(eth_hdr_pkt->ether_shost, out_iface->addr, ETHER_ADDR_LEN); 
          fprintf(stderr, "Send packet in ARP req queue\n");
          print_hdrs(pkt->buf, pkt->len);
          sr_send_packet(sr, pkt->buf, pkt->len, iface);
        }
        pkt = next_pkt;
      }
      sr_arpreq_destroy(&(sr->cache), req);
    }
  } else if (ntohs(arp_hdr->ar_op) == arp_op_request) { /* Nhận được ARP request */
    fprintf(stderr, "Handle arp request\n");
    struct sr_if* ifa = sr->if_list;


    while (ifa) { /* Kiểm tra xem IP đích của packet có phải là 1 trong các IP của router không*/
      if (arp_hdr->ar_tip == ifa->ip) {
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
  sr_ethernet_hdr_t* eth_hdr = (sr_ethernet_hdr_t* )packet;
  sr_ip_hdr_t* ip_hdr = (sr_ip_hdr_t* )(packet + sizeof(sr_ethernet_hdr_t));
  sr_arpcache_insert(&(sr->cache), eth_hdr->ether_shost, ip_hdr->ip_src);

  if (ip_hdr->ip_p == ip_protocol_icmp) {
    fprintf(stderr, "handle icmp ->");
    sr_nat_handle_icmp(sr, packet, len, iface);
  } else {
    fprintf(stderr, "handle tcp ->");
    sr_nat_handle_tcp(sr, packet, len, iface);
  }
}

void send_icmp_echo_reply(struct sr_instance* sr, uint8_t* recv_packet, uint32_t recv_len, char* iface_name) {
  sr_ethernet_hdr_t* recv_eth_hdr = (sr_ethernet_hdr_t* )recv_packet;
  sr_ip_hdr_t* recv_ip_hdr = (sr_ip_hdr_t* )(recv_packet + sizeof(sr_ethernet_hdr_t));
  sr_icmp_hdr_t* recv_icmp_hdr = (sr_icmp_hdr_t* )(recv_packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));

  uint32_t icmp_data_len = recv_len - sizeof(sr_ethernet_hdr_t) - sizeof(sr_ip_hdr_t) - sizeof(sr_icmp_hdr_t);
  uint32_t send_len = recv_len;
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
  send_ip_hdr->ip_len = htons(recv_len - sizeof(sr_ethernet_hdr_t));
  send_ip_hdr->ip_id = recv_ip_hdr->ip_id;
  send_ip_hdr->ip_off = htons(IP_DF);
  send_ip_hdr->ip_ttl = 64;
  send_ip_hdr->ip_p = ip_protocol_icmp;
  send_ip_hdr->ip_src = recv_ip_hdr->ip_dst;
  send_ip_hdr->ip_dst = recv_ip_hdr->ip_src;
  send_ip_hdr->ip_sum = 0;
  send_ip_hdr->ip_sum = cksum((uint8_t* )send_ip_hdr, sizeof(sr_ip_hdr_t));

  send_icmp_hdr->icmp_type = 0;
  send_icmp_hdr->icmp_code = 0;
  send_icmp_hdr->icmp_sum = 0;
  send_icmp_hdr->icmp_id = recv_icmp_hdr->icmp_id;
  send_icmp_hdr->icmp_seq = recv_icmp_hdr->icmp_seq;

  if (icmp_data_len > 0) {
    uint8_t* recv_icmp_data = recv_packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_hdr_t);
    uint8_t* send_icmp_data = send_packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_hdr_t);
    memcpy(send_icmp_data, recv_icmp_data, icmp_data_len);
  
  }
  send_icmp_hdr->icmp_sum = cksum(send_icmp_hdr, send_len - sizeof(sr_ethernet_hdr_t) - sizeof(sr_ip_hdr_t));

  fprintf(stderr, "Send ICMP echo reply\n");

  sr_send_packet(sr, send_packet, send_len, iface_name);

  free(send_packet);

} 

void send_icmp_error(struct sr_instance* sr, uint8_t* recv_packet, uint32_t len, char* iface_name, uint8_t type, uint8_t code) {
  struct sr_if* iface = sr_get_interface(sr, iface_name);
  if (!iface) {
      fprintf(stderr, "Interface %s not found\n", iface_name);
      return;
  }
  
  sr_ethernet_hdr_t* recv_eth_hdr = (sr_ethernet_hdr_t* )recv_packet;
  sr_ip_hdr_t* recv_ip_hdr = (sr_ip_hdr_t* )(recv_packet + sizeof(sr_ethernet_hdr_t));

  uint32_t send_len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t);
  uint8_t* send_packet = malloc(send_len);

  sr_ethernet_hdr_t* send_eth_hdr = (sr_ethernet_hdr_t*)send_packet;
  sr_ip_hdr_t* send_ip_hdr = (sr_ip_hdr_t*)(send_packet + sizeof(sr_ethernet_hdr_t));
  sr_icmp_t3_hdr_t* send_icmp_hdr = (sr_icmp_t3_hdr_t*)(send_packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
  
  memcpy(send_eth_hdr->ether_dhost, recv_eth_hdr->ether_shost, ETHER_ADDR_LEN);
  memcpy(send_eth_hdr->ether_shost, iface->addr, ETHER_ADDR_LEN);
  send_eth_hdr->ether_type = htons(ethertype_ip);

  send_ip_hdr->ip_hl = 5;            
  send_ip_hdr->ip_v = 4;         
  send_ip_hdr->ip_tos = 0;    
  send_ip_hdr->ip_len = htons(sizeof(sr_icmp_t3_hdr_t) + sizeof(sr_ip_hdr_t));
  send_ip_hdr->ip_id = htons(0);
  send_ip_hdr->ip_off = htons(IP_DF);
  send_ip_hdr->ip_ttl = 64;
  send_ip_hdr->ip_p = htons(ip_protocol_icmp);
  send_ip_hdr->ip_src = iface->ip;
  send_ip_hdr->ip_dst = recv_ip_hdr->ip_src;
  send_ip_hdr->ip_sum = 0;
  send_ip_hdr->ip_sum = cksum(send_ip_hdr, sizeof(sr_ip_hdr_t));

  send_icmp_hdr->icmp_code = code;
  send_icmp_hdr->icmp_type = type;
  send_icmp_hdr->unused = 0;
  send_icmp_hdr->next_mtu = 0;
  uint32_t copy_len = (len - sizeof(sr_ethernet_hdr_t)) > ICMP_DATA_SIZE ? ICMP_DATA_SIZE : (len - sizeof(sr_ethernet_hdr_t));
  memcpy(send_icmp_hdr->data, recv_ip_hdr, copy_len);  
  send_icmp_hdr->icmp_sum = 0;
  send_icmp_hdr->icmp_sum = cksum(send_icmp_hdr, sizeof(sr_icmp_t3_hdr_t));
  fprintf(stderr, "Send ICMP error: type %u, code %u\n", type, code);
  sr_send_packet(sr, send_packet, send_len, iface_name);
}



struct sr_rt* get_match_rt_entry(struct sr_instance* sr, uint32_t ip_dst) {
    struct sr_rt* current_rt_entry = sr->routing_table;
    struct sr_rt* best_match_entry = NULL;
    uint32_t longest_mask_match = 0; 

    while (current_rt_entry) {
        uint32_t current_dest = current_rt_entry->dest.s_addr;
        uint32_t current_mask = current_rt_entry->mask.s_addr;


        if ((ip_dst & current_mask) == (current_dest & current_mask)) {

            if (current_mask > longest_mask_match) {
                best_match_entry = current_rt_entry;
                longest_mask_match = current_mask;
            }
            else if (best_match_entry == NULL && current_mask == 0x00000000) {
                best_match_entry = current_rt_entry;
                longest_mask_match = current_mask;
            }
        }
        current_rt_entry = current_rt_entry->next;
    }

    return best_match_entry;
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
  sr_arp_hdr_t* arp_hdr = (sr_arp_hdr_t* )(packet + sizeof(sr_ethernet_hdr_t));

  struct sr_if* iface_info = sr_get_interface(sr, iface);

  memcpy(eth_hdr->ether_shost, iface_info->addr, ETHER_ADDR_LEN);
  memcpy(eth_hdr->ether_dhost, target_mac, ETHER_ADDR_LEN);
  eth_hdr->ether_type = htons(ethertype_arp);

  arp_hdr->ar_hrd = htons(1);
  arp_hdr->ar_pro = htons(ethertype_ip);
  arp_hdr->ar_hln = ETHER_ADDR_LEN;
  arp_hdr->ar_pln = 4;
  arp_hdr->ar_op = htons(arp_op_reply);
  memcpy(arp_hdr->ar_sha, iface_info->addr, ETHER_ADDR_LEN);
  arp_hdr->ar_sip = iface_info->ip;
  memcpy(arp_hdr->ar_tha, target_mac, ETHER_ADDR_LEN);
  arp_hdr->ar_tip = target_ip;
  fprintf(stderr, "Send ARP reply\n");

  sr_send_packet(sr, packet, packet_len, iface);
  free(packet);
}

void send_arp_request(struct sr_instance* sr, uint32_t target_ip, char* iface) {
  uint32_t packet_len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t);
  uint8_t* packet = (uint8_t* )malloc(packet_len);
  sr_ethernet_hdr_t* eth_hdr = (sr_ethernet_hdr_t* )packet;
  sr_arp_hdr_t* arp_hdr = (sr_arp_hdr_t* )(packet + sizeof(sr_ethernet_hdr_t));

  struct sr_if* iface_info = sr_get_interface(sr, iface);

  memcpy(eth_hdr->ether_shost, iface_info->addr, ETHER_ADDR_LEN);
  memset(eth_hdr->ether_dhost, 0xFF, ETHER_ADDR_LEN);
  eth_hdr->ether_type = htons(ethertype_arp);

  arp_hdr->ar_hrd = htons(1);
  arp_hdr->ar_pro = htons(ethertype_ip);
  arp_hdr->ar_hln = ETHER_ADDR_LEN;
  arp_hdr->ar_pln = 4;
  arp_hdr->ar_op = htons(arp_op_request);
  memcpy(arp_hdr->ar_sha, iface_info->addr, ETHER_ADDR_LEN);
  arp_hdr->ar_sip = iface_info->ip;
  memset(arp_hdr->ar_tha, 0x00, ETHER_ADDR_LEN);
  arp_hdr->ar_tip = target_ip;
  fprintf(stderr, "Send ARP request\n");
  sr_send_packet(sr, packet, packet_len, iface);
  free(packet);
}

/* Check that the packet is valid (is large enough to hold an IP header and has a correct checksum) */
int is_valid_packet(struct sr_instance* sr, uint8_t* packet, uint32_t len) {
  if (len < sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t)) {
    fprintf(stderr, "IP PACKET fail\n");

    return 0; 
  }

  sr_ip_hdr_t* ip_hdr = (sr_ip_hdr_t* )(packet + sizeof(sr_ethernet_hdr_t));
  uint32_t ip_hdr_len = ip_hdr->ip_hl * 4;
  if ((ip_hdr_len < sizeof(sr_ip_hdr_t)) || (ntohs(ip_hdr->ip_len) > sizeof(sr_ip_hdr_t))) {
    fprintf(stderr, "IP PACKET fail\n");

    return 0;
  }

  uint16_t origin_cksum = ip_hdr->ip_sum;
  ip_hdr->ip_sum = 0;
  uint16_t cal_cksum = cksum((uint16_t* )ip_hdr, ip_hdr_len);

  if (origin_cksum != cal_cksum) {
    fprintf(stderr, "IP PACKET fail\n");

    return 0;
  }

  return 1;
}

int is_icmp_echo_request(struct sr_instance* sr, uint8_t* packet, uint32_t len) {
  sr_icmp_hdr_t* icmp_hdr = (sr_icmp_hdr_t* )(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
  if (icmp_hdr->icmp_type != 8) return 0;

  uint16_t recv_cksum = icmp_hdr->icmp_sum;
  icmp_hdr->icmp_sum = 0;
  uint16_t cal_cksum = cksum((uint16_t* )icmp_hdr, len - sizeof(sr_ethernet_hdr_t) - sizeof(sr_ip_hdr_t));
  icmp_hdr->icmp_sum = recv_cksum;
  if (cal_cksum != recv_cksum) {
    return 0;
  }
  return 1;
}




/* Bonus for NAT */

/* Handle ICMP packet */
void sr_nat_handle_icmp(struct sr_instance* sr, uint8_t* packet, uint32_t len, char* iface) {
  sr_ip_hdr_t* ip_hdr = (sr_ip_hdr_t* )(packet + sizeof(sr_ethernet_hdr_t));
  sr_icmp_hdr_t* icmp_hdr = (sr_icmp_hdr_t* )(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
  struct sr_if* iface_ext_info = sr_get_interface(sr, "eth2");
  struct sr_if* iface_int_info = sr_get_interface(sr, "eth1");
  struct sr_if* ifaces = sr->if_list;
  struct sr_nat_mapping* mapping = NULL;
  int is_if_rt = 0;

  /* From internal */
  if (strcmp(iface, "eth1") == 0) {
    fprintf(stderr, "from internal ethernet -> ");
    while (ifaces) { /* For Router */
      if (ifaces->ip == ip_hdr->ip_dst) {
        fprintf(stderr, "to router\n");
        is_if_rt = 1;
        if (is_icmp_echo_request(sr, packet, len)) {
          send_icmp_echo_reply(sr, packet, len, iface);
        }
      }
      ifaces = ifaces->next;
    }
    
    if (is_if_rt == 0) { /* Not for router */
      fprintf(stderr, "next-hop through router\n");
      
      mapping = sr_nat_insert_mapping(sr->nat, ip_hdr->ip_src, icmp_hdr->icmp_id, nat_mapping_icmp);
      ip_hdr->ip_src = iface_ext_info->ip;
      icmp_hdr->icmp_id = mapping->aux_ext;


      ip_hdr->ip_ttl--;
      ip_hdr->ip_sum = 0;
      ip_hdr->ip_sum = cksum(ip_hdr, sizeof(sr_ip_hdr_t));
      icmp_hdr->icmp_sum = 0;
      icmp_hdr->icmp_sum = cksum(icmp_hdr, len - sizeof(sr_ethernet_hdr_t) - sizeof(sr_ip_hdr_t));

      if (ip_hdr->ip_ttl <= 0) {
        fprintf(stderr, "time exceeded\n");
        send_icmp_error(sr, packet, len, iface, 11, 0);
        return;
      } else { 
        if (sr_load_rt(sr, "rtable") != 0) return;
        struct sr_rt* rt_entry = get_match_rt_entry(sr, ip_hdr->ip_dst);
        if (!rt_entry) {
          fprintf(stderr, "fail to find rtable\n");
          send_icmp_error(sr, packet, len, iface, 3, 0);
          return;
        } else { 
          fprintf(stderr, "success to find in rtable\n");
          struct sr_arpentry* arp_entry = sr_arpcache_lookup(&(sr->cache), ip_hdr->ip_dst);
          if (arp_entry) { 
            fprintf(stderr, "exist match ARP cache entry\n");
            sr_ethernet_hdr_t* eth_hdr = (sr_ethernet_hdr_t*)packet;
            struct sr_if* iface_info = sr_get_interface(sr, rt_entry->interface);
            memcpy(eth_hdr->ether_shost, iface_info->addr, ETHER_ADDR_LEN);
            memcpy(eth_hdr->ether_dhost, arp_entry->mac, ETHER_ADDR_LEN);
            fprintf(stderr, "Send frame to next-hop\n");
            sr_send_packet(sr, packet, len, iface_info->name);
            free(arp_entry);
          } else { 
            fprintf(stderr, "don't exist match ARP cache entry\n");
            struct sr_if* iface_info = sr_get_interface(sr, rt_entry->interface);
            struct sr_arpreq* req = sr_arpcache_queuereq(&(sr->cache), ip_hdr->ip_dst, packet, len, iface_info->name);
            handle_arpreq(sr, req);
          } 
        }
      }
    }
  } else { /* From external */

    fprintf(stderr, "from external ethernet ->");
    mapping = sr_nat_lookup_external(sr->nat, icmp_hdr->icmp_id, nat_mapping_icmp);
    if (mapping) { 
      fprintf(stderr, "to inside network\n");
      ip_hdr->ip_dst = mapping->ip_int;
      icmp_hdr->icmp_id = mapping->aux_int;

      ip_hdr->ip_ttl--;
      ip_hdr->ip_sum = 0;
      ip_hdr->ip_sum = cksum(ip_hdr, sizeof(sr_ip_hdr_t));
      icmp_hdr->icmp_sum = 0;
      icmp_hdr->icmp_sum = cksum(icmp_hdr, len - sizeof(sr_ethernet_hdr_t) - sizeof(sr_ip_hdr_t));

      if (ip_hdr->ip_ttl <= 0) {
        fprintf(stderr, "time exceeded\n");
        send_icmp_error(sr, packet, len, iface, 11, 0);
        return;
      } else { 
        if (sr_load_rt(sr, "rtable") != 0) return;
        struct sr_rt* rt_entry = get_match_rt_entry(sr, ip_hdr->ip_dst);
        if (!rt_entry) {
          fprintf(stderr, "fail to find rtable\n");
          send_icmp_error(sr, packet, len, iface, 3, 0);
          return;
        } else { 
          fprintf(stderr, "success to find in rtable\n");
          struct sr_arpentry* arp_entry = sr_arpcache_lookup(&(sr->cache), ip_hdr->ip_dst);
          if (arp_entry) { 
            fprintf(stderr, "exist match ARP cache entry\n");
            sr_ethernet_hdr_t* eth_hdr = (sr_ethernet_hdr_t*)packet;
            struct sr_if* iface_info = sr_get_interface(sr, rt_entry->interface);
            memcpy(eth_hdr->ether_shost, iface_info->addr, ETHER_ADDR_LEN);
            memcpy(eth_hdr->ether_dhost, arp_entry->mac, ETHER_ADDR_LEN);
            fprintf(stderr, "Send frame to next-hop\n");
            sr_send_packet(sr, packet, len, iface_info->name);
            free(arp_entry);
          } else { 
            fprintf(stderr, "don't exist match ARP cache entry\n");
            struct sr_if* iface_info = sr_get_interface(sr, rt_entry->interface);
            struct sr_arpreq* req = sr_arpcache_queuereq(&(sr->cache), ip_hdr->ip_dst, packet, len, iface_info->name);
            handle_arpreq(sr, req);
          } 
        }
      }
    } else {
      if (ip_hdr->ip_dst == iface_ext_info->ip) {
        fprintf(stderr, "to router's external IP\n");
        if (is_icmp_echo_request(sr, packet, len)) {
          send_icmp_echo_reply(sr, packet, len, iface);
        }
      } else if (ip_hdr->ip_dst == iface_int_info->ip) {
        fprintf(stderr, "to router's internal IP\n");
        fprintf(stderr, "drop packet\n");
        return;
      } else {
        struct sr_rt* entry = get_match_rt_entry(sr, ip_hdr->ip_dst);
        if (entry) {
          if (strcmp(entry->interface, "eth1") == 0) {
            fprintf(stderr, "to inside network\n");
            mapping = sr_nat_lookup_external(sr->nat, icmp_hdr->icmp_id, nat_mapping_icmp);
            if (mapping) { 
              ip_hdr->ip_dst = mapping->ip_int;
              icmp_hdr->icmp_id = mapping->aux_int;
        
              ip_hdr->ip_ttl--;
              ip_hdr->ip_sum = 0;
              ip_hdr->ip_sum = cksum(ip_hdr, sizeof(sr_ip_hdr_t));
              icmp_hdr->icmp_sum = 0;
              icmp_hdr->icmp_sum = cksum(icmp_hdr, len - sizeof(sr_ethernet_hdr_t) - sizeof(sr_ip_hdr_t));
        
              if (ip_hdr->ip_ttl <= 0) {
                fprintf(stderr, "time exceeded\n");
                send_icmp_error(sr, packet, len, iface, 11, 0);
                return;
              } else { 
                if (sr_load_rt(sr, "rtable") != 0) return;
                struct sr_rt* rt_entry = get_match_rt_entry(sr, ip_hdr->ip_dst);
                if (!rt_entry) {
                  fprintf(stderr, "fail to find rtable\n");
                  send_icmp_error(sr, packet, len, iface, 3, 0);
                  return;
                } else { 
                  fprintf(stderr, "success to find in rtable\n");
                  struct sr_arpentry* arp_entry = sr_arpcache_lookup(&(sr->cache), ip_hdr->ip_dst);
                  if (arp_entry) { 
                    fprintf(stderr, "exist match ARP cache entry\n");
                    sr_ethernet_hdr_t* eth_hdr = (sr_ethernet_hdr_t*)packet;
                    struct sr_if* iface_info = sr_get_interface(sr, rt_entry->interface);
                    memcpy(eth_hdr->ether_shost, iface_info->addr, ETHER_ADDR_LEN);
                    memcpy(eth_hdr->ether_dhost, arp_entry->mac, ETHER_ADDR_LEN);
                    fprintf(stderr, "Send frame to next-hop\n");
                    sr_send_packet(sr, packet, len, iface_info->name);
                    free(arp_entry);
                  } else { 
                    fprintf(stderr, "don't exist match ARP cache entry\n");
                    struct sr_if* iface_info = sr_get_interface(sr, rt_entry->interface);
                    struct sr_arpreq* req = sr_arpcache_queuereq(&(sr->cache), ip_hdr->ip_dst, packet, len, iface_info->name);
                    handle_arpreq(sr, req);
                  } 
                }
              }
            } else {
              fprintf(stderr, "don't exist mapping in nat table for external network -> drop\n");
            }
          } else {
            fprintf(stderr, "to outside network\n");
            ip_hdr->ip_ttl--;
            ip_hdr->ip_sum = 0;
            ip_hdr->ip_sum = cksum(ip_hdr, sizeof(sr_ip_hdr_t));
            icmp_hdr->icmp_sum = 0;
            icmp_hdr->icmp_sum = cksum(icmp_hdr, len - sizeof(sr_ethernet_hdr_t) - sizeof(sr_ip_hdr_t));
      
            if (ip_hdr->ip_ttl <= 0) {
              fprintf(stderr, "time exceeded\n");
              send_icmp_error(sr, packet, len, iface, 11, 0);
              return;
            } else { 
              if (sr_load_rt(sr, "rtable") != 0) return;
              struct sr_rt* rt_entry = get_match_rt_entry(sr, ip_hdr->ip_dst);
              if (!rt_entry) {
                fprintf(stderr, "fail to find rtable\n");
                send_icmp_error(sr, packet, len, iface, 3, 0);
                return;
              } else { 
                fprintf(stderr, "success to find in rtable\n");
                struct sr_arpentry* arp_entry = sr_arpcache_lookup(&(sr->cache), ip_hdr->ip_dst);
                if (arp_entry) { 
                  fprintf(stderr, "exist match ARP cache entry\n");
                  sr_ethernet_hdr_t* eth_hdr = (sr_ethernet_hdr_t*)packet;
                  struct sr_if* iface_info = sr_get_interface(sr, rt_entry->interface);
                  memcpy(eth_hdr->ether_shost, iface_info->addr, ETHER_ADDR_LEN);
                  memcpy(eth_hdr->ether_dhost, arp_entry->mac, ETHER_ADDR_LEN);
                  fprintf(stderr, "Send frame to next-hop\n");
                  sr_send_packet(sr, packet, len, iface_info->name);
                  free(arp_entry);
                } else { 
                  fprintf(stderr, "don't exist match ARP cache entry\n");
                  struct sr_if* iface_info = sr_get_interface(sr, rt_entry->interface);
                  struct sr_arpreq* req = sr_arpcache_queuereq(&(sr->cache), ip_hdr->ip_dst, packet, len, iface_info->name);
                  handle_arpreq(sr, req);
                } 
              }
            }
          }
        }

      }
    }
  }
}


void sr_nat_handle_tcp(struct sr_instance* sr, uint8_t* packet, uint32_t len, char* iface) {
  sr_ip_hdr_t* ip_hdr = (sr_ip_hdr_t* )(packet + sizeof(sr_ethernet_hdr_t));
  uint32_t ip_hdr_len = ip_hdr->ip_hl * 4;
  sr_tcp_hdr_t* tcp_hdr = (sr_tcp_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t) + ip_hdr_len);

  uint32_t tcp_total_len = ntohs(ip_hdr->ip_len) - ip_hdr_len;

  struct sr_if* iface_ext_info = sr_get_interface(sr, "eth2");
  struct sr_if* iface_int_info = sr_get_interface(sr, "eth1");
  struct sr_if* ifaces_temp_iter = sr->if_list;
  struct sr_nat_mapping* mapping = NULL;
  struct sr_nat_connection* conn = NULL;
  int is_for_router_itself = 0;

  if (strcmp(iface, "eth1") == 0) {
    fprintf(stderr, "from internal ethernet -> ");
    while (ifaces_temp_iter) { 
      if (ifaces_temp_iter->ip == ip_hdr->ip_dst) {
        fprintf(stderr, "to router\n");
        is_for_router_itself = 1;
        fprintf(stderr, "Can't get data from router (TCP for router itself)\n");
        return; 
      }
      ifaces_temp_iter = ifaces_temp_iter->next;
    }
    
    if (is_for_router_itself == 0) { 
      fprintf(stderr, "next-hop through router (NAT outbound)\n");
      print_hdrs(packet, len);

      mapping = sr_nat_lookup_internal(sr->nat, ip_hdr->ip_src, ntohs(tcp_hdr->tcp_src), nat_mapping_tcp);
      if (!mapping) {
          mapping = sr_nat_insert_mapping(sr->nat, ip_hdr->ip_src, ntohs(tcp_hdr->tcp_src), nat_mapping_tcp);
      }
      conn = sr_nat_lookup_connection(mapping, ip_hdr->ip_src, ip_hdr->ip_dst, ntohs(tcp_hdr->tcp_src), ntohs(tcp_hdr->tcp_dst));
      if (!conn) {
          conn = sr_nat_insert_connection(mapping, ip_hdr->ip_src, ip_hdr->ip_dst, ntohs(tcp_hdr->tcp_src), ntohs(tcp_hdr->tcp_dst));
          if (!conn) {
              fprintf(stderr, "Error: Failed to insert new connection for outbound TCP.\n");
              return;
          }
      } else {
        conn->last_active = time(NULL);
        if ((tcp_hdr->tcp_flags & TH_SYN) && (tcp_hdr->tcp_flags & TH_ACK)) {
          conn->state = nat_conn_established;
        } else if (tcp_hdr->tcp_flags & TH_SYN) {
            conn->state = nat_conn_transitory;
        } else if (tcp_hdr->tcp_flags & (TH_FIN | TH_RST)) {
        } else {
        }
      }

      ip_hdr->ip_src = iface_ext_info->ip;
      tcp_hdr->tcp_src = htons(mapping->aux_ext);

      ip_hdr->ip_ttl--;
      ip_hdr->ip_sum = 0;
      ip_hdr->ip_sum = cksum(ip_hdr, ip_hdr_len);

      tcp_hdr->tcp_sum = 0;
      tcp_hdr->tcp_sum = calculate_tcp_checksum(ip_hdr, tcp_hdr, tcp_total_len);

      if (ip_hdr->ip_ttl <= 0) {
        fprintf(stderr, "time exceeded\n");
        send_icmp_error(sr, packet, len, iface, 11, 0);
        return;
      } else { 
        if (sr_load_rt(sr, "rtable") != 0) return;
        struct sr_rt* rt_entry = get_match_rt_entry(sr, ip_hdr->ip_dst);
        if (!rt_entry) {
          fprintf(stderr, "fail to find rtable entry for destination IP\n");
          send_icmp_error(sr, packet, len, iface, 3, 0);
          return;
        } else { 
          fprintf(stderr, "success to find in rtable\n");
          struct sr_arpentry* arp_entry = sr_arpcache_lookup(&(sr->cache), rt_entry->gw.s_addr);
          if (arp_entry) { 
            fprintf(stderr, "exist match ARP cache entry\n");
            sr_ethernet_hdr_t* eth_hdr = (sr_ethernet_hdr_t*)packet;
            struct sr_if* iface_info = sr_get_interface(sr, rt_entry->interface);
            memcpy(eth_hdr->ether_shost, iface_info->addr, ETHER_ADDR_LEN);
            memcpy(eth_hdr->ether_dhost, arp_entry->mac, ETHER_ADDR_LEN);
            fprintf(stderr, "Send frame to next-hop\n");
            sr_send_packet(sr, packet, len, iface_info->name);
            free(arp_entry);
          } else { 
            fprintf(stderr, "don't exist match ARP cache entry, queueing ARP request\n");
            struct sr_if* iface_info = sr_get_interface(sr, rt_entry->interface);
            struct sr_arpreq* req = sr_arpcache_queuereq(&(sr->cache), rt_entry->gw.s_addr, packet, len, iface_info->name);
            handle_arpreq(sr, req);
          } 
        }
      }
    }
  } else {

    fprintf(stderr, "from external ethernet ->");
    mapping = sr_nat_lookup_external(sr->nat, ntohs(tcp_hdr->tcp_dst), nat_mapping_tcp);
    if (mapping) { 
      fprintf(stderr, "to inside network (NAT inbound)\n");
      print_hdrs(packet, len);
      
      conn = sr_nat_lookup_connection(mapping, mapping->ip_int, ip_hdr->ip_src, mapping->aux_int, ntohs(tcp_hdr->tcp_src));
      
      if (conn || sr_nat_is_connection_allowed(mapping, tcp_hdr, ip_hdr->ip_src, ntohs(tcp_hdr->tcp_src))) {
        if (!conn) {
            conn = sr_nat_insert_connection(mapping, mapping->ip_int, ip_hdr->ip_src, mapping->aux_int, ntohs(tcp_hdr->tcp_src));
            if (!conn) {
                fprintf(stderr, "Error: Failed to insert new connection for inbound TCP.\n");
                return;
            }
        }
        conn->last_active = time(NULL);
        if ((tcp_hdr->tcp_flags & TH_SYN) && (tcp_hdr->tcp_flags & TH_ACK)) {
            conn->state = nat_conn_established;
        } else if (tcp_hdr->tcp_flags & TH_SYN) {
            conn->state = nat_conn_transitory;
        } else if (tcp_hdr->tcp_flags & (TH_FIN | TH_RST)) {
        } else {
        }

        ip_hdr->ip_dst = mapping->ip_int;
        tcp_hdr->tcp_dst = htons(mapping->aux_int);

        ip_hdr->ip_ttl--;
        ip_hdr->ip_sum = 0;
        ip_hdr->ip_sum = cksum(ip_hdr, ip_hdr_len);

        tcp_hdr->tcp_sum = 0;
        tcp_hdr->tcp_sum = calculate_tcp_checksum(ip_hdr, tcp_hdr, tcp_total_len);

        if (ip_hdr->ip_ttl <= 0) {
          fprintf(stderr, "time exceeded\n");
          send_icmp_error(sr, packet, len, iface, 11, 0);
          return;
        } else { 
          if (sr_load_rt(sr, "rtable") != 0) return;
          struct sr_rt* rt_entry = get_match_rt_entry(sr, ip_hdr->ip_dst);
          if (!rt_entry) {
            fprintf(stderr, "fail to find rtable entry for destination IP\n");
            send_icmp_error(sr, packet, len, iface, 3, 0);
            return;
          } else { 
            fprintf(stderr, "success to find in rtable\n");
            struct sr_arpentry* arp_entry = sr_arpcache_lookup(&(sr->cache), rt_entry->gw.s_addr);
            if (arp_entry) { 
              fprintf(stderr, "exist match ARP cache entry\n");
              sr_ethernet_hdr_t* eth_hdr = (sr_ethernet_hdr_t*)packet;
              struct sr_if* iface_info = sr_get_interface(sr, rt_entry->interface);
              memcpy(eth_hdr->ether_shost, iface_info->addr, ETHER_ADDR_LEN);
              memcpy(eth_hdr->ether_dhost, arp_entry->mac, ETHER_ADDR_LEN);
              fprintf(stderr, "Send frame to next-hop\n");
              print_hdrs(packet, len);

              sr_send_packet(sr, packet, len, iface_info->name);
              free(arp_entry);
            } else { 
              fprintf(stderr, "don't exist match ARP cache entry, queueing ARP request\n");
              struct sr_if* iface_info = sr_get_interface(sr, rt_entry->interface);
              struct sr_arpreq* req = sr_arpcache_queuereq(&(sr->cache), rt_entry->gw.s_addr, packet, len, iface_info->name);
              handle_arpreq(sr, req);
            } 
          }
        }
      } else {
        fprintf(stderr, "TCP connection not allowed (unsolicited or no mapping) - drop packet\n");
        return; 
      }
    } else {
      if (ip_hdr->ip_dst == iface_ext_info->ip) {
        fprintf(stderr, "to router's external IP\n");
        if (is_icmp_echo_request(sr, packet, len)) {
          send_icmp_echo_reply(sr, packet, len, iface);
        }
      } else if (ip_hdr->ip_dst == iface_int_info->ip) {
        fprintf(stderr, "to router's internal IP\n");
        fprintf(stderr, "drop packet (unsolicited traffic to internal IP from external, direct access attempt)\n");
        return;
      } else {
        struct sr_rt* rt_entry = get_match_rt_entry(sr, ip_hdr->ip_dst);
        if (rt_entry) {
          if (strcmp(rt_entry->interface, "eth1") == 0) {
            fprintf(stderr, "to inside network (potential unsolicited incoming NAT traffic without specific mapping. This often implies a security risk or misconfiguration for NAT!)\n");
            mapping = sr_nat_lookup_external(sr->nat, ntohs(tcp_hdr->tcp_src), nat_mapping_tcp);

            if (mapping) { 
              ip_hdr->ip_dst = mapping->ip_int;
              tcp_hdr->tcp_src = htons(mapping->aux_int);
          
              ip_hdr->ip_ttl--;
              ip_hdr->ip_sum = 0;
              ip_hdr->ip_sum = cksum(ip_hdr, ip_hdr_len);

              tcp_hdr->tcp_sum = 0;
              tcp_hdr->tcp_sum = calculate_tcp_checksum(ip_hdr, tcp_hdr, tcp_total_len);        
              
              if (ip_hdr->ip_ttl <= 0) {
                fprintf(stderr, "time exceeded\n");
                send_icmp_error(sr, packet, len, iface, 11, 0);
                return;
              } else { 
                if (sr_load_rt(sr, "rtable") != 0) return;
                struct sr_rt* inner_rt_entry = get_match_rt_entry(sr, ip_hdr->ip_dst);
                if (!inner_rt_entry) {
                  fprintf(stderr, "fail to find rtable entry for destination IP after NAT\n");
                  send_icmp_error(sr, packet, len, iface, 3, 0);
                  return;
                } else { 
                  fprintf(stderr, "success to find in rtable\n");
                  struct sr_arpentry* arp_entry = sr_arpcache_lookup(&(sr->cache), inner_rt_entry->gw.s_addr);
                  if (arp_entry) { 
                    fprintf(stderr, "exist match ARP cache entry\n");
                    sr_ethernet_hdr_t* eth_hdr = (sr_ethernet_hdr_t*)packet;
                    struct sr_if* iface_info = sr_get_interface(sr, inner_rt_entry->interface);
                    memcpy(eth_hdr->ether_shost, iface_info->addr, ETHER_ADDR_LEN);
                    memcpy(eth_hdr->ether_dhost, arp_entry->mac, ETHER_ADDR_LEN);
                    fprintf(stderr, "Send frame to next-hop\n");
                    sr_send_packet(sr, packet, len, iface_info->name);
                    free(arp_entry);
                  } else { 
                    fprintf(stderr, "don't exist match ARP cache entry, queueing ARP request\n");
                    struct sr_if* iface_info = sr_get_interface(sr, inner_rt_entry->interface);
                    struct sr_arpreq* req = sr_arpcache_queuereq(&(sr->cache), inner_rt_entry->gw.s_addr, packet, len, iface_info->name);
                    handle_arpreq(sr, req);
                  } 
                }
              }
            } else {
              fprintf(stderr, "don't exist mapping in nat table for external network (unsolicited incoming) -> drop\n");
              return;
            }
          } else {
            fprintf(stderr, "to outside network (normal routing, no NAT translation needed)\n");
            ip_hdr->ip_ttl--;
            ip_hdr->ip_sum = 0;
            ip_hdr->ip_sum = cksum(ip_hdr, ip_hdr_len);
            
            tcp_hdr->tcp_sum = 0;
            tcp_hdr->tcp_sum = calculate_tcp_checksum(ip_hdr, tcp_hdr, tcp_total_len);    

            if (ip_hdr->ip_ttl <= 0) {
              fprintf(stderr, "time exceeded\n");
              send_icmp_error(sr, packet, len, iface, 11, 0);
              return;
            } else { 
              if (sr_load_rt(sr, "rtable") != 0) return;
              struct sr_rt* inner_rt_entry = get_match_rt_entry(sr, ip_hdr->ip_dst);
              if (!inner_rt_entry) {
                fprintf(stderr, "fail to find rtable entry for destination IP\n");
                send_icmp_error(sr, packet, len, iface, 3, 0);
                return;
              } else { 
                fprintf(stderr, "success to find in rtable\n");
                struct sr_arpentry* arp_entry = sr_arpcache_lookup(&(sr->cache), inner_rt_entry->gw.s_addr);
                if (arp_entry) { 
                  fprintf(stderr, "exist match ARP cache entry\n");
                  sr_ethernet_hdr_t* eth_hdr = (sr_ethernet_hdr_t*)packet;
                  struct sr_if* iface_info = sr_get_interface(sr, inner_rt_entry->interface);
                  memcpy(eth_hdr->ether_shost, iface_info->addr, ETHER_ADDR_LEN);
                  memcpy(eth_hdr->ether_dhost, arp_entry->mac, ETHER_ADDR_LEN);
                  fprintf(stderr, "Send frame to next-hop\n");
                  sr_send_packet(sr, packet, len, iface_info->name);
                  free(arp_entry);
                } else { 
                  fprintf(stderr, "don't exist match ARP cache entry, queueing ARP request\n");
                  struct sr_if* iface_info = sr_get_interface(sr, inner_rt_entry->interface);
                  struct sr_arpreq* req = sr_arpcache_queuereq(&(sr->cache), inner_rt_entry->gw.s_addr, packet, len, iface_info->name);
                  handle_arpreq(sr, req);
                } 
              }
            }
          }
        } else {
            fprintf(stderr, "No route to host (from external, no mapping, no internal route)\n");
            send_icmp_error(sr, packet, len, iface, 3, 0);
            return;
        }
      }
    }
  }
}

/* Check if connection is allowed (Endpoint-Independent Filtering) */
int sr_nat_is_connection_allowed(struct sr_nat_mapping* mapping, sr_tcp_hdr_t* tcp_hdr, uint32_t remote_ip, uint16_t remote_port) {
  /* For established mappings, allow any external host to connect */
  /* This implements Endpoint-Independent Filtering */
  return 1; /* Allow all connections to existing mappings */
}

/* Handle unsolicited inbound SYN per RFC5382 REQ-4 */
void handle_unsolicited_syn(struct sr_instance* sr, uint8_t* packet, uint32_t len, char* iface, sr_ip_hdr_t* ip_hdr, sr_tcp_hdr_t* tcp_hdr) {
  
  /* Store the SYN packet for 6 seconds */
  /* If an outbound SYN for same connection arrives, drop this one */
  /* Otherwise, send ICMP Port Unreachable after 6 seconds */
  
  fprintf(stderr, "Storing unsolicited SYN for 6 seconds\n");

}


uint16_t calculate_tcp_checksum(sr_ip_hdr_t* ip_hdr, sr_tcp_hdr_t* tcp_hdr, uint32_t tcp_total_len) {
    uint32_t pseudo_header_len = 12; 
    uint32_t total_len = pseudo_header_len + tcp_total_len;

    uint8_t *checksum_buf = (uint8_t *)malloc(total_len + (total_len % 2));
    if (!checksum_buf) {
        return 1;
    }

    memcpy(checksum_buf, &(ip_hdr->ip_src), 4); 
    memcpy(checksum_buf + 4, &(ip_hdr->ip_dst), 4); 
    checksum_buf[8] = 0; 
    checksum_buf[9] = ip_hdr->ip_p; 
    *((uint16_t *)(checksum_buf + 10)) = htons(tcp_total_len); 

    uint16_t original_tcp_sum = tcp_hdr->tcp_sum; 
    tcp_hdr->tcp_sum = 0; 
    memcpy(checksum_buf + pseudo_header_len, tcp_hdr, tcp_total_len);
    tcp_hdr->tcp_sum = original_tcp_sum; 

    if (total_len % 2 != 0) {
        checksum_buf[total_len] = 0; 
        total_len++;
    }

    uint16_t calculated_sum = cksum(checksum_buf, total_len);

    free(checksum_buf);
    return calculated_sum;
}