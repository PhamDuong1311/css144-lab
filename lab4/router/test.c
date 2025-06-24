/* Handle TCP */
void sr_nat_handle_tcp(struct sr_instance* sr, uint8_t* packet, uint32_t len, char* iface) {
  sr_ip_hdr_t* ip_hdr = (sr_ip_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t));
  sr_tcp_hdr_t* tcp_hdr = (sr_tcp_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
  struct sr_if* iface_ext_info = sr_get_interface(sr, "eth2");
  struct sr_if* iface_int_info = sr_get_interface(sr, "eth1");
  struct sr_if* ifaces = sr->if_list;
  struct sr_nat_mapping* mapping = NULL;
  int is_if_rt = 0;

  /* From internal */
  if (strcmp(iface, "eth1") == 0) {
      fprintf(stderr, "from internal ethernet -> ");
      while (ifaces) {
        if (ifaces->ip == ip_hdr->ip_dst) {
          fprintf(stderr, "to router\n");
          is_if_rt = 1;
          handle_tcp_to_router(sr, packet, len, iface);
          return;
        }
          ifaces = ifaces->next;
      }
      
      if (is_if_rt == 0) { /* Not for router - needs NAT translation */
          fprintf(stderr, "next-hop through router\n");
          
          /* Endpoint-Independent Mapping: lookup or create mapping */
          mapping = sr_nat_lookup_internal(sr->nat, ip_hdr->ip_src, ntohs(tcp_hdr->tcp_src), nat_mapping_tcp);
          if (!mapping) {
              mapping = sr_nat_insert_mapping(sr->nat, ip_hdr->ip_src, ntohs(tcp_hdr->tcp_src), nat_mapping_tcp);
              if (!mapping) {
                  fprintf(stderr, "Failed to create TCP mapping - drop packet\n");
                  return;
              }
          }
          
          /* Update connection tracking */
          struct sr_nat_connection* conn = sr_nat_lookup_connection(mapping, 
              ip_hdr->ip_src, ip_hdr->ip_dst, ntohs(tcp_hdr->tcp_src), ntohs(tcp_hdr->tcp_dst));
          if (!conn) {
              conn = sr_nat_insert_connection(mapping, 
                  ip_hdr->ip_src, ip_hdr->ip_dst, ntohs(tcp_hdr->tcp_src), ntohs(tcp_hdr->tcp_dst));
          }
          
          /* Update connection state based on TCP flags */
          if (conn) {
              sr_nat_update_tcp_connection_state(conn, tcp_hdr, 1); /* outbound */
          }
          
          /* Translate source IP and port */
          ip_hdr->ip_src = iface_ext_info->ip;
          tcp_hdr->tcp_src = htons(mapping->aux_ext);
          
          /* Update TTL and checksums */
          ip_hdr->ip_ttl--;
          ip_hdr->ip_sum = 0;
          ip_hdr->ip_sum = cksum(ip_hdr, sizeof(sr_ip_hdr_t));
          tcp_hdr->tcp_sum = 0;
          tcp_hdr->tcp_sum = tcp_cksum(ip_hdr, tcp_hdr, len - sizeof(sr_ethernet_hdr_t) - sizeof(sr_ip_hdr_t));

          if (ip_hdr->ip_ttl <= 0) {
              fprintf(stderr, "TCP time exceeded\n");
              send_icmp_error(sr, packet, len, iface, 11, 0);
              return;
          }
          
          /* Forward packet */
          forward_tcp_packet(sr, packet, len, ip_hdr->ip_dst);
      }
  } else { /* From external */
      fprintf(stderr, "TCP from external ethernet -> ");
      
      /* Endpoint-Independent Filtering: lookup mapping */
      mapping = sr_nat_lookup_external(sr->nat, ntohs(tcp_hdr->tcp_dst), nat_mapping_tcp);
      
      if (mapping) {
          fprintf(stderr, "to inside network\n");
          
          /* Check if connection exists or is allowed */
          struct sr_nat_connection* conn = sr_nat_lookup_connection(mapping,
              mapping->ip_int, ip_hdr->ip_src, mapping->aux_int, ntohs(tcp_hdr->tcp_src));
          
          if (conn || sr_nat_is_connection_allowed(mapping, tcp_hdr, ip_hdr->ip_src, ntohs(tcp_hdr->tcp_src))) {
              if (!conn) {
                  /* Create new connection for allowed traffic */
                  conn = sr_nat_insert_connection(mapping,
                      mapping->ip_int, ip_hdr->ip_src, mapping->aux_int, ntohs(tcp_hdr->tcp_src));
              }
              
              /* Update connection state */
              if (conn) {
                  sr_nat_update_tcp_connection_state(conn, tcp_hdr, 0); /* inbound */
              }
              
              /* Translate destination IP and port */
              ip_hdr->ip_dst = mapping->ip_int;
              tcp_hdr->tcp_dst = htons(mapping->aux_int);

              /* Update TTL and checksums */
              ip_hdr->ip_ttl--;
              ip_hdr->ip_sum = 0;
              ip_hdr->ip_sum = cksum(ip_hdr, sizeof(sr_ip_hdr_t));
              tcp_hdr->tcp_sum = 0;
              tcp_hdr->tcp_sum = tcp_cksum(ip_hdr, tcp_hdr, len - sizeof(sr_ethernet_hdr_t) - sizeof(sr_ip_hdr_t));

              if (ip_hdr->ip_ttl <= 0) {
                  fprintf(stderr, "TCP time exceeded\n");
                  send_icmp_error(sr, packet, len, iface, 11, 0);
                  return;
              }
              
              /* Forward to internal network */
              forward_tcp_packet(sr, packet, len, ip_hdr->ip_dst);
          } else {
              fprintf(stderr, "TCP connection not allowed - drop packet\n");
          }
      } else {
          /* Handle unsolicited inbound TCP */
          if (tcp_hdr->tcp_flags & TCP_SYN && !(tcp_hdr->tcp_flags & TCP_ACK)) {
              fprintf(stderr, "unsolicited inbound SYN\n");
              handle_unsolicited_syn(sr, packet, len, iface, ip_hdr, tcp_hdr);
          } else {
              /* Check if packet is for router */
              if (ip_hdr->ip_dst == iface_ext_info->ip) {
                  fprintf(stderr, "to router's external IP\n");
                  handle_tcp_to_router(sr, packet, len, iface);
              } else if (ip_hdr->ip_dst == iface_int_info->ip) {
                  fprintf(stderr, "to router's internal IP - drop\n");
              } else {
                  struct sr_rt* entry = get_match_rt_entry(sr, ip_hdr->ip_dst);
                  if (entry) {
                      if (strcmp(entry->interface, "eth1") == 0) {
                          fprintf(stderr, "to inside network - no mapping, drop\n");
                      } else {
                          fprintf(stderr, "to outside network\n");
                          forward_tcp_no_nat(sr, packet, len);
                      }
                  } else {
                      fprintf(stderr, "No route found - send ICMP unreachable\n");
                      send_icmp_error(sr, packet, len, iface, 3, 0);
                  }
              }
          }
      }
  }
}

/* Update TCP connection state based on flags */
void sr_nat_update_tcp_connection_state(struct sr_nat_connection* conn, sr_tcp_hdr_t* tcp_hdr, int outbound) {
  conn->last_active = time(NULL);
  
  /* Determine if connection is established or transitory */
  if (tcp_hdr->tcp_flags & TCP_SYN) {
      if (tcp_hdr->tcp_flags & TCP_ACK) {
          /* SYN-ACK: moving towards established */
          conn->state = nat_conn_transitory;
      } else {
          /* SYN: initial connection attempt */
          conn->state = nat_conn_transitory;
      }
  } else if (tcp_hdr->tcp_flags & TCP_ACK) {
      /* Data transfer or connection established */
      conn->state = nat_conn_established;
  } else if (tcp_hdr->tcp_flags & (TCP_FIN | TCP_RST)) {
      /* Connection termination */
      conn->state = nat_conn_transitory;
  }
}

/* Check if connection is allowed (Endpoint-Independent Filtering) */
int sr_nat_is_connection_allowed(struct sr_nat_mapping* mapping, sr_tcp_hdr_t* tcp_hdr, 
                              uint32_t remote_ip, uint16_t remote_port) {
  /* For established mappings, allow any external host to connect */
  /* This implements Endpoint-Independent Filtering */
  return 1; /* Allow all connections to existing mappings */
}

/* Handle unsolicited inbound SYN per RFC5382 REQ-4 */
void handle_unsolicited_syn(struct sr_instance* sr, uint8_t* packet, uint32_t len, 
                         char* iface, sr_ip_hdr_t* ip_hdr, sr_tcp_hdr_t* tcp_hdr) {
  
  /* Store the SYN packet for 6 seconds */
  /* If an outbound SYN for same connection arrives, drop this one */
  /* Otherwise, send ICMP Port Unreachable after 6 seconds */
  
  fprintf(stderr, "Storing unsolicited SYN for 6 seconds\n");
  sr_nat_store_unsolicited_syn(sr->nat, packet, len, 
      ip_hdr->ip_src, ntohs(tcp_hdr->tcp_src), ip_hdr->ip_dst, ntohs(tcp_hdr->tcp_dst));
}

/* Calculate TCP checksum with pseudo-header */
uint16_t tcp_cksum(sr_ip_hdr_t* ip_hdr, sr_tcp_hdr_t* tcp_hdr, int len) {
  struct tcp_pseudo_hdr {
      uint32_t src_addr;
      uint32_t dst_addr;
      uint8_t  zero;
      uint8_t  protocol;
      uint16_t tcp_len;
  } pseudo_hdr;
  
  pseudo_hdr.src_addr = ip_hdr->ip_src;
  pseudo_hdr.dst_addr = ip_hdr->ip_dst;
  pseudo_hdr.zero = 0;
  pseudo_hdr.protocol = ip_protocol_tcp;
  pseudo_hdr.tcp_len = htons(len);
  
  /* Calculate checksum over pseudo header + TCP segment */
  uint32_t sum = 0;
  uint16_t* ptr;
  
  /* Add pseudo header */
  ptr = (uint16_t*)&pseudo_hdr;
  for (int i = 0; i < sizeof(pseudo_hdr)/2; i++) {
      sum += ntohs(ptr[i]);
  }
  
  /* Add TCP header and data */
  ptr = (uint16_t*)tcp_hdr;
  for (int i = 0; i < len/2; i++) {
      sum += ntohs(ptr[i]);
  }
  
  /* Handle odd length */
  if (len % 2) {
      sum += ((uint8_t*)tcp_hdr)[len-1] << 8;
  }
  
  /* Fold 32-bit sum to 16 bits */
  while (sum >> 16) {
      sum = (sum & 0xFFFF) + (sum >> 16);
  }
  
  return htons(~sum);
}

/* Forward TCP packet using same logic as ICMP */
void forward_tcp_packet(struct sr_instance* sr, uint8_t* packet, uint32_t len, uint32_t dst_ip) {
  if (sr_load_rt(sr, "rtable") != 0) return;
  
  struct sr_rt* rt_entry = get_match_rt_entry(sr, dst_ip);
  if (!rt_entry) {
      fprintf(stderr, "fail to find rtable for TCP\n");
      send_icmp_error(sr, packet, len, "eth2", 3, 0);
      return;
  } else { 
      fprintf(stderr, "success to find in rtable for TCP\n");
      struct sr_arpentry* arp_entry = sr_arpcache_lookup(&(sr->cache), dst_ip);
      if (arp_entry) { 
          fprintf(stderr, "exist match ARP cache entry for TCP\n");
          sr_ethernet_hdr_t* eth_hdr = (sr_ethernet_hdr_t*)packet;
          struct sr_if* iface_info = sr_get_interface(sr, rt_entry->interface);
          memcpy(eth_hdr->ether_shost, iface_info->addr, ETHER_ADDR_LEN);
          memcpy(eth_hdr->ether_dhost, arp_entry->mac, ETHER_ADDR_LEN);
          fprintf(stderr, "Send TCP frame to next-hop\n");
          sr_send_packet(sr, packet, len, iface_info->name);
          free(arp_entry);
      } else { 
          fprintf(stderr, "don't exist match ARP cache entry for TCP\n");
          struct sr_if* iface_info = sr_get_interface(sr, rt_entry->interface);
          struct sr_arpreq* req = sr_arpcache_queuereq(&(sr->cache), dst_ip, packet, len, iface_info->name);
          handle_arpreq(sr, req);
      } 
  }
}