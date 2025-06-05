/* This file defines an ARP cache, which is made of two structures: an ARP
   request queue, and ARP cache entries. The ARP request queue holds data about
   an outgoing ARP cache request and the packets that are waiting on a reply
   to that ARP cache request. The ARP cache entries hold IP->MAC mappings and
   are timed out every SR_ARPCACHE_TO seconds.

   Pseudocode for use of these structures follows.

   --

   # When sending packet to next_hop_ip
   entry = arpcache_lookup(next_hop_ip)

   if entry:
       use next_hop_ip->mac mapping in entry to send the packet
       free entry
   else:
       req = arpcache_queuereq(next_hop_ip, packet, len)
       handle_arpreq(req) 

   --

   The handle_arpreq() function is a function you should write, and it should
   handle sending ARP requests if necessary:

   function handle_arpreq(req):
       if difftime(now, req->sent) >= 1.0
           if req->times_sent >= 5:
               send icmp host unreachable to source addr of all pkts waiting
                 on this request
               arpreq_destroy(req)
           else:
               send arp request
               req->sent = now
               req->times_sent++

   --

   The ARP reply processing code should move entries from the ARP request
   queue to the ARP cache:

   # When servicing an arp reply that gives us an IP->MAC mapping
   req = arpcache_insert(ip, mac)

   if req:
       send all packets on the req->packets linked list
       arpreq_destroy(req)

   --

   To meet the guidelines in the assignment (ARP requests are sent every second
   until we send 5 ARP requests, then we send ICMP host unreachable back to
   all packets waiting on this ARP request), you must fill out the following
   function that is called every second and is defined in sr_arpcache.c:

   void sr_arpcache_sweepreqs(struct sr_instance *sr) {
       for each request on sr->cache.requests:
           handle_arpreq(request)
   }

   Since handle_arpreq as defined in the comments above could destroy your
   current request, make sure to save the next pointer before calling
   handle_arpreq when traversing through the ARP requests linked list.
 */

#ifndef SR_ARPCACHE_H
#define SR_ARPCACHE_H

#include <inttypes.h>
#include <time.h>
#include <pthread.h>
#include "sr_if.h"

#define SR_ARPCACHE_SZ    100  
#define SR_ARPCACHE_TO    15.0

/* Cấu trúc packet đang đợi nhận ARP reply để lấy MAC rồi gửi frame tới next-top */
struct sr_packet {
    uint8_t *buf;               /* A raw Ethernet frame, presumably with the dest MAC empty */
    unsigned int len;           /* Length of raw Ethernet frame */
    char *iface;                /* The outgoing interface */
    struct sr_packet *next;
};

/* Cấu trúc cho 1 ARP request đang đợi phản hồi */
struct sr_arpreq {
    uint32_t ip;
    time_t sent;                /* Last time this ARP request was sent. You 
                                   should update this. If the ARP request was 
                                   never sent, will be 0. */
    uint32_t times_sent;        /* Number of times this request was sent. You 
                                   should update this. */
    struct sr_packet *packets;  /* List of pkts waiting on this req to finish */
    struct sr_arpreq *next;
};

/* Cấu trúc 1 entry ánh xạ IP-MAC trong ARP cache */
struct sr_arpentry {
    unsigned char mac[6]; 
    uint32_t ip;                /* IP addr in network byte order */
    time_t added;         
    int valid;
};

/* Cấu trúc cho toàn bộ ARP cache và ARP request queue */
struct sr_arpcache {
    struct sr_arpentry entries[SR_ARPCACHE_SZ];
    struct sr_arpreq *requests;
    pthread_mutex_t lock; /* ARP cache là vùng dữ liệu dùng chung của cac thread nên phải dùng khóa để ngăn chặn nhiều thread cùng truy cập, tránh xung đột dữ liệu */
    pthread_mutexattr_t attr; 
};

/* Nếu packet cần forward tới next-hop, gọi sr_arpcache_lookup() để tra cứu IP trong ARP cache (lấy MAC để forward) */
struct sr_arpentry *sr_arpcache_lookup(struct sr_arpcache *cache, uint32_t ip);

/* Nếu packet có IP không được tìm thấy trong ARP cache, gọi sr_arpcache_queuereq() để packet được thêm vào ARP request queue */
struct sr_arpreq *sr_arpcache_queuereq(struct sr_arpcache *cache,
                         uint32_t ip,
                         uint8_t *packet,               /* borrowed */
                         unsigned int packet_len,
                         char *iface);

struct sr_arpreq *sr_arpcache_insert(struct sr_arpcache *cache,
                            unsigned char *mac,
                            uint32_t ip);                         
/* Thiếu hàm gửi ARP request

 Sau khi nhận được ARP reply (có MAC mong muốn), gọi sr_arpcache_insert() để:
  - Gỡ ARP request khỏi queue
  - Lưu IP-MAC vào ARP cache
  - Trả về req đề gửi các packet bị trì hoãn trước đó chứ không free ngay (free sau)
struct sr_arpreq *sr_arpcache_insert(struct sr_arpcache *cache,
                                     unsigned char *mac,
                                     uint32_t ip);

Frees all memory associated with this arp request entry. If this arp request
entry is on the arp request queue, it is removed from the queue. */
void sr_arpreq_destroy(struct sr_arpcache *cache, struct sr_arpreq *entry);

/* Prints out the ARP table. */
void sr_arpcache_dump(struct sr_arpcache *cache);

/* You shouldn't have to call these methods--they're already called in the
   starter code for you. The init call is a constructor, the destroy call is
   a destructor, and a cleanup thread times out cache entries every 15
   seconds. */

int   sr_arpcache_init(struct sr_arpcache *cache);
int   sr_arpcache_destroy(struct sr_arpcache *cache);
void *sr_arpcache_timeout(void *cache_ptr);

#endif
