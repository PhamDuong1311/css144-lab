
#include <signal.h>
#include <assert.h>
#include "sr_nat.h"
#include <unistd.h>

int sr_nat_init(struct sr_instance* sr, struct sr_nat *nat) { /* Initializes the nat */

  assert(nat);

  /* Acquire mutex lock */
  pthread_mutexattr_init(&(nat->attr));
  pthread_mutexattr_settype(&(nat->attr), PTHREAD_MUTEX_RECURSIVE);
  int success = pthread_mutex_init(&(nat->lock), &(nat->attr));

  /* Initialize timeout thread */

  pthread_attr_init(&(nat->thread_attr));
  pthread_attr_setdetachstate(&(nat->thread_attr), PTHREAD_CREATE_JOINABLE);
  pthread_attr_setscope(&(nat->thread_attr), PTHREAD_SCOPE_SYSTEM);
  pthread_attr_setscope(&(nat->thread_attr), PTHREAD_SCOPE_SYSTEM);
  pthread_create(&(nat->thread), &(nat->thread_attr), sr_nat_timeout, nat);

  /* CAREFUL MODIFYING CODE ABOVE THIS LINE! */

  nat->mappings = NULL;
  /* Initialize any variables here */
  struct sr_if* int_eth_info = sr_get_interface(sr, "sw0-eth1");
  struct sr_if* ext_eth_info = sr_get_interface(sr, "sw0-eth2");
  if (!int_eth_info || !ext_eth_info) {
    pthread_mutex_destroy(&(nat->lock));
    pthread_mutexattr_destroy(&(nat->attr));
    return NULL;
  }
  nat->int_eth = int_eth_info->ip;
  nat->ext_eth = ext_eth_info->ip;

  nat->id_incre = 0;
  nat->port_incre = 1024;

  return success;
}


int sr_nat_destroy(struct sr_nat *nat) {  /* Destroys the nat (free memory) */

  pthread_mutex_lock(&(nat->lock));

  /* free nat memory here */
  struct sr_nat_mapping* current_mapping = nat->mappings;
  while (current_mapping) {
    struct sr_nat_mapping* next_mapping = current_mapping->next;
    if (current_mapping->type == nat_mapping_tcp) {
      struct sr_nat_connection* current_conn = current_mapping->conns;
      while(current_conn) {
        struct sr_nat_connection* next_conn = current_conn->next;
        free(current_conn);
        current_conn = next_conn;
      }
    }
    free(current_mapping);
    current_mapping = next_mapping;
  }
  free(nat->mappings);

  pthread_kill(nat->thread, SIGKILL);
  return pthread_mutex_destroy(&(nat->lock)) &&
    pthread_mutexattr_destroy(&(nat->attr));

}

void *sr_nat_timeout(void *nat_ptr) {  /* Periodic Timout handling */
  struct sr_nat *nat = (struct sr_nat *)nat_ptr;
  while (1) {
    sleep(1.0);
    pthread_mutex_lock(&(nat->lock));

    time_t curtime = time(NULL);

    /* handle periodic tasks here */

    pthread_mutex_unlock(&(nat->lock));
  }
  return NULL;
}

/* Get the mapping associated with given external port.
   You must free the returned structure if it is not NULL. */
struct sr_nat_mapping *sr_nat_lookup_external(struct sr_nat *nat,
    uint16_t aux_ext, sr_nat_mapping_type type ) {

  pthread_mutex_lock(&(nat->lock));

  /* handle lookup here, malloc and assign to copy */
  struct sr_nat_mapping *copy = NULL;
  struct sr_nat_mapping *nat_entry = nat->mappings;
  while (nat_entry) {
    if (nat_entry->aux_int == aux_ext && nat_entry->type == type) {
      copy = (struct sr_nat_mapping* )malloc(sizeof(struct sr_nat_mapping));
      if (!copy) {
        pthread_mutex_destroy(&(nat->lock));
        return NULL;
      }
      memcpy(copy, nat_entry, sizeof(struct sr_nat_mapping));
      copy->next = NULL;
      break;
    }
    nat_entry = nat_entry->next;
  }
  pthread_mutex_unlock(&(nat->lock));
  return copy;
}

/* Get the mapping associated with given internal (ip, port) pair.
   You must free the returned structure if it is not NULL. */
struct sr_nat_mapping *sr_nat_lookup_internal(struct sr_nat *nat,
  uint32_t ip_int, uint16_t aux_int, sr_nat_mapping_type type ) {

  pthread_mutex_lock(&(nat->lock));

  /* handle lookup here, malloc and assign to copy. */
  struct sr_nat_mapping *copy = NULL;
  struct sr_nat_mapping *nat_entry = nat->mappings;
  while (nat_entry) {
    if (nat_entry->ip_int == ip_int && nat_entry->aux_int == aux_int && nat_entry->type == type) {
      copy = (struct sr_nat_mapping* )malloc(sizeof(struct sr_nat_mapping));
      if (!copy) {
        pthread_mutex_destroy(&(nat->lock));
        return NULL;
      }
      memcpy(copy, nat_entry, sizeof(struct sr_nat_mapping));
      copy->next = NULL;
      break;
    }
    nat_entry = nat_entry->next;
  }

  pthread_mutex_unlock(&(nat->lock));
  return copy;
}

/* Insert a new mapping into the nat's mapping table.
   Actually returns a copy to the new mapping, for thread safety.
 */
struct sr_nat_mapping *sr_nat_insert_mapping(struct sr_nat *nat,
  uint32_t ip_int, uint16_t aux_int, sr_nat_mapping_type type ) {

  pthread_mutex_lock(&(nat->lock));

  /* handle insert here, create a mapping, and then return a copy of it */
  struct sr_nat_mapping *mapping = NULL;

  struct sr_nat_mapping *copy_mapping = (struct sr_nat_mapping* )malloc(sizeof(struct sr_nat_mapping));
  if (!copy_mapping) {
    pthread_mutex_destroy(&(nat->lock));
    return NULL;
  }

  mapping = sr_nat_lookup_internal(nat, ip_int, aux_int, type);
  if (mapping) {
    mapping->last_updated = time(NULL);
  } else {
    mapping->ip_int = ip_int;
    mapping->aux_int = aux_int;
    mapping->ip_ext = nat->ext_eth;
    mapping->last_updated = time(NULL);
    mapping->type = type;
    mapping->conns = NULL;
    
    if (type == nat_mapping_icmp) {
      mapping->aux_ext = (nat->id_incre)++;
    } else if (type == nat_mapping_tcp) {
      mapping->aux_ext = (nat->port_incre)++;
      if (nat->port_incre > 65535) {
        nat->port_incre = 1024;
      }
    }

    mapping->next = nat->mappings;
    nat->mappings = mapping;
  }

  /* Đây là kỹ thuật giúp tránh thay đổi node trong LL khi trả về, trả về 1 node copy mà không trỏ về đâu (next = NULL) */
  memcpy(copy_mapping, mapping, sizeof(struct sr_nat_mapping));
  copy_mapping->next = NULL;

  pthread_mutex_unlock(&(nat->lock));
  return copy_mapping;
}

struct sr_nat_connection* sr_nat_insert_connection(struct sr_nat_mapping* mapping, uint32_t ip_src, uint32_t ip_dst, uint16_t port_src, uint16_t port_dst) {
  struct sr_nat_connection* conn = NULL;
  struct sr_nat_connection* copy_conn = (struct sr_nat_connection* )malloc(sizeof(struct sr_nat_connection));
  conn = sr_nat_lookup_connection(mapping, ip_src, ip_dst, port_src, port_dst);
  if (conn) {
    conn->last_active = time(NULL);
  } else {
    struct sr_nat_connection* conn = (struct sr_nat_connection* )malloc(sizeof(struct sr_nat_connection));
    if (!conn) return NULL;

    conn->ip_src = ip_src;
    conn->ip_dst = ip_dst;
    conn->port_src = port_src;
    conn->port_dst = port_dst;
    conn->last_active = time(NULL);

    conn->next = mapping->conns;
    mapping->conns = conn;
  }

  memcpy(copy_conn, conn, sizeof(struct sr_nat_connection));
  copy_conn->next = NULL;
  return copy_conn;
}

struct sr_nat_connection* sr_nat_lookup_connection(struct sr_nat_mapping* mapping, uint32_t ip_src, uint32_t ip_dst, uint16_t port_src, uint16_t port_dst) {
  struct sr_nat_connection* conn = mapping->conns;
  while (conn) {
    if (conn->ip_src == ip_src && conn->ip_dst == ip_dst && conn->port_src == port_src && conn->port_dst = port_dst) {
      struct sr_nat_connection* copy_conn = (struct sr_nat_connection* )malloc(sizeof(struct sr_nat_connection));
      memcpy(copy_conn, conn, sizeof(struct sr_nat_connection));
      copy_conn->next = NULL;
      return copy_conn;
    }
    conn = conn->next;
  }

  return NULL;
}