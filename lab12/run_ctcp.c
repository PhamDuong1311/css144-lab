/******************************************************************************
* ctcp.c
* ------
* Implementation of cTCP done here. This is the only file you need to change.
* Look at the following files for references and useful functions:
*   - ctcp.h: Headers for this file.
*   - ctcp_iinked_list.h: Linked list functions for managing a linked list.
*   - ctcp_sys.h: Connection-related structs and functions, cTCP segment
*                 definition.
*   - ctcp_utils.h: Checksum computation, getting the current time..
*
*****************************************************************************/

/*
* Segment length (byte)= Header(20) + Payload(data + 1)
*/

#include "ctcp.h"
#include "ctcp_linked_list.h"
#include "ctcp_sys.h"
#include "ctcp_utils.h"

/* define status in TCP, slide cs144 */
#define WAIT_INPUT      0x001 // Send DATA segment => BLOCK_FOR_ACK
#define BLOCK_FOR_ACK	  0x002 // Receive ACK segment => WAIT_INPUT or CLOSE_WAIT
#define FIN_WAIT_1      0x004 // Receive ACK segment => FIN_WAIT_2
#define FIN_WAIT_2      0x008 // Receive FIN segment => TIME_WAIT
#define TIME_WAIT       0x010 // timeout => CLOSED
#define CLOSE_WAIT      0x020 // Send FIN segment => LAST_ACK
#define LAST_ACK        0x040 // Receive ACK segment => CLOSED
#define CLOSING         0x080 // Receive ACK segment => TIME_WAIT


/**
* Connection state.
*
* Stores per-connection information such as the current sequence number,
* unacknowledged packets, etc..
*
* You should add to this to store other fields you might need.
*/
struct ctcp_state {
  struct ctcp_state *next;  /* Next in linked list */
  struct ctcp_state **prev; /* Prev in linked list */
    
  conn_t *conn;             /* Connection object -- needed in order to figure
                              out destination when sending */
  linked_list_t *sent_segments;  /* Linked list of segments sent to this connection.
                                    It may be useful to have multiple linked lists
                                    for unacknowledged segments, segments that
                                    haven't been sent, etc. Lab 1 uses the
                                    stop-and-wait protocol and therefore does not
                                    necessarily need a linked list. You may remove
                                    this if this is the case for you */
    
  /* FIXME: Add other needed fields. */
  linked_list_t *recv_segments;
  uint32_t seqno; /* sequence number */
  uint32_t ackno; /* acknowledgement number */
  uint16_t status; /* status when connect */
  int byte_sent; /* Số byte đã gửi đi cho host khác chưa ACK */
  int byte_recv;
  char buf_sent[MAX_SEG_DATA_SIZE]; // Buffer để lưu trữ dữ liệu input
  uint16_t recv_window; /* receive window size  (MAX_SEG_DATA_SIZE) */
  uint16_t sent_window;
  int rt_timeout; /* retransmission timeout,in ms */
  struct timeval start_send_time;
  int retrans_count;
  bool fin_recv_first;
  bool first_seg;
};

/**
* Linked list of connection states. Go through this in ctcp_timer() to
* resubmit segments and tear down connections.
*/
static ctcp_state_t *state_list;

/* FIXME: Feel free to add as many helper functions as needed. Don't repeat
code! Helper functions make the code clearer and cleaner. */


/**
* function creates segment and send with according flag
* FIN, ACK , 0 (data)
**/
void create_segment_and_send(ctcp_state_t *state, char * buffer, uint16_t buf_len, uint32_t flags, uint32_t ack_num);

/* funtion using checksum to check whether segment is corrupted
* return 1 if corrupt, 0 otherwise */
int is_corrupted_seg(ctcp_segment_t *segment, size_t len);

/* functions handle fin, ack & data segment */
void fin_seg_handle(ctcp_state_t *state, ctcp_segment_t *segment);
void data_seg_handle(ctcp_state_t *state, ctcp_segment_t *segment);
void ack_seg_handle(ctcp_state_t *state, ctcp_segment_t *segment);

/* function calculate time from lastest state sent segment*/
uint32_t get_time_from_last_trans(ctcp_state_t *state);

/* funtion handle retransmission */
void retransmission_handle(ctcp_state_t *state);

ctcp_state_t *ctcp_init(conn_t *conn, ctcp_config_t *cfg) {
  /* Connection could not be established. */
  if (conn == NULL) {
    return NULL;
  }
    
  /* Established a connection. Create a new state and update the linked list
  of connection states. */
  ctcp_state_t *state = calloc(1, sizeof(ctcp_state_t));
  state->next = state_list;
  state->prev = &state_list;
  if (state_list)
  state_list->prev = &state->next;
  state_list = state;
    
  /* Set fields. */
  state->conn = conn;
  /* FIXME: Do any other initialization here. */
  state->seqno = 1;
  state->ackno = 1;
  state->status = WAIT_INPUT;
  state->byte_sent = 0; 
  state->byte_recv = 0;
  memset(state->buf_sent, 0, MAX_SEG_DATA_SIZE);
  state->recv_window = cfg->recv_window;
  state->sent_window = cfg->send_window;
  state->rt_timeout = cfg->rt_timeout;
  state->retrans_count = 0;
    
  state->sent_segments = ll_create();
  state->recv_segments = ll_create();
  state->fin_recv_first = false;
  state->first_seg = true;

  free(cfg);
    
    
  return state;
}

void ctcp_destroy(ctcp_state_t *state) {
  /* Update linked list. */
  if (state->next)
  state->next->prev = state->prev;
    
  *state->prev = state->next;
  conn_remove(state->conn);
    
  /* FIXME: Do any other cleanup here. */
  ll_node_t *tmp_node = NULL;
  while ((tmp_node = ll_front(state->sent_segments)))
    free(ll_remove(state->sent_segments, tmp_node));
    
  tmp_node = NULL;
  while (NULL != (tmp_node = ll_front(state->recv_segments)))
    free(ll_remove(state->recv_segments, tmp_node));
    
  free(state);
  end_client();
}

void ctcp_read(ctcp_state_t *state) {
  if (!state) return;

  if (state->status & (BLOCK_FOR_ACK | FIN_WAIT_1 | FIN_WAIT_2 | LAST_ACK | CLOSING)) return;

  uint16_t bytes_left = state->sent_window - state->byte_sent;
  if (bytes_left <= 0) {
    state->status = BLOCK_FOR_ACK;
    return;
  }
    
  int max_byte = bytes_left < MAX_SEG_DATA_SIZE ? bytes_left : MAX_SEG_DATA_SIZE;

  int byte_read = conn_input(state->conn, state->buf_sent, max_byte);
  if (byte_read < 0) {
    if (state->status == CLOSE_WAIT) {
      state->status = LAST_ACK;
      create_segment_and_send(state, NULL, 0, FIN, state->ackno);
      state->byte_sent++;
      return;
    }
  
    if (ll_length(state->sent_segments) == 0) {
      state->status = FIN_WAIT_1;
      create_segment_and_send(state, NULL, 0, FIN, state->ackno);
      state->byte_sent++; 
      return;
    } 
  } else if (byte_read > 0) { 
    create_segment_and_send(state, state->buf_sent, byte_read, 0, state->ackno);
    state->byte_sent += byte_read;
  }
  memset(state->buf_sent, 0, MAX_SEG_DATA_SIZE);
}

void ctcp_receive(ctcp_state_t *state, ctcp_segment_t *segment, size_t len) {
  if (!state || !segment) return;
  
  int check = is_corrupted_seg(segment, len);
  if (check) {
    free(segment);
    return;
  }

  uint32_t flags = segment->flags;
    
  if (flags & TH_FIN) {
    fin_seg_handle(state, segment);
  } else if (flags & TH_ACK) {
    ack_seg_handle(state, segment);    
    // piggybacked ack
    if (ntohs(segment->len) > sizeof(ctcp_segment_t)) {
      data_seg_handle(state, segment);
    }
  } else if (flags == 0) {
    data_seg_handle(state, segment);
  }
  free(segment);
}


void ctcp_output(ctcp_state_t *state) {
  if (!state) return;
    
  ll_node_t *browse_node = ll_front(state->recv_segments);
  if (!browse_node) return;
    
  ctcp_segment_t *browse_seg = NULL;
  uint16_t data_seg_len = 0;
    
  while (browse_node) {
    browse_seg = (ctcp_segment_t *)(browse_node->object);
    if (ntohl(browse_seg->seqno) == state->ackno) {
      data_seg_len = ntohs(browse_seg->len) - sizeof(ctcp_segment_t);
            
      size_t buf_space = conn_bufspace(state->conn);
      size_t val_can_output = (data_seg_len < buf_space) ? data_seg_len : buf_space;
      if (val_can_output == conn_output(state->conn, browse_seg->data, val_can_output)) {
        state->byte_recv -= data_seg_len; 
        state->ackno += data_seg_len; 
        free(ll_remove(state->recv_segments, browse_node)); 
        browse_node = ll_front(state->recv_segments); 
      }
    } else browse_node = browse_node->next;
  }
}

void ctcp_timer() {
  ctcp_state_t *state = state_list; 
  while (state) {
    if (ll_length(state->sent_segments))
      retransmission_handle(state);
    state = state->next;
  }
}

/* Hàm tạo segment và gửi sang bên khác */
void create_segment_and_send(ctcp_state_t *state, char *buffer, uint16_t buf_len, uint32_t flags, uint32_t ack_num) {
  if (state->first_seg == true) {
      state->first_seg = false;
      flags |= ACK;
    }
  
  uint16_t seg_len;
  seg_len = sizeof(ctcp_segment_t) + buf_len;

  ctcp_segment_t *segment = calloc(1, seg_len);
  segment->seqno = htonl(state->seqno);
  segment->ackno = htonl(ack_num);
  segment->len = htons(seg_len);
  segment->flags = htonl(flags);
  segment->window = htons(state->sent_window);
  segment->cksum = 0;
    
  if (buf_len > 0) {
    memcpy(segment->data, buffer, buf_len);
    state->seqno += buf_len;
    ll_add(state->sent_segments, segment);
  } 

  if (flags & FIN) { 
    state->seqno++;
    ll_add(state->sent_segments, segment);
  } 
  segment->cksum = cksum(segment, seg_len);
  conn_send(state->conn, segment, seg_len);

  if ((flags & ACK) && (buf_len == 0)) free(segment); 
}

/* Xử lý FIN segment nhận được */
void fin_seg_handle(ctcp_state_t *state, ctcp_segment_t *segment) {
  uint32_t ack_num = ntohl(segment->seqno) + 1;
  create_segment_and_send(state, NULL, 0, ACK, ack_num);
  conn_output(state->conn, NULL, 0);

  if (state->ackno == ntohl(segment->seqno)) {
    state->ackno = ack_num;
  }
    

  if (state->status & FIN_WAIT_2) {
    state->status = TIME_WAIT;
    ctcp_destroy(state);
  }

  if (state->status & FIN_WAIT_1) {
    state->status = CLOSING;
  }

  if (state->status & WAIT_INPUT) {
    state->fin_recv_first = true;
    state->status = CLOSE_WAIT;
  }

}

/* Hàm xử lý ACK segment nhận được */
void ack_seg_handle(ctcp_state_t *state, ctcp_segment_t *segment) {
  if (!state || !segment || !state->sent_segments->head) return;
  
  ll_node_t *browse_node = state->sent_segments->head;
  ctcp_segment_t *browse_seg = NULL;
  uint16_t seg_data_len;

  while (browse_node) {
    browse_seg = (ctcp_segment_t *)(browse_node->object);
    seg_data_len = ntohs(browse_seg->len) - sizeof(ctcp_segment_t);
    if (browse_seg->flags & TH_FIN) seg_data_len = 1;

    if (ntohl(segment->ackno) == (ntohl(browse_seg->seqno) + seg_data_len)) {
      state->byte_sent -= seg_data_len;
      free(ll_remove(state->sent_segments, browse_node));
      state->retrans_count = 0;
          
      /* Thay đổi trạng thái */ 
      if (ll_length(state->sent_segments) == 0) {
        if (state->status == BLOCK_FOR_ACK) {
          if (state->fin_recv_first == true) state->status = CLOSE_WAIT;
          else state->status = WAIT_INPUT;
        } else if (state->status == FIN_WAIT_1) { 
          state->status = FIN_WAIT_2;
        } else if (state->status == CLOSING) { 
          state->status = TIME_WAIT;
          ctcp_destroy(state);
        } else if (state->status == LAST_ACK) {           
          ctcp_destroy(state);
        }
      } else if (state->sent_window > state->byte_sent) { 
        if (state->fin_recv_first == true) state->status = CLOSE_WAIT;
        else state->status = WAIT_INPUT;
      }
      return;
    }
    browse_node = browse_node->next;
  }

}

/* Hàm xử lý khi nhận DATA segment */
void data_seg_handle(ctcp_state_t *state, ctcp_segment_t *segment) {
  uint16_t data_len = ntohs(segment->len) - sizeof(ctcp_segment_t);
  uint32_t ack_num = ntohl(segment->seqno) + data_len;

  // Segment tới hợp lệ (in-order)
  if (state->ackno == ntohl(segment->seqno)) {
    state->byte_recv += data_len;
    create_segment_and_send(state, NULL, 0, ACK, ack_num);
    
    ctcp_segment_t *copy_segment = calloc(1, ntohs(segment->len));
    memcpy(copy_segment, segment, ntohs(segment->len));
    ll_add(state->recv_segments, copy_segment);
    ctcp_output(state);
  } else { // Trường hợp out-of-order
    /* Các vấn đề xảy ra trong quá trình nhận Data transfer*/
    // 1. Segment bắt đầu đúng chỗ (seqno hợp lệ) nhưng data trong segment quá dài => tràn recv_window
    if ((data_len + state->byte_recv) > state->recv_window) return;

    // 2. Segment bắt đầu sai chỗ (seqno hợp lệ chỉ nhận từ seqno thuộc [ackno, ackno + recv_window -1])
    if (ntohl(segment->seqno) >= (state->ackno + state->recv_window)) return;

    // 3. Segment trùng lặp (Đã gửi ACK cho Sender nhưng Sender không nhận được)
    if (state->ackno >= ack_num) return;

    // 4. Segment trùng lặp (Chưa gửi ACK cho Sender vì segment nằm trong buffer - không đến đúng thứ tự)
    if (ll_length(state->recv_segments)) {
      ll_node_t *check_node = ll_front(state->recv_segments);
      while (check_node) {
        ctcp_segment_t *check_seg = (ctcp_segment_t *)check_node->object; 
        if (check_seg->seqno == segment->seqno) return;
        check_node = check_node->next;
      }
    }

    state->byte_recv += data_len;
    create_segment_and_send(state, NULL, data_len, ACK, ack_num);

    ctcp_segment_t *copy_segment = calloc(1, ntohs(segment->len));
    memcpy(copy_segment, segment, ntohs(segment->len));
    ll_add(state->recv_segments, copy_segment);
  }

}

int is_corrupted_seg(ctcp_segment_t *segment, size_t len) {  
  if (!segment) return 1;
  if (ntohs(segment->len) != len) return 1;
  uint16_t computed_cksum = segment->cksum;
  uint16_t cksum_test;
  segment->cksum = 0;
  cksum_test = cksum(segment, ntohs(segment->len));
  return (cksum_test == computed_cksum ? 0 : 1);
}

/* Hàm lấy thời gian từ lần cuối gửi segment cho tới hiện tại */
uint32_t get_time_from_last_trans(ctcp_state_t *state) {
  if (!state) return -1;
  uint32_t time_interval =  (long)current_time() - ((uint32_t)state->start_send_time.tv_sec * 1000 + (uint32_t)state->start_send_time.tv_usec / 1000);
  return time_interval;
}

/* Hàm retransmit segment khi timeout */
void retransmission_handle(ctcp_state_t *state) {
  if (!state) return;
  ll_node_t *browse_node = state->sent_segments->head;
  uint32_t time_get = get_time_from_last_trans(state);
        
  if (browse_node) {
    ctcp_segment_t *segment = (ctcp_segment_t *)(browse_node->object);
    if (time_get >= state->rt_timeout) {
      if (state->retrans_count > 5) {
        free(ll_remove(state->sent_segments, browse_node));
        return;
      } else {
        conn_send(state->conn, segment, ntohs(segment->len));
        state->retrans_count++;
      }
    }
  }
  gettimeofday(&(state->start_send_time), NULL);
}
