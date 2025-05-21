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

/* define status in TCP */
#define WAIT_INPUT      0x001 // Send DATA segment => BLOCK_FOR_ACK
#define BLOCK_FOR_ACK	  0x002 // Receive ACK segment => WAIT_INPUT or CLOSE_WAIT
#define FIN_WAIT_1      0x004 // Receive ACK segment => FIN_WAIT_2
#define FIN_WAIT_2      0x008 // Receive FIN segment => TIME_WAIT
#define TIME_WAIT       0x010 // timeout => CLOSED
#define CLOSE_WAIT      0x020 // Send FIN segment => LAST_ACK
#define LAST_ACK        0x040 // Receive ACK segment => CLOSED
#define CLOSING         0x080 // Receive ACK segment => TIME_WAIT
#define WAIT_SEND_FIN	  0x100 // Receive ACK segment and send FIN segment => FIN_WAIT_2 or CLOSED


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
  linked_list_t *sent_segments;  /* LL lưu các FIN, DATA segment đang đợi ACK */
    
  /* FIXME: Add other needed fields. */
  linked_list_t *recv_segments; /* LL lưu các DATA segment đang đợi đẩy ra output */
  uint32_t seqno; /* seqno sẽ gửi */
  uint32_t ackno; /* ackno mong nhận được */
  uint16_t status; /* status hiện tại */
  int byte_sent; /* Số byte đã gửi đi cho host khác chưa ACK */
  int byte_recv; /* Số byte nhận được chưa đẩy ra stdout */
  char buf_sent[MAX_SEG_DATA_SIZE]; // Buffer để lưu trữ dữ liệu input
  uint16_t recv_window; /* receive window size  (cfg) */
  uint16_t sent_window; /* Kích thước swnd (cfg) */
  int rt_timeout; /* retransmission timeout,in ms */
  struct timeval start_send_time; /* Thời gian bắt đầu gửi */
  int retrans_count;  /* Số lần gửi lại của 1 segment*/
  bool fin_recv_first; /* FIN segment đầu tiên nhận được*/
  bool first_seg; /* Segment đầu tiên (cả nhận cả gửi) */
};

/**
* Linked list of connection states. Go through this in ctcp_timer() to
* resubmit segments and tear down connections.
*/
static ctcp_state_t *state_list;

/* FIXME: Feel free to add as many helper functions as needed. Don't repeat
code! Helper functions make the code clearer and cleaner. */

void create_segment_and_send(ctcp_state_t *state, char * buffer, uint16_t buf_len, uint32_t flags, uint32_t ack_num);
int is_corrupted_seg(ctcp_segment_t *segment, size_t len);

void fin_seg_handle(ctcp_state_t *state, ctcp_segment_t *segment);
void data_seg_handle(ctcp_state_t *state, ctcp_segment_t *segment);
void ack_seg_handle(ctcp_state_t *state, ctcp_segment_t *segment);

uint32_t get_time_from_last_trans(ctcp_state_t *state);
void retransmission_handle(ctcp_state_t *state);

ctcp_state_t *ctcp_init(conn_t *conn, ctcp_config_t *cfg) {
  /* Connection could not be established. */
  if (!conn) {
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
  state->sent_segments = ll_create(); // Tạo 1 new LL chứa các segment đã gửi nhưng chưa ACK
  state->recv_segments = ll_create(); // Tạo tương tự 1 new LL cho các segment đã nhận
  state->seqno = 1;
  state->ackno = 1;
  state->status = WAIT_INPUT; // Bởi vì coi như 3-way handshake tự được xử lý, mình chỉ cần handle data transfer và 4-way handshake
  state->byte_sent = 0;
  state->byte_recv = 0;
  memcpy(state->buf_sent, 0, MAX_SEG_DATA_SIZE);
  state->recv_window = cfg->recv_window; 
  state->sent_window = cfg->send_window;
  state->rt_timeout = cfg->rt_timeout;

  state->retrans_count = 0;
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
  /* GIải phóng các segment gửi */
  ll_node_t *sent_node = ll_front(state->sent_segments); 
  while (sent_node) {
    free(ll_remove(state->sent_segments, tmp_node));
  }

  /* Giải phóng các segment nhận */
  ll_node_t *recv_node = ll_front(state->recv_segments);
  while (recv_node) {
    free(ll_remove(state->recv_segments, recv_node));
  }

  /* Giải phóng state */
  free(state);
}

void ctcp_read(ctcp_state_t *state) {

}

void ctcp_receive(ctcp_state_t *state, ctcp_segment_t *segment, size_t len) {

}


void ctcp_output(ctcp_state_t *state) {

}

void ctcp_timer() {

}

/* Hàm tạo segment và gửi sang bên khác */
void create_segment_and_send(ctcp_state_t *state, char *buffer, uint16_t buf_len, uint32_t flags, uint32_t ack_num) {
  uint16_t seg_len = sizeof(ctcp_segment_t) + buf_len;
  ctcp_segment_t *segment = calloc(1, seg_len);
  segment->seqno = htonl(state->seqno);
  segment->ackno = htonl(ack_num);
  segment->len = htons(seg_len);
  segment->flags = htonl(flags);
  segment->window = htons(state->sent_window);
  segment->cksum = 0;

  // Gửi DATA segment
  if (buf_len > 0) {
    memcpy(segment->data, buffer, buf_len);
    state->seqno += buf_len;
    ll_add(state->sent_segments, segment);
  } else if (flags == FIN) { // Gửi FIN segment
    state->seqno++;
    ll_add(state->sent_segments, segment);
  }
  
  // Tính lại cksum và gửi đi (sử dụng chung cho cả 3 loại segment: data, fin, ack)
  segment->cksum = cksum(segment, seg_len);
  conn_send(state->conn, segment, seg_len);

  if ((buf_len == 0) && (flags == ACK)) free(segment);
}

/* Xử lý FIN segment nhận được */
void fin_seg_handle(ctcp_state_t *state, ctcp_segment_t *segment) {

  // Tăng ack và gửi đi
  uint32_t ack_num = ntohl(segment->seqno) + 1;
  create_segment_and_send(state, NULL, 0, ACK, ack_num);

  // Kiểm tra FIN segment nhận được có đúng segment đang chờ không
  if (state->ackno == ntohl(segment->seqno)) {
    state->ackno = ack_num;
  }
  
  // Thay đổi status
  if (state->status == FIN_WAIT_2) {
    state->status = TIME_WAIT;
    // Chèn thêm timer function vào đây
    ctcp_destroy(state);
  } else if (state->status == FIN_WAIT_1) {
    state->status = CLOSING;
  } else if (state->status == WAIT_INPUT) {
    state->status = CLOSE_WAIT;
    state->fin_recv_first = true;
  }
}

/* Hàm xử lý ACK segment nhận được */
void ack_seg_handle(ctcp_state_t *state, ctcp_segment_t *segment) {
  
}

/* Hàm xử lý khi nhận DATA segment */
void data_seg_handle(ctcp_state_t *state, ctcp_segment_t *segment) {
  uint16_t data_len = ntohs(segment->len) - sizeof(ctcp_segment_t);
  uint32_t ack_num = ntohl(segment->seqno) + data_len

  // Segment tới hợp lệ (in-order)
  if (state->ackno == ntohl(segment->seqno)) {
    state->ackno = ack_num;
    state->byte_recv += data_len;
    create_segment_and_send(state, NULL, data_len, ACK, ack_num);
    
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

/* Hàm kiểm tra checksum của segment nhận được có đúng không */
int is_corrupted_seg(ctcp_segment_t *segment, size_t len) {  

}

/* Hàm lấy thời gian từ lần cuối gửi segment cho tới hiện tại */
uint32_t get_time_from_last_trans(ctcp_state_t *state) {

}

/* Hàm retransmit segment khi timeout */
void retransmission_handle(ctcp_state_t *state) {

}

