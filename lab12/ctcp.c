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
  linked_list_t *sent_segments;  /* Linked list of segments sent to this connection.
                                    It may be useful to have multiple linked lists
                                    for unacknowledged segments, segments that
                                    haven't been sent, etc. Lab 1 uses the
                                    stop-and-wait protocol and therefore does not
                                    necessarily need a linked list. You may remove
                                    this if this is the case for you */
    
  /* FIXME: Add other needed fields. */
  linked_list_t *recv_segments; /* Các segment nhận được */
  uint32_t seqno; /* seqno sẽ gửi */
  uint32_t ackno; /* ackno mong nhận được */
  uint16_t status; /* status hiện tại */
  int byte_sent; /* Số byte đã gửi đi cho host khác chưa ACK */
  int byte_recv; /* Số byte nhận được chưa đẩy ra stdout */
  char buf_sent[MAX_SEG_DATA_SIZE]; // Buffer để lưu trữ dữ liệu input
  uint16_t recv_window; /* receive window size  (MAX_SEG_DATA_SIZE) */
  uint16_t sent_window; /* Kích thước swnd (MAX_SEG_DATA_SIZE) */
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
  /* FIXME: Do any other initialization here. */

}

void ctcp_destroy(ctcp_state_t *state) {
  /* Update linked list. */
  if (state->next)
  state->next->prev = state->prev;
    
  *state->prev = state->next;
  conn_remove(state->conn);
    
  /* FIXME: Do any other cleanup here. */

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

}

/* Xử lý FIN segment nhận được */
void fin_seg_handle(ctcp_state_t *state, ctcp_segment_t *segment) {

}

/* Hàm xử lý ACK segment nhận được */
void ack_seg_handle(ctcp_state_t *state, ctcp_segment_t *segment) {

}

/* Hàm xử lý khi nhận DATA segment */
void data_seg_handle(ctcp_state_t *state, ctcp_segment_t *segment) {

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

