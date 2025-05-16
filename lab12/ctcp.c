/******************************************************************************
 * ctcp.c
 * ------
 * Implementation of cTCP done here. This is the only file you need to change.
 * Look at the following files for references and useful functions:
 *   - ctcp.h: Headers for this file.
 *   - ctcp_iinked_list.h: Linked list functions for managing a linked list.
 *   - ctcp_sys.h: Connection-related structs and functions, cTCP segment
 *                 definition.
 *   - ctcp_utils.h: Checksum computation, getting the current time.
 *
 *****************************************************************************/

 #include "ctcp.h"
 #include "ctcp_linked_list.h"
 #include "ctcp_sys.h"
 #include "ctcp_utils.h"
 
  /* define status in TCP, slide cs144 */
  #define WAIT_INPUT      0x001 // Send DATA segment => BLOCK_FOR_ACK
  #define BLOCK_FOR_ACK	  0x002 // Receive ACK segment => WAIT_INPUT 
  #define FIN_WAIT_1      0x004 // Receive ACK segment => FIN_WAIT_2
  #define FIN_WAIT_2      0x008 // Receive FIN segment => TIME_WAIT
  #define TIME_WAIT       0x010 // timeout => CLOSED
  #define CLOSE_WAIT      0x020 // Send FIN segment => LAST_ACK
  #define LAST_ACK        0x040 // Receive ACK segment => CLOSED
  #define CLOSING         0x080 // Receive ACK segment => TIME_WAIT
  #define WAIT_SEND_FIN	  0x100 // Receive ACK segment and send FIN segment => FIN_WAIT_1
 
  
 /**
  * Connection state.
  *
  * Stores per-connection information such as the current sequence number,
  * unacknowledged packets, etc.
  */
 struct ctcp_state {
   struct ctcp_state *next;  /* Next in linked list */
   struct ctcp_state **prev; /* Prev in linked list */
 
   conn_t *conn;             /* Connection object */
   linked_list_t *sent_segments;  /* Linked list of segments sent to this connection */
   linked_list_t *recv_segments;
   long last_sent_time;      /* Time when unacked segment was last sent */
   int xmit_count;           /* Number of times segment has been transmitted */
   int rt_timeout;

   uint32_t next_seqno;      /* Next sequence number to use */
   uint32_t next_ackno;
   uint32_t expected_ackno;  /* Expected acknowledgment number */
   
   // Buffer received from other host before push to output (not received from input)
   char recv_buffer[MAX_SEG_DATA_SIZE];        /* Buffer for received data */
   size_t byte_recv;      /* Length of data in receive buffer */

   char sent_buffer[MAX_SEG_DATA_SIZE];
   size_t byte_sent;

   
   bool sent_fin;            /* Whether FIN has been sent */
   bool recv_fin;            /* Whether FIN has been received */
   bool input_eof;           /* Whether input has reached EOF */
   bool output_eof;          /* Whether output has reached EOF */

   uint16_t sent_window;
   uint16_t recv_window;
   uint16_t status;
 };
 
 /* Linked list of connection states */
 static ctcp_state_t *state_list = NULL;

 /* Helpder function declaration */
  static ctcp_segment_t* create_segment(ctcp_state_t *state, uint32_t flags, char *data, size_t len_data);
  static void send_segment(ctcp_state_t *state, ctcp_segment_t *seg, size_t len);

  static bool can_destroy(ctcp_state_t *state);

  void ack_seg_handle(ctcp_state_t *state, ctcp_segment_t *seg);
  void data_seg_handle(ctcp_state_t *state, ctcp_segment_t *seg);
  void fin_seg_handle(ctcp_state_t *state, ctcp_segment_t *seg);
 
  int is_correct_cksum(ctcp_segment_t *seg);

 ctcp_state_t *ctcp_init(conn_t *conn, ctcp_config_t *cfg) {
   if (conn == NULL) {
     return NULL;
   }
 
   ctcp_state_t *state = calloc(1, sizeof(ctcp_state_t));
   state->next = state_list;
   state->prev = &state_list;
   if (state_list)
     state_list->prev = &state->next;
   state_list = state;
 
   state->conn = conn;
   state->next_seqno = 1;  
   state->next_ackno = 1;
   state->expected_ackno = 1;
   state->status = WAIT_INPUT;

   state->last_sent_time = 0;
   state->xmit_count = 0;
   
   memset(state->recv_buffer, 0, MAX_SEG_DATA_SIZE);
   state->byte_recv = 0;
   memset(state->sent_buffer, 0, MAX_SEG_DATA_SIZE);
   state->byte_sent = 0;

   state->sent_window = cfg->send_window;
   state->recv_window = cfg->recv_window;
   state->rt_timeout = cfg->rt_timeout;

  state->sent_segments = ll_create();
  state->recv_segments = ll_create();

  state->sent_fin = false;        
  state->recv_fin = false;            
  state->input_eof = false;           
  state->output_eof = false;         
   
  free(cfg);
   
   return state;
 }
 
 void ctcp_destroy(ctcp_state_t *state) {
   if (state->next)
     state->next->prev = state->prev;
   *state->prev = state->next;
 
   if (state->unacked_seg) {
     free(state->unacked_seg);
   }
   
   ll_node_t *node = NULL;
   while (node == ll_front(state->segments)) {
     ctcp_segment_t *seg = ll_remove(state->segments, node);
     free(seg);
   }
   ll_destroy(state->segments);
   
   free(state->recv_buffer);
   conn_remove(state->conn);
   free(state);
 }
 
 
 void ctcp_read(ctcp_state_t *state) {
  // Nếu đang ở status chờ nhận segment thì cho alex luôn
  if (state->status & (BLOCK_FOR_ACK | WAIT_SEND_FIN | FIN_WAIT_1 | FIN_WAIT_2 | LAST_ACK | CLOSING)) {
      return;
  }

  // Kiểm tra xem số byte còn lại có thể gửi
  int bytes_left = state->sent_window - state->byte_sent;
  if (bytes_left <= 0) {
    state->status = BLOCK_FOR_ACK;
    return;
  }
     
  int max_byte = bytes_left < MAX_SEG_DATA_SIZE ? bytes_left : MAX_SEG_DATA_SIZE;

  int bytes_read = conn_input(state->conn, state->sent_buffer, max_byte);
  
  // Status là WAIT_INPUT
  if (bytes_read > 0) {
      ctcp_segment_t *data_seg = create_segment(state, 0, state->sent_buffer, bytes_read);
      send_segment(state, data_seg, sizeof(ctcp_segment_t) + bytes_read);
      state->status = BLOCK_FOR_ACK;
      
  } else if (bytes_read < 0) {      
      // Đóng kết nối có 2 status sẽ gửi FIN
      if (state->status & CLOSE_WAIT) {
        // Gửi FIN số 2 trong connection
        ctcp_segment_t *fin_seg = create_segment(state, FIN, NULL, 0);
        send_segment(state, fin_seg, sizeof(ctcp_segment_t));
        state->status = LAST_ACK; 
        state->byte_sent++;
      } else if (state->unacked_seg != NULL) {   // Nếu có segment chưa được ACK, chờ trước khi gửi FIN
            state->status = WAIT_SEND_FIN;
            ctcp_segment_t *ack_seg = create_segment(state, FIN, NULL, 0);
            send_segment(state, ack_seg, sizeof(ctcp_segment_t));
            state->byte_sent++;
      } else {
          // Gửi FIN số 1 trong connection
          ctcp_segment_t *fin_seg = create_segment(state, FIN, NULL, 0);
          send_segment(state, fin_seg, sizeof(ctcp_segment_t));
          state->status = FIN_WAIT_1;
          state->byte_recv++;

      }
      // Kiểm tra nếu có thể đóng kết nối ngay
      if (can_destroy(state)) {
          ctcp_destroy(state);
      }
  } else if (bytes_read == 0) {
      // Không có dữ liệu, chuyển sang chờ dữ liệu đầu vào
      state->status = WAIT_INPUT;
  }
  memset(state->sent_buffer, 0, MAX_SEG_DATA_SIZE);
}
 


 void ctcp_receive(ctcp_state_t *state, ctcp_segment_t *segment, size_t len) {
   // Convert field to host order
   uint32_t flags = ntohl(segment->flags);
   fprintf(stderr, "[DEBUG] Received segment with flags: 0x%X\n", flags);
   if (!is_correct_cksum(segment)) {
     free(segment);
     return;
   }
   if (flags & ACK) {
     ack_seg_handle(state, segment);
     if (ntohl(segment->len) > sizeof(ctcp_segment_t)) {
     data_seg_handle(state, segment);
   }
   } else if (flags & FIN) {
     fin_seg_handle(state, segment);
   } else if (flags == 0) {
     data_seg_handle(state, segment);
   }
   free(segment);
 }
 
 void ctcp_output(ctcp_state_t *state) {
   if (state->byte_recv == 0) {
     return;
   }
   
   size_t buf_space = conn_bufspace(state->conn);
   if (buf_space == 0) {
     return;
   }
   
   size_t to_output = (state->byte_recv < buf_space) ? 
                      state->byte_recv : buf_space;
   
   int bytes_written = conn_output(state->conn, state->recv_buffer, to_output);
   if (bytes_written > 0) {
     // Remove outputted data from buffer
     memmove(state->recv_buffer, state->recv_buffer + bytes_written, 
             state->byte_recv - bytes_written);
     state->byte_recv -= bytes_written;
     
     if (state->recv_fin && state->byte_recv == 0) {
       state->output_eof = true;
       if (can_destroy(state)) {
         ctcp_destroy(state);
       }
     }
   } else if (bytes_written == -1) {
     state->output_eof = true;
     if (can_destroy(state)) {
       ctcp_destroy(state);
     }
   }
 }
 
 void ctcp_timer() {

 }


 /* Helper function to create a new segment */
 static ctcp_segment_t* create_segment(ctcp_state_t *state, uint32_t flags, char *data, size_t len_data) {
   size_t seg_len = sizeof(ctcp_segment_t) + len_data;
   ctcp_segment_t *seg = calloc(1, seg_len);
   
   seg->seqno = htonl(state->next_seqno);
   seg->ackno = htonl(state->next_ackno);
   seg->len = htons(seg_len);
   seg->flags = htonl(flags);
   seg->window = htons(state->sent_window);
   seg->cksum = 0;
   
   // Khi tạo segment để gửi đi thì chỉ có FIN, DATA segment được lưu vào LL để chờ ACK segment
   if (len_data > 0) {
    memcpy(seg->data, data, len_data);
    ll_add(state->sent_segments, seg);
    state->next_seqno += len_data;
   } else if (flags & FIN) {
    ll_add(state->sent_segments, seg);
    state->next_seqno++;
   } 
   seg->cksum = cksum(seg, seg_len);
   return seg;
 }
 
 /* Helper function to send a segment */
 static void send_segment(ctcp_state_t *state, ctcp_segment_t *seg, size_t len) {
   if (conn_send(state->conn, seg, len) > 0) {
    // sent FIN or DATA segment
     if (ntohl(seg->flags) & (FIN | (len > sizeof(ctcp_segment_t)))) {
       state->last_sent_time = current_time();
       state->xmit_count = 0;
     } else { // sent ACK segment
       free(seg);
     }
   } else {
     free(seg);
   }
 }
 
 /* Helper function to check if we can destroy the connection */
 static bool can_destroy(ctcp_state_t *state) {
   return (state->recv_fin && state->input_eof && state->output_eof && 
           state->unacked_seg == NULL);
 }

  /* Helper function to handle received segment */
  void ack_seg_handle(ctcp_state_t *state, ctcp_segment_t *seg) {
    /* Có 5 trường hợp host nhận dược ACK */

    // Trường hợp 1: Host đang đợi Host khác ACK lại DATA mà Host đã gửi
    if (state->status == BLOCK_FOR_ACK) {
      // Kiểm tra xem Host có segment nào chưa ACK trong LL không
      ll_node_t *browse_node = state->sent_segments->head;
      ctcp_segment_t *browse_seg = (ctcp_segment_t *)(browse_node->object);

      if (browse_node == NULL) {
        // Nếu còn dữ liệu từ input, tiếp tục về trạng thái WAIT_INPUT
        if (state->input_eof != true) {
          state->status = WAIT_INPUT;
        } else {

        }
      } else { // Nếu có segment trong LL thif gửi lại
        if (state->xmit_count < 5) {
          send_segment(state, browse_seg, ntohl(browse_seg);
          state->xmit_count ++;
        }
      }
    } else if (state->status == FIN_WAIT_1) { // Đợi ACK cho FIN thứ 1 vừa gửi
      if (state->expected_ackno ==  ntohl(seg->ackno)) {
        state->status = FIN_WAIT_2;
      }
    } else if (state->status == LAST_ACK) { // Đợi ACK cho FIN thứ 2 vừa gửi
      if (state->expected_ackno ==  ntohl(seg->ackno)) {
        ctcp_destroy(state);
      }
    } else if (state->status == CLOSING) { // Đợi ACK cho cả 2 FIN gửi đồng thời
      state->status = TIME_WAIT;
    } else if (state->status == WAIT_SEND_FIN) { // Đợi nốt các ACK còn lại cho DATA trước khi FIN
      ctcp_segment_t *segment = create_segment(state, FIN, NULL, 0);
      send_segment(state, segment, segment->len);
    }
  }

  void data_seg_handle(ctcp_state_t *state, ctcp_segment_t *seg) {
    uint32_t seq_num = ntohl(seg->seqno);
    uint32_t seg_len = ntohl(seg->len);
    uint32_t data_len = sizeof(ctcp_segment_t) - seg_len;

    if (state->recv_window < data_len) {
      return;
    } else {
      state->next_ackno = seq_num + data_len;
      ctcp_segment_t *ack = create_segment(state, ACK, NULL, 0);
      send_segment(state, ack, sizeof(ctcp_segment_t));
    }


  }

  void fin_seg_handle(ctcp_state_t *state, ctcp_segment_t *seg) {
    state->next_ackno++;
    ctcp_segment_t *ack = create_segment(state, ACK, NULL, 0);
    send_segment(state, ack, sizeof(ctcp_segment_t));
    conn_output(state->conn, NULL, 0);

    if (state->status & FIN_WAIT_2) {
      state->status = TIME_WAIT;
      
      ctcp_destroy(state);
    } else if ((FIN_WAIT_1 | WAIT_SEND_FIN | WAIT_INPUT) & state->status) {
     if (FIN_WAIT_1 == state->status) {
       state->status = CLOSING;
     } else if (WAIT_INPUT == state->status) {
       state->status = CLOSE_WAIT;
     } else 
       ctcp_destroy(state);
    }
  }

  int is_correct_cksum(ctcp_segment_t *seg) {
   uint16_t recv_cksum = seg->cksum;
   seg->cksum = 0;
   uint16_t calc_cksum = cksum(seg, ntohl(seg->len));
   if (recv_cksum == calc_cksum) {
     return 1;
   }
   return 0;
  }