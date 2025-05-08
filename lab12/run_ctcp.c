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
 
 /**
  * Connection state.
  *
  * Stores per-connection information such as the current sequence number,
  * unacknowledged packets, etc.
  *
  * You should add to this to store other fields you might need.
  */
 struct ctcp_state {
   struct ctcp_state *next;  /* Next in linked list */
   struct ctcp_state **prev; /* Prev in linked list */
 
   conn_t *conn;             /* Connection object -- needed in order to figure
                                out destination when sending */
   linked_list_t *segments;  /* Linked list of segments sent to this connection.
                                It may be useful to have multiple linked lists
                                for unacknowledged segments, segments that
                                haven't been sent, etc. Lab 1 uses the
                                stop-and-wait protocol and therefore does not
                                necessarily need a linked list. You may remove
                                this if this is the case for you */
 
   /* FIXME: Add other needed fields. */
   uint32_t seqno;          // Next sequence number to send
   uint32_t ackno;          // Next expected sequence number
   int eof_sent;            // Have we sent EOF?
   int eof_received;        // Have we received EOF?
   ctcp_segment_t *unacked; // Unacknowledged segment
   uint64_t last_send_time; // For retransmission timeout
   
 };
 
 /**
  * Linked list of connection states. Go through this in ctcp_timer() to
  * resubmit segments and tear down connections.
  */
 static ctcp_state_t *state_list = NULL;
 
 /* FIXME: Feel free to add as many helper functions as needed. Don't repeat
           code! Helper functions make the code clearer and cleaner. */
 
 /* ------------------- Helper Functions ------------------- */
static void send_ack(ctcp_state_t *state, uint32_t ackno) {
    ctcp_segment_t *ack = calloc(1, sizeof(ctcp_segment_t));
    ack->seqno = state->seqno;
    ack->ackno = ackno;
    ack->flags = ACK;
    ack->len = sizeof(ctcp_segment_t);
    ack->cksum = cksum(ack, ack->len);
    conn_send(state->conn, ack, ack->len);
    free(ack);
  }

ctcp_state_t *ctcp_init(conn_t *conn, ctcp_config_t *cfg) {
  /* Connection could not be established. */
  if (conn == NULL) {
    return NULL;
  }

  /* Established a connection. Create a new state and update the linked list
    of connection states. */
  ctcp_state_t *state = calloc(sizeof(ctcp_state_t), 1);
  state->next = state_list;
  state->prev = &state_list;
  if (state_list)
    state_list->prev = &state->next;
  state_list = state;

  /* Set fields. */
  state->conn = conn;
  /* FIXME: Do any other initialization here. */
  state->seqno = 1;       // Bắt đầu với SEQ = 1
  state->ackno = 1;       // Bắt đầu với ACK = 1
  state->eof_sent = 0;
  state->eof_received = 0;
  state->unacked = NULL;

  return state;
}

void ctcp_destroy(ctcp_state_t *state) {
  /* Update linked list. */
  if (state->next)
    state->next->prev = state->prev;

  *state->prev = state->next;
  conn_remove(state->conn);

  /* FIXME: Do any other cleanup here. */
  if (state->unacked)
  free(state->unacked);

  free(state);
  end_client();
}

void ctcp_read(ctcp_state_t *state) {
  if (state->unacked != NULL)
    return; // Chưa được ACK, chờ

    fprintf(stderr, "Received segment with seqno=%u, expected ackno=%u\n", 
      segment->seqno, state->ackno);

  char buf[MAX_SEG_DATA_SIZE];
  int len = conn_input(state->conn, buf, MAX_SEG_DATA_SIZE);

  if (len == 0) {
    return; // Không có dữ liệu
  } else if (len < 0) {
    // Ứng dụng đóng, gửi FIN
    if (!state->eof_sent) {
      ctcp_segment_t *seg = calloc(1, sizeof(ctcp_segment_t));
      seg->seqno = state->seqno;
      seg->flags = FIN;
      seg->len = sizeof(ctcp_segment_t);
      seg->cksum = cksum(seg, seg->len);

      conn_send(state->conn, seg, seg->len);
      state->unacked = seg;
      state->last_send_time = current_time();
      state->eof_sent = 1;
    }
    return;
  }

  // Tạo segment dữ liệu
  ctcp_segment_t *seg = calloc(1, sizeof(ctcp_segment_t));
  seg->seqno = state->seqno;
  seg->ackno = 0;
  seg->flags = 0;
  seg->window = htons(MAX_SEG_DATA_SIZE);
  seg->len = sizeof(ctcp_segment_t) + len;
  memcpy(seg->data, buf, len);
  seg->cksum = cksum(seg, seg->len);

  conn_send(state->conn, seg, seg->len);
  state->unacked = seg;
  state->last_send_time = current_time();
}

void ctcp_receive(ctcp_state_t *state, ctcp_segment_t *segment, size_t len) {
  if (segment == NULL || len < sizeof(ctcp_segment_t))
    return;

  uint16_t recv_cksum = segment->cksum;
  segment->cksum = 0;
  if (cksum(segment, len) != recv_cksum)
    return;

  if (segment->flags & ACK) {
    if (state->unacked) {
      uint32_t expected_ack = state->unacked->seqno + (state->unacked->len - sizeof(ctcp_segment_t));
      if (segment->ackno == expected_ack) {
        free(state->unacked);
        state->unacked = NULL;
        state->seqno = segment->ackno;
      }
    }
  }

  if (segment->flags & FIN) {
    state->eof_received = 1;
    conn_output(state->conn, NULL, 0); // Gửi EOF đến ứng dụng
    send_ack(state, segment->seqno + 1);
    free(segment);
    return;
  }

  if (segment->len > sizeof(ctcp_segment_t)) {
    uint16_t data_len = segment->len - sizeof(ctcp_segment_t);
    if (segment->seqno == state->ackno) {
      conn_output(state->conn, segment->data, data_len);
      state->ackno += data_len;
      send_ack(state, state->ackno);
    }
  }

  free(segment);
}

void ctcp_output(ctcp_state_t *state) {
  // Không cần xử lý trong stop-and-wait
}

void ctcp_timer() {
  ctcp_state_t *curr = state_list;
  while (curr) {
    if (curr->unacked) {
      uint64_t now = current_time();
      if (now - curr->last_send_time > MAX_SEG_LIFETIME_MS * MAX_NUM_XMITS) {
        curr->unacked->cksum = 0;
        curr->unacked->cksum = cksum(curr->unacked, curr->unacked->len);
        conn_send(curr->conn, curr->unacked, curr->unacked->len);
        curr->last_send_time = now;
      }
    }

    ctcp_state_t *next = curr->next;
    if (curr->eof_sent && curr->eof_received && curr->unacked == NULL) {
      ctcp_destroy(curr);
    }
    curr = next;
  }
}