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

/* timer to delay */
int delay_keep;
timer_t timer_id;
void expired_func(union sigval sig_value);
int init_timer(timer_t *t_id);
void set_timer(timer_t t_id, int period_ms);

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
    
  init_timer(&timer_id);
    
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
  while (NULL != (tmp_node = ll_front(state->sent_segments)))
    free(ll_remove(state->sent_segments, tmp_node));
    
  tmp_node = NULL;
  while (NULL != (tmp_node = ll_front(state->recv_segments)))
    free(ll_remove(state->recv_segments, tmp_node));
    
  free(state);
  end_client();
}

void ctcp_read(ctcp_state_t *state) {
// Kiểm tra kết nối còn tồn tại không
  if (!state) return;

// Bỏ qua nếu kết nối đang ở trạng thái không thể gửi (đang đợi nhận segmnet)
  if ((BLOCK_FOR_ACK | FIN_WAIT_1 | FIN_WAIT_2 | LAST_ACK | WAIT_SEND_FIN) & state->status) return;

// Kiểm tra xem còn vùng trống trong swnd không, nếu không thì chuyển sang status BLOCK_FOR_ACK
  int bytes_left = state->sent_window - state->byte_sent;
  if (bytes_left <= 0) {
    state->status = BLOCK_FOR_ACK;
    return;
  }
    
// Từ dòng này trở đi là vẫn còn vùng trống trong swnd => có thể gửi thêm segment :))

// Số byte tối đa có thể đọc (so sánh MAX_SEG_DATA_SIZE với vùng trống trong swnd)
  int max_byte = bytes_left < MAX_SEG_DATA_SIZE ? bytes_left : MAX_SEG_DATA_SIZE;

// Đọc từ stdin với số byte tối đa có thể đọc vừa tính được (chia nhỏ data đầu vào thành các segment hoặc nhỏ hơn), lưu vào buffer
  int byte_read = conn_input(state->conn, state->buf_sent, max_byte);
  { // Hết byte đọc từ stdin => EOF => gửi FIN segment
    if (byte_read < 0) {
    // Đóng FIN lần 2
      if (state->status == CLOSE_WAIT) {
        state->status = LAST_ACK;
        create_segment_and_send(state, NULL, 0, FIN, state->ackno);
        state->byte_sent++;
        return;
      }
    
    // Đóng FIN lần 1
    // Các segment trong LL đã ACK hết => length của LL = 0 => gửi FIN segment
      if (ll_length(state->sent_segments) == 0) {
        state->status = FIN_WAIT_1;
        create_segment_and_send(state, NULL, 0, FIN, state->ackno);
        state->byte_sent++; 
        return;
      } else { // Tồn tại segment trong LL chưa ACK => length của LL != 0 => Gửi nốt ACk rồi gửi FIN ( xử lý lại chỗ này)
        state->status = WAIT_SEND_FIN;
        create_segment_and_send(state, NULL, 0, FIN, state->ackno);
        state->byte_sent++; 
        return;
      }
    } else if (byte_read > 0) { // Còn byte đọc từ stdin => gửi DATA segment
      create_segment_and_send(state, state->buf_sent, byte_read, 0, state->ackno);
      state->byte_sent += byte_read;
    }
    // Xóa buffer đọc từ stdin sau khi đã gửi đi
    memset(state->buf_sent, 0, MAX_SEG_DATA_SIZE);

    // Trường hợp gửi ACK segment đã được xử lý lại handle ở bên ctcp_receive()
  }
}

void ctcp_receive(ctcp_state_t *state, ctcp_segment_t *segment, size_t len)
{
  /* FIXME */
  if (NULL == state || NULL == segment)
    return;
  
  fprintf(stderr, "recv: %ld\n", len);  
  int check = is_corrupted_seg(segment, len);
  if (1 == check)
  {
    //printf("corrupt happen\n");
    free(segment);
    return;
  }
  if (state->first_seg)
  {
    state->first_seg = 0;
    state->seqno = ntohl(segment->ackno);
  }
  uint32_t flags = segment->flags;
    
  if ((TH_ACK & flags) && (TH_FIN & flags))
  {
    ack_seg_handle(state, segment);
    fin_seg_handle(state, segment);
  }
  else if (TH_FIN & flags)
  {
    fin_seg_handle(state, segment);
  }
  else if (TH_ACK & flags)
  {
    ack_seg_handle(state, segment);
        
    /* piggybacked ack */
    if (ntohs(segment->len) > sizeof(ctcp_segment_t))
    {
      data_seg_handle(state, segment);
    }
  }
  else if (0 == flags)  
  {
    data_seg_handle(state, segment);
  }
  free(segment);
}


void ctcp_output(ctcp_state_t *state)
{
  /* FIXME */
  if (NULL == state)
    return;
    
  ll_node_t *browse_node = NULL;
  browse_node = state->recv_segments->head;
  if (NULL == browse_node)
    return;
    
  ctcp_segment_t *browse_seg = NULL;
  uint16_t data_seg_len = 0;
    
  while (NULL != browse_node)
  {
    browse_seg = (ctcp_segment_t *)(browse_node->object);
    if (ntohl(browse_seg->seqno) == state->ackno)
    {
      data_seg_len = ntohs(browse_seg->len) - sizeof(ctcp_segment_t);
            
      size_t buf_space = conn_bufspace(state->conn);
      size_t val_can_output = (data_seg_len < buf_space) ? data_seg_len : buf_space;
      /* bufspace may has some error, this case terminate connection */
      if (val_can_output != data_seg_len)
      {
        printf("wtf\n");
        ctcp_destroy(state);
      }
      else
      {
        if (val_can_output != conn_output(state->conn, browse_seg->data, val_can_output))
        {
          //printf("error conn_output\n");
        }
                
        state->byte_recv -= data_seg_len;
        state->ackno += data_seg_len;
        free(ll_remove(state->recv_segments, browse_node));
        browse_node = ll_front(state->recv_segments);
      }
    }
    else
      browse_node = browse_node->next;
  }
}

void ctcp_timer() {
  /* FIXME */
  ctcp_state_t *state = state_list; 
  //fprintf(stderr, "ll_length: %d\n", ll_length(state -> sent_segments));  
  while (state)
  {
    if (0 != ll_length(state->sent_segments))
      retransmission_handle(state);
    state = state->next;
  }
}

/* Hàm tạo segment và gửi sang bên khác */
void create_segment_and_send(ctcp_state_t *state, char *buffer, uint16_t buf_len, uint32_t flags, uint32_t ack_num) {
// Chia data nhận từ stdin thành các segment và điều kiện gửi thoải mãn swnd xử lý tại ctcp_read() 

// Nếu đây là DATA segment đầu tiên được gửi đi, gán flags mặc định là ACK (vì data transfer lúc nào cũng có ACK flags) 
if (true == state->first_seg) {
    state->first_seg = false;
    flags |= ACK;
  }
  
  // Kích thước segment: header (sizeof(ctcp_segment_t)) + payload (buf_len)
  uint16_t seg_len;
  seg_len = sizeof(ctcp_segment_t) + buf_len;

  // Đóng gói các field của segment
  ctcp_segment_t *segment = calloc(1, seg_len);
  segment->seqno = htonl(state->seqno);
  segment->ackno = htonl(ack_num);
  segment->len = htons(seg_len);
  segment->flags = htonl(flags);
  segment->window = htons(state->sent_window);

  // Ban đầu cksum = 0 để tính cksum mới
  segment->cksum = 0;
    
  // Data segment
  if (buf_len > 0) {
    memcpy(segment->data, buffer, buf_len);
    state->seqno += buf_len;

    // Thêm DATA segment vừa gửi vào LL để chờ ACK cho segment (Nếu nhận được ACK thì xóa khỏi LL)
    ll_add(state->sent_segments, segment);

    // Tính lại cksum
    segment->cksum = cksum(segment, seg_len);
    conn_send(state->conn, segment, seg_len);
  } 

  // FIN segment
  if (flags & FIN) { 
    state->seqno++;

    // Nếu là FIN segment thì cũng thêm vào LL chờ ACK 
    ll_add(state->sent_segments, segment);

    // Tính lại cksum
    segment->cksum = cksum(segment, seg_len);
    conn_send(state->conn, segment, seg_len);
  } 

  // ACK segment
  if ((flags & ACK) && (buf_len == 0)) free(segment); 
}

/* Xử lý FIN segment nhận được */
void fin_seg_handle(ctcp_state_t *state, ctcp_segment_t *segment) {
  // Dù ở status nào thì khi nhận được FIN segment cũng sẽ gửi lại 1 ACK segment
  uint32_t ack_num = ntohl(segment->seqno) + 1;
  create_segment_and_send(state, NULL, 0, ACK, ack_num);
  conn_output(state->conn, NULL, 0);
  //ctcp_destroy(state);

  // Chưa rõ phần này lắm
  if (state->ackno == ntohl(segment->seqno)) {
    state->ackno = ack_num;
  }
    
  /* Thay đổi field status trong state */
  // Nếu status đang chờ nhận FIN segment thứ 2
  if (state->status & FIN_WAIT_2) {
    state->status = TIME_WAIT;
    printf("state changed from FIN_WAIT_2 to TIME_WAIT \n");
    ctcp_destroy(state);
  }

  // Cả 2 bên gửi FIN đồng thời
  if (state->status & FIN_WAIT_1) {
    printf("state changed from FIN_WAIT_1 to CLOSING \n");
    state->status = CLOSING;
  }

  // Đợi app gọi close(), peer gửi FIN trước
  if (state->status & WAIT_INPUT) {
    state->fin_recv_first = true;
    printf("state changed to CLOSE_WAIT\n");
    state->status = CLOSE_WAIT;
  }

  // App đã gọi close(), chuẩn bị gửi FIN nhưng peer gửi FIN trước nên đóng lun
  if (state->status & WAIT_SEND_FIN) { 
    ctcp_destroy(state); // Hủy state kể cả chưa ACK hết data
  }
}

/* Hàm xử lý ACK segment nhận được */
void ack_seg_handle(ctcp_state_t *state, ctcp_segment_t *segment) {
  // Kiểm tra state, segment nhận được, unACK segment của state tồn tại
  if (!state || !segment || !state->sent_segments->head) return;
  
  // Lấy segment đầu tiên trong LL đã gửi
  ll_node_t *browse_node = state->sent_segments->head;
  ctcp_segment_t *browse_seg = (ctcp_segment_t *)(browse_node->object);
  // Kích thước data của segment chưa ACK (bỏ đi phần header)
  uint16_t seg_data_len = ntohs(browse_seg->len) - sizeof(ctcp_segment_t);
    
  // Nếu segment trong LL là FIN segment => đặt len = 1
  if (browse_seg->flags & TH_FIN) seg_data_len = 1; 
    
  // ACK segment không hợp lệ => Retransmit FIN hoặc DATA segment
  if (ntohl(segment->ackno) != (ntohl(browse_seg->seqno) + seg_data_len)) {
    conn_send(state->conn, browse_seg, ntohs(browse_seg->len));
    return;
  } else { // ACK segment hợp lệ 
    // Giảm số byte đã gửi, xóa segment ra khỏi LL chờ, reset bộ đếm retransmit
    state->byte_sent -= seg_data_len;
    free(ll_remove(state->sent_segments, browse_node));
    state->retrans_count = 0;
        
    /* Thay đổi trạng thái */ 
    // Hết segment trong LL (segmnent đã ACK hết)
    if (ll_length(state->sent_segments) == 0) {
      // status = BLOCK_FOR_ACK
      if (state->status == BLOCK_FOR_ACK) {
        if (state->fin_recv_first == true) state->status = CLOSE_WAIT;
        else state->status = WAIT_INPUT;
      } else if (state->status == FIN_WAIT_1) { // status = FIN_WAIT_1
        state->status = FIN_WAIT_2;
      } else if (state->status == WAIT_SEND_FIN) { // status = WAIT_SEND_FIN
        create_segment_and_send(state, NULL, 0, FIN, state->ackno);
        state->byte_sent++;
        if (state->fin_recv_first == true) ctcp_destroy(state);
        else state->status = FIN_WAIT_2;
      } else if (state->status == CLOSING) { // status = CLOSING
        state->status = TIME_WAIT;
        ctcp_destroy(state);
      } else if (state->status == LAST_ACK) { // status = LAST_ACK                
        set_timer(timer_id, 2 * 5000);
        while (delay_keep == 0);
        delay_keep = 0;
        ctcp_destroy(state);
      }
    } else if (state->sent_window > state->byte_sent) { // Segment chưa ACK hết, 
      if (state->fin_recv_first == true) state->status = CLOSE_WAIT;
      else state->status = WAIT_INPUT;
    }
    return;
  }
    
  // ACK segment nhận được không phải của segment đầu tiên => duyệt node tiếp theo
  if (ntohl(segment->ackno)) {
    while (browse_node != NULL) {
      browse_seg = (ctcp_segment_t *)(browse_node->object);
      seg_data_len = ntohs(browse_seg->len) - sizeof(ctcp_segment_t);
            
      if (browse_seg->flags & TH_FIN) seg_data_len = 1;
      if (ntohl(segment->ackno) == (ntohl(browse_seg->seqno) + seg_data_len)) {
        state->byte_sent -= seg_data_len;
        free(ll_remove(state->sent_segments, browse_node));
        return;
      }
      browse_node = browse_node->next;
    }
  }
}

/* Hàm xử lý khi nhận DATA segment */
void data_seg_handle(ctcp_state_t *state, ctcp_segment_t *segment)
{
  uint16_t seg_len = ntohs(segment->len);
  uint32_t seq_num = ntohl(segment->seqno);
  uint16_t data_len = seg_len - sizeof(ctcp_segment_t);
  uint32_t ack_num = seq_num + data_len;
    
  /* Kiểm tra điều kiện nhận segment */
  // 1. Không nhận nếu vùng đệm nhận (recv_window) đầy
  if (state->recv_window < (state->byte_recv + data_len)) return;

  // 2. Kiểm tra segment có nằm ngoài cửa sổ nhận không
  if (seq_num >= (state->ackno + state->recv_window)) return;

  // 3. Nếu segment đã được ACK rồi (dữ liệu cũ) thì gửi lại ACK và bỏ qua
  if (state->ackno >= ack_num) {
    create_segment_and_send(state, NULL, 0, ACK, ack_num);
    return;
  }
    
  /* Kiểm tra segment trùng lặp trong bộ đệm nhận */
  if (ll_length(state->recv_segments) > 0) {
    ll_node_t *check_node = NULL;
    check_node = ll_front(state->recv_segments); // Lấy segment đầu tiên
    if (check_node == NULL) return;
    ctcp_segment_t *check_seg = NULL;

    // Duyệt qua toàn bộ danh sách đã nhận
    while (check_node != NULL) {
      check_seg = (ctcp_segment_t*)(check_node->object);
  
      // Nếu phát hiện segment trùng seq_num thì bỏ qua
      if (segment->seqno == check_seg->seqno) return;

      check_node = check_node->next;
    }
  }
    
  // Cập nhật số byte đã nhận
  state->byte_recv += data_len;

  // Gửi ACK ngay lập tức cho dữ liệu nhận được
  create_segment_and_send(state, NULL, 0, ACK, ack_num);
    
  /* Thêm segment vào bộ đệm nhận */
  // 1. Tạo bản copy của segment để lưu trữ
  ctcp_segment_t *copy_seg = calloc(1, seg_len);
  memcpy(copy_seg, segment, seg_len);

  // 2. Thêm vào danh sách các segment đã nhận
  ll_add(state->recv_segments, copy_seg);

  // 3. Nếu segment này là segment mong đợi tiếp theo (in-order)
  // thì gọi ctcp_output() để xử lý dữ liệu
  if (state->ackno == ntohl(segment->seqno)) ctcp_output(state);
}

/* funtion using checksum to check whether segment is corrupted
* return 1 if corrupt, 0 otherwise */
int is_corrupted_seg(ctcp_segment_t *segment, size_t len)
{
    
  if (NULL == segment)
    return 1;
  if (len != ntohs(segment->len))
    return 1;
  uint16_t computed_cksum = segment->cksum;
  uint16_t cksum_test;
  segment->cksum = 0;
  cksum_test = cksum(segment, ntohs(segment->len));
  return (cksum_test == computed_cksum ? 0 : 1);
}

/* funtion get time interval from last send to current */
uint32_t get_time_from_last_trans(ctcp_state_t *state)
{
  if (NULL == state)
  {
    //printf("error get time from last trans: state NULL!\n");
    return -1;
  }
  uint32_t time_interval =  (long)current_time() - ((uint32_t)state->start_send_time.tv_sec * 1000 + (uint32_t)state->start_send_time.tv_usec / 1000);
  return time_interval;
}

/* function handle retransmission, return number of restransmission times, -1 if error or disconnected */
void retransmission_handle(ctcp_state_t *state)
{
  if (NULL == state)
    return;
  linked_list_t *list = state->sent_segments;
  uint32_t time_get = get_time_from_last_trans(state);
  printf("time get %u\n", time_get);
  /* time out happen */
  if (time_get >= state->rt_timeout)
  {
    state->retrans_count++;
    //printf("time out happen %d\n", state->retrans_count);
    if (5 < state->retrans_count)
    {
      ctcp_destroy(state);
      fprintf(stderr, "Retrans Counter: %d\n", state -> retrans_count); 
      return;
    }
        
    /* retransmit data */
    if (NULL != list->head)
    {
      ctcp_segment_t *segment = (ctcp_segment_t *)(list->head->object);
      conn_send(state->conn, segment, ntohs(segment->len));
    }
    gettimeofday(&(state->start_send_time), NULL);
  }
}



/* function handle when timer expired */
void expired_func(union sigval sig_value)
{
  set_timer(timer_id, 0); /* stop timer */
  delay_keep = 1;
}

/* funtion create timer to delay */
int init_timer(timer_t *t_id)
{
  delay_keep = 0;
    
  struct sigevent sig_event;
  sig_event.sigev_notify = SIGEV_THREAD;
  sig_event.sigev_notify_function = expired_func;

  int res;
  res = 1; // timer_create(CLOCK_REALTIME, &sig_event, t_id);
  if (-1 == res)
  {
    //printf("fail to create timer!\n");
  }
  return res;
}
void set_timer(timer_t t_id, int period_ms)
{
  struct itimerspec infor_timer = {.it_interval.tv_sec = period_ms/1000,
                                  .it_interval.tv_nsec = 0,
                                  .it_value.tv_sec = period_ms/1000,
                                  .it_value.tv_nsec = 0
  };
  int res = 1; //timer_settime(t_id, 0, &infor_timer, NULL);
  if (-1 == res)
  {
    //printf("fail to start/stop timer!");
  }
}
