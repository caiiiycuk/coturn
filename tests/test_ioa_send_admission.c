/* SPDX-License-Identifier: BSD-3-Clause */
#include "mainrelay.h"
#include "ns_ioalib_impl.h"
#include <event2/bufferevent_ssl.h>
#include <unity.h>

/* Only system/OpenSSL write outcomes are controlled. The production IO
 * admission, congestion, bandwidth, backlog and buffer ownership paths run. */
static int test_ssl_write(SSL *ssl, const void *buffer, int len);
static int test_ssl_get_error(const SSL *ssl, int ret);
static int test_bev_write(struct bufferevent *bev, const void *buffer, size_t len);
static ssize_t test_sendto(int fd, const void *buffer, size_t len, int flags, const struct sockaddr *addr,
                           socklen_t alen);
#undef TURN_LOG_FUNC
#define TURN_LOG_FUNC(level, ...) ((void)0)
#define SSL_write test_ssl_write
#define SSL_get_error test_ssl_get_error
#define bufferevent_write test_bev_write
#define sendto test_sendto
#include "../src/apps/relay/ns_ioalib_engine_impl.c"
#undef SSL_write
#undef SSL_get_error
#undef bufferevent_write
#undef sendto

turn_params_t turn_params;
static struct _ioa_engine engine;
static struct _ioa_socket sock;
static struct event_base *base;
static SSL_CTX *context;
static int ssl_calls, ssl_successes, udp_calls, udp_error, ssl_error;
static bool bev_error;

static int test_ssl_write(SSL *ssl, const void *buffer, int len) {
  UNUSED_ARG(ssl);
  UNUSED_ARG(buffer);
  ++ssl_calls;
  if (ssl_successes-- > 0) {
    return len;
  }
  errno = ssl_error ? 0 : EAGAIN;
  return -1;
}

static int test_ssl_get_error(const SSL *ssl, int ret) {
  UNUSED_ARG(ssl);
  UNUSED_ARG(ret);
  return ssl_error;
}

static int test_bev_write(struct bufferevent *bev, const void *buffer, size_t len) {
  return bev_error ? -1 : bufferevent_write(bev, buffer, len);
}

static ssize_t test_sendto(int fd, const void *buffer, size_t len, int flags, const struct sockaddr *addr,
                           socklen_t alen) {
  ++udp_calls;
  if (udp_error) {
    errno = udp_error;
    return -1;
  }
  return sendto(fd, buffer, len, flags, addr, alen);
}

void setUp(void) {
  memset(&engine, 0, sizeof(engine));
  memset(&sock, 0, sizeof(sock));
  memset(&turn_params, 0, sizeof(turn_params));
  ssl_calls = udp_calls = udp_error = ssl_successes = ssl_error = 0;
  bev_error = false;
  base = event_base_new();
  TEST_ASSERT_NOT_NULL(base);
  context = NULL;
  sock.fd = socket(AF_INET, SOCK_DGRAM, 0);
  TEST_ASSERT_TRUE(sock.fd >= 0);
  sock.magic = SOCKET_MAGIC;
  sock.e = &engine;
  sock.st = UDP_SOCKET;
  sock.family = AF_INET;
  TEST_ASSERT_EQUAL_INT(0, make_ioa_addr((const uint8_t *)"127.0.0.1", 9, &sock.remote_addr));
}

void tearDown(void) {
  if (sock.bev) {
    bufferevent_free(sock.bev);
  }
  if (sock.ssl) {
    SSL_free(sock.ssl);
  }
  if (context) {
    SSL_CTX_free(context);
  }
  while (sock.bufs.head) {
    pop_elem_from_buffer_list(&sock.bufs);
  }
  while (engine.bufs.head) {
    pop_elem_from_buffer_list(&engine.bufs);
  }
  close(sock.fd);
  event_base_free(base);
}

static int send_payload(size_t len, int *skip, bool *admitted) {
  ioa_network_buffer_handle nbh = ioa_network_buffer_allocate(&engine);
  TEST_ASSERT_NOT_NULL(nbh);
  memset(ioa_network_buffer_data(nbh), 'x', len);
  ioa_network_buffer_set_size(nbh, len);
  return send_data_from_ioa_socket_nbh_with_admission(&sock, NULL, nbh, TTL_IGNORE, TOS_IGNORE, skip, admitted);
}

static void tcp_socket(void) {
  sock.st = TCP_SOCKET;
  sock.sat = CLIENT_SOCKET;
  sock.connected = 1;
  sock.bev = bufferevent_socket_new(base, -1, 0);
  TEST_ASSERT_NOT_NULL(sock.bev);
}

static void dtls_socket(void) {
  sock.st = DTLS_SOCKET;
  context = SSL_CTX_new(DTLS_method());
  TEST_ASSERT_NOT_NULL(context);
  sock.ssl = SSL_new(context);
  TEST_ASSERT_NOT_NULL(sock.ssl);
  BIO *bio = BIO_new_dgram(sock.fd, BIO_NOCLOSE);
  TEST_ASSERT_NOT_NULL(bio);
  SSL_set_bio(sock.ssl, bio, bio);
}

static void test_tcp_queue_and_congestion_veto(void) {
  tcp_socket();
  bool admitted = false;
  int skip = 0;
  TEST_ASSERT_EQUAL_INT(5, send_payload(5, &skip, &admitted));
  TEST_ASSERT_TRUE(admitted);
  TEST_ASSERT_EQUAL_INT(0, skip);
  struct evbuffer *output = bufferevent_get_output(sock.bev);
  TEST_ASSERT_EQUAL_size_t(5, evbuffer_get_length(output));
  TEST_ASSERT_EQUAL_INT(0, evbuffer_expand(output, BUFFEREVENT_MAX_UDP_TO_TCP_WRITE));
  char fill[BUFFEREVENT_MAX_UDP_TO_TCP_WRITE] = {0};
  TEST_ASSERT_EQUAL_INT(0, bufferevent_write(sock.bev, fill, sizeof(fill)));
  const size_t queued = evbuffer_get_length(output);
  TEST_ASSERT_EQUAL_INT(5, send_payload(5, &skip, &admitted));
  TEST_ASSERT_FALSE(admitted);
  TEST_ASSERT_EQUAL_INT(0, skip);
  TEST_ASSERT_EQUAL_size_t(queued, evbuffer_get_length(output));
  TEST_ASSERT_EQUAL_UINT32(1, engine.bufs.tsz);
}

static void test_tls_missing_context_and_shutdown(void) {
  tcp_socket();
  sock.st = TLS_SOCKET;
  bool admitted = true;
  int skip = 0;
  TEST_ASSERT_EQUAL_INT(0, send_payload(5, &skip, &admitted));
  TEST_ASSERT_FALSE(admitted);
  TEST_ASSERT_EQUAL_INT(0, skip);
  TEST_ASSERT_TRUE(sock.tobeclosed);
  TEST_ASSERT_EQUAL_size_t(0, evbuffer_get_length(bufferevent_get_output(sock.bev)));

  bufferevent_free(sock.bev);
  context = SSL_CTX_new(TLS_method());
  SSL *ssl = SSL_new(context);
  sock.bev = bufferevent_openssl_socket_new(base, -1, ssl, BUFFEREVENT_SSL_OPEN, BEV_OPT_CLOSE_ON_FREE);
  TEST_ASSERT_NOT_NULL(sock.bev);
  SSL_set_shutdown(ssl, SSL_SENT_SHUTDOWN);
  sock.tobeclosed = 0;
  TEST_ASSERT_EQUAL_INT(0, send_payload(5, &skip, &admitted));
  TEST_ASSERT_FALSE(admitted);
  TEST_ASSERT_EQUAL_INT(0, skip);
  TEST_ASSERT_TRUE(sock.tobeclosed);
  TEST_ASSERT_EQUAL_size_t(0, evbuffer_get_length(bufferevent_get_output(sock.bev)));
}

static void test_tls_queue_and_tcp_write_failure(void) {
  tcp_socket();
  sock.st = TLS_SOCKET;
  bufferevent_free(sock.bev);
  context = SSL_CTX_new(TLS_method());
  SSL *ssl = SSL_new(context);
  TEST_ASSERT_NOT_NULL(ssl);
  sock.bev = bufferevent_openssl_socket_new(base, -1, ssl, BUFFEREVENT_SSL_OPEN, BEV_OPT_CLOSE_ON_FREE);
  TEST_ASSERT_NOT_NULL(sock.bev);
  bool admitted = false;
  int skip = 0;
  TEST_ASSERT_EQUAL_INT(5, send_payload(5, &skip, &admitted));
  TEST_ASSERT_TRUE(admitted);
  TEST_ASSERT_EQUAL_size_t(5, evbuffer_get_length(bufferevent_get_output(sock.bev)));
  bev_error = true;
  TEST_ASSERT_EQUAL_INT(-1, send_payload(5, &skip, &admitted));
  TEST_ASSERT_FALSE(admitted);
  TEST_ASSERT_EQUAL_INT(0, skip);
  TEST_ASSERT_TRUE(sock.tobeclosed);
  TEST_ASSERT_TRUE(sock.broken);
  TEST_ASSERT_EQUAL_size_t(5, evbuffer_get_length(bufferevent_get_output(sock.bev)));
}

static void test_dtls_direct_success_and_fatal(void) {
  dtls_socket();
  bool admitted = false;
  int skip = 0;
  ssl_successes = 1;
  TEST_ASSERT_EQUAL_INT(5, send_payload(5, &skip, &admitted));
  TEST_ASSERT_TRUE(admitted);
  TEST_ASSERT_EQUAL_UINT32(0, sock.bufs.tsz);
  ssl_error = SSL_ERROR_SSL;
  TEST_ASSERT_EQUAL_INT(-1, send_payload(5, &skip, &admitted));
  TEST_ASSERT_FALSE(admitted);
  TEST_ASSERT_EQUAL_INT(0, skip);
  TEST_ASSERT_TRUE(sock.tobeclosed);
  TEST_ASSERT_EQUAL_UINT32(0, sock.bufs.tsz);
}

static void test_dtls_full_queued_and_flush_frees_room(void) {
  dtls_socket();
  bool admitted = false;
  int skip = 0;
  TEST_ASSERT_EQUAL_INT(0, send_payload(5, &skip, &admitted));
  TEST_ASSERT_TRUE(admitted);
  TEST_ASSERT_EQUAL_UINT32(1, sock.bufs.tsz);
  while (sock.bufs.tsz < MAX_SOCKET_BUFFER_BACKLOG) {
    TEST_ASSERT_TRUE(add_buffer_to_buffer_list(&sock.bufs, "xxxxx", 5));
  }
  TEST_ASSERT_EQUAL_INT(0, send_payload(5, &skip, &admitted));
  TEST_ASSERT_FALSE(admitted);
  TEST_ASSERT_EQUAL_INT(0, skip);
  TEST_ASSERT_EQUAL_UINT32(MAX_SOCKET_BUFFER_BACKLOG, sock.bufs.tsz);
  /* One old entry flushes, the next blocks, then the current payload queues. */
  ssl_successes = 1;
  const int before = ssl_calls;
  TEST_ASSERT_EQUAL_INT(0, send_payload(5, &skip, &admitted));
  TEST_ASSERT_TRUE(admitted);
  TEST_ASSERT_EQUAL_INT(3, ssl_calls - before);
  TEST_ASSERT_EQUAL_UINT32(MAX_SOCKET_BUFFER_BACKLOG, sock.bufs.tsz);
}

static void test_udp_best_effort_zero_and_fatal(void) {
  bool admitted = false;
  int skip = 0;
  TEST_ASSERT_EQUAL_INT(5, send_payload(5, &skip, &admitted));
  TEST_ASSERT_TRUE(admitted);
  TEST_ASSERT_EQUAL_INT(0, send_payload(0, &skip, &admitted));
  TEST_ASSERT_TRUE(admitted);
  const int handled[] = {EAGAIN, ENOBUFS, ECONNRESET};
  for (size_t i = 0; i < sizeof(handled) / sizeof(*handled); ++i) {
    udp_error = handled[i];
    TEST_ASSERT_EQUAL_INT(5, send_payload(5, &skip, &admitted));
    TEST_ASSERT_TRUE(admitted);
    TEST_ASSERT_EQUAL_INT(0, skip);
    TEST_ASSERT_FALSE(sock.tobeclosed);
  }
  udp_error = EACCES;
  TEST_ASSERT_EQUAL_INT(-1, send_payload(5, &skip, &admitted));
  TEST_ASSERT_FALSE(admitted);
  TEST_ASSERT_EQUAL_INT(0, skip);
  TEST_ASSERT_TRUE(sock.tobeclosed);
}

static void test_early_exits_and_bandwidth_skip(void) {
  bool admitted = true;
  int skip = 0;
  ts_ur_super_session session = {0};
  sock.session = &session;
  sock.sat = RELAY_SOCKET;
  session.bps = 1;
  TEST_ASSERT_EQUAL_INT(5, send_payload(5, &skip, &admitted));
  TEST_ASSERT_FALSE(admitted);
  TEST_ASSERT_EQUAL_INT(1, skip);
  TEST_ASSERT_EQUAL_INT(0, udp_calls);
  TEST_ASSERT_EQUAL_INT(-1, send_data_from_ioa_socket_nbh_with_admission(NULL, NULL, NULL, 0, 0, NULL, &admitted));
  TEST_ASSERT_FALSE(admitted);
  admitted = true;
  TEST_ASSERT_EQUAL_INT(-1, send_data_from_ioa_socket_nbh_with_admission(&sock, NULL, NULL, 0, 0, NULL, &admitted));
  TEST_ASSERT_FALSE(admitted);
  sock.done = 1;
  TEST_ASSERT_EQUAL_INT(-1, send_payload(5, &skip, &admitted));
  TEST_ASSERT_FALSE(admitted);
}

#if defined(__linux__)
static void test_udp_batch_takes_buffer_once_even_if_flush_fails(void) {
  turn_params.udp_sendmmsg = true;
  udp_sendmmsg_batch_begin();
  bool admitted = false;
  int skip = 0;
  TEST_ASSERT_EQUAL_INT(5, send_payload(5, &skip, &admitted));
  TEST_ASSERT_TRUE(admitted);
  TEST_ASSERT_EQUAL_UINT32(1, udp_sendmmsg_batch.count);
  TEST_ASSERT_EQUAL_UINT32(0, engine.bufs.tsz);
  TEST_ASSERT_EQUAL_INT(0, udp_calls);
  udp_error = EACCES;
  udp_sendmmsg_batch_end();
  TEST_ASSERT_EQUAL_UINT32(0, udp_sendmmsg_batch.count);
  TEST_ASSERT_EQUAL_UINT32(1, engine.bufs.tsz);
  TEST_ASSERT_EQUAL_INT(1, udp_calls);
  TEST_ASSERT_TRUE(admitted);
}
#endif

int main(void) {
  UNITY_BEGIN();
  RUN_TEST(test_tcp_queue_and_congestion_veto);
  RUN_TEST(test_tls_missing_context_and_shutdown);
  RUN_TEST(test_tls_queue_and_tcp_write_failure);
  RUN_TEST(test_dtls_direct_success_and_fatal);
  RUN_TEST(test_dtls_full_queued_and_flush_frees_room);
  RUN_TEST(test_udp_best_effort_zero_and_fatal);
  RUN_TEST(test_early_exits_and_bandwidth_skip);
#if defined(__linux__)
  RUN_TEST(test_udp_batch_takes_buffer_once_even_if_flush_fails);
#endif
  return UNITY_END();
}
