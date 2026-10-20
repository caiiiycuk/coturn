/* SPDX-License-Identifier: BSD-3-Clause */
#include "userdb.c"
#include <unity.h>

turn_params_t turn_params;
const turn_dbdriver_t *get_dbdriver(void) { abort(); }
void send_auth_message_to_auth_server(struct auth_message *message) {
  (void)message;
  abort();
}
void convert_string_key_to_binary(const char *source, hmackey_t key, size_t size) {
  (void)source;
  (void)key;
  (void)size;
  abort();
}
uint8_t *ioa_network_buffer_data(ioa_network_buffer_handle buffer) {
  (void)buffer;
  abort();
}
size_t ioa_network_buffer_get_size(ioa_network_buffer_handle buffer) {
  (void)buffer;
  abort();
}

void setUp(void) {
  create_default_realm();
  set_default_realm_name("first");
  realm_params_t *rp = get_realm("first");
  ur_string_map_free(&rp->status.alloc_counters);
  rp->status.alloc_counters = ur_string_map_create(NULL);
  rp->status.total_current_allocs = 0;
  change_total_quota("first", 0);
  change_user_quota("first", 0);
}
void tearDown(void) {}

static void test_two_realms_runtime_limits_and_unknown_lookup(void) {
  turn_observe_quota snapshot = {0};
  const size_t before = ur_string_map_size(realms);
  TEST_ASSERT_EQUAL(0, turn_read_quota_snapshot("missing", &snapshot));
  char overlong[STUN_MAX_REALM_SIZE + 2] = {0};
  memset(overlong, 'x', sizeof(overlong) - 1);
  overlong[sizeof(overlong) - 1] = 0;
  TEST_ASSERT_EQUAL(0, turn_read_quota_snapshot(overlong, &snapshot));
  TEST_ASSERT_EQUAL(before, ur_string_map_size(realms));
  TEST_ASSERT_EQUAL(1, turn_read_quota_snapshot("first", &snapshot));
  TEST_ASSERT_TRUE(snapshot.known);
  TEST_ASSERT_EQUAL_UINT64(0, snapshot.total);
  change_total_quota("first", 7);
  change_user_quota("first", 2);
  change_total_quota("second", 13);
  TEST_ASSERT_EQUAL(1, turn_read_quota_snapshot("first", &snapshot));
  TEST_ASSERT_EQUAL_UINT64(7, snapshot.total);
  TEST_ASSERT_EQUAL_UINT64(2, snapshot.user);
  TEST_ASSERT_EQUAL(1, turn_read_quota_snapshot("second", &snapshot));
  TEST_ASSERT_EQUAL_UINT64(13, snapshot.total);
}

static void test_quota_causes_and_release_after_failed_creation(void) {
  turn_quota_cause cause;
  change_total_quota("first", 2);
  change_user_quota("first", 1);
  TEST_ASSERT_EQUAL(0, check_new_allocation_quota((uint8_t *)"one", 0, (uint8_t *)"first", &cause));
  TEST_ASSERT_EQUAL(-1, check_new_allocation_quota((uint8_t *)"one", 0, (uint8_t *)"first", &cause));
  TEST_ASSERT_EQUAL(TURN_QUOTA_USER, cause);
  TEST_ASSERT_EQUAL(0, check_new_allocation_quota((uint8_t *)"two", 0, (uint8_t *)"first", &cause));
  TEST_ASSERT_EQUAL(-1, check_new_allocation_quota((uint8_t *)"three", 0, (uint8_t *)"first", &cause));
  TEST_ASSERT_EQUAL(TURN_QUOTA_TOTAL, cause);
  turn_observe_quota snapshot = {0};
  TEST_ASSERT_EQUAL(1, turn_read_quota_snapshot("first", &snapshot));
  TEST_ASSERT_EQUAL_UINT64(2, snapshot.used);
  release_allocation_quota((uint8_t *)"one", 0, (uint8_t *)"first");
  release_allocation_quota((uint8_t *)"two", 0, (uint8_t *)"first");
  TEST_ASSERT_EQUAL(1, turn_read_quota_snapshot("first", &snapshot));
  TEST_ASSERT_EQUAL_UINT64(0, snapshot.used);
}

static pthread_mutex_t turn_test_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t turn_test_cond = PTHREAD_COND_INITIALIZER;
static bool turn_test_locked, turn_test_release;
static void *turn_test_hold(void *map) {
  ur_string_map_lock(map);
  pthread_mutex_lock(&turn_test_lock);
  turn_test_locked = true;
  pthread_cond_signal(&turn_test_cond);
  while (!turn_test_release) {
    pthread_cond_wait(&turn_test_cond, &turn_test_lock);
  }
  pthread_mutex_unlock(&turn_test_lock);
  ur_string_map_unlock(map);
  return NULL;
}
static void turn_test_busy(const ur_string_map *map) {
  pthread_t thread;
  turn_test_locked = turn_test_release = false;
  pthread_mutex_lock(&turn_test_lock);
  TEST_ASSERT_EQUAL(0, pthread_create(&thread, NULL, turn_test_hold, (void *)map));
  while (!turn_test_locked) {
    pthread_cond_wait(&turn_test_cond, &turn_test_lock);
  }
  turn_observe_quota snapshot = {.used = 99};
  const int result = turn_read_quota_snapshot("first", &snapshot);
  turn_test_release = true;
  pthread_cond_signal(&turn_test_cond);
  pthread_mutex_unlock(&turn_test_lock);
  pthread_join(thread, NULL);
  TEST_ASSERT_EQUAL(-1, result);
  TEST_ASSERT_EQUAL_UINT64(99, snapshot.used);
}
static void test_busy_existing_locks_never_wait_or_replace_snapshot(void) {
  turn_test_busy(realms);
  turn_test_busy(get_realm("first")->status.alloc_counters);
}
int main(void) {
  UNITY_BEGIN();
  RUN_TEST(test_two_realms_runtime_limits_and_unknown_lookup);
  RUN_TEST(test_quota_causes_and_release_after_failed_creation);
  RUN_TEST(test_busy_existing_locks_never_wait_or_replace_snapshot);
  return UNITY_END();
}
