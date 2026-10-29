/* SPDX-License-Identifier: BSD-3-Clause */
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <time.h>
#include <unity.h>

static uint64_t turn_test_seconds;
static unsigned turn_test_clock_calls;
static bool turn_test_clock_failure;
#if defined(WINDOWS)
#include <windows.h>
static ULONGLONG WINAPI turn_test_ticks(void) {
  ++turn_test_clock_calls;
  return turn_test_seconds * 1000;
}
#define GetTickCount64 turn_test_ticks
#else
static int turn_test_clock(clockid_t clock_id, struct timespec *ts) {
  (void)clock_id;
  ++turn_test_clock_calls;
  if (turn_test_clock_failure) {
    return -1;
  }
  ts->tv_sec = (time_t)turn_test_seconds;
  ts->tv_nsec = 0;
  return 0;
}
#define clock_gettime turn_test_clock
#endif
#include "turn_observability.c"
#undef clock_gettime
#undef GetTickCount64

static int turn_test_quota_result;
static int turn_test_quota(const char *realm, turn_observe_quota *out) {
  (void)realm;
  if (turn_test_quota_result > 0) {
    *out = (turn_observe_quota){3, 10, 2, true};
  }
  return turn_test_quota_result;
}

void setUp(void) {
  while (turn_observe_owners) {
    turn_observe_owner *next = turn_observe_owners->next;
    pthread_mutex_destroy(&turn_observe_owners->lock);
    free(turn_observe_owners);
    turn_observe_owners = next;
  }
  turn_observe_quota_owner = NULL;
  memset(turn_observe_realms, 0, sizeof(turn_observe_realms));
  turn_observe_count = 0;
  turn_observe_frozen = turn_observe_enabled = false;
  turn_observe_read_quota = NULL;
  turn_test_seconds = 100;
  turn_test_clock_failure = false;
  turn_test_clock_calls = 0;
  turn_test_quota_result = 1;
}
void tearDown(void) {}

static turn_observe_owner *turn_test_start(void) {
  turn_observe_start("default", true, turn_test_quota);
  return turn_observe_owner_new();
}

static void test_config_is_bounded_exact_and_frozen(void) {
  char name[STUN_MAX_REALM_SIZE + 2] = {0};
  memset(name, 'x', sizeof(name));
  name[sizeof(name) - 1] = 0;
  TEST_ASSERT_FALSE(turn_observe_add_realm(name));
  name[STUN_MAX_REALM_SIZE] = 0;
  TEST_ASSERT_TRUE(turn_observe_add_realm(name));
  TEST_ASSERT_TRUE(turn_observe_add_realm(name));
  for (unsigned i = 1; i < 16; ++i) {
    char realm[20] = {0};
    snprintf(realm, sizeof(realm), "realm-%u", i);
    TEST_ASSERT_TRUE(turn_observe_add_realm(realm));
  }
  TEST_ASSERT_FALSE(turn_observe_add_realm("seventeenth"));
  turn_test_start();
  TEST_ASSERT_EQUAL(16, turn_observe_realm_count());
  TEST_ASSERT_EQUAL(0, turn_observe_realm_index("default"));
  TEST_ASSERT_EQUAL(0, turn_observe_realm_index("untrusted-client-realm"));
  TEST_ASSERT_FALSE(turn_observe_add_realm("realm-1"));
}

static void test_default_and_runtime_disabled(void) {
  turn_observe_start("default", false, turn_test_quota);
  TEST_ASSERT_EQUAL(1, turn_observe_realm_count());
  TEST_ASSERT_EQUAL_STRING("default", turn_observe_realm_name(0));
  TEST_ASSERT_NULL(turn_observe_owner_new());
  TEST_ASSERT_EQUAL(0, turn_observe_realm_index("default"));
  turn_observe_session state = {0};
  turn_observe_bind(NULL, &state, "default");
  turn_observe_created(NULL, &state);
  turn_observe_data(NULL, &state, 100);
  turn_observe_bind(NULL, &state, "other");
  turn_observe_closed(NULL, &state);
  const turn_observe_session empty = {0};
  TEST_ASSERT_EQUAL_MEMORY(&empty, &state, sizeof(state));
  TEST_ASSERT_EQUAL(0, state.active);
  TEST_ASSERT_EQUAL(0, state.bytes);
  TEST_ASSERT_EQUAL(0, turn_test_clock_calls);
}

#if !defined(TURN_NO_PROMETHEUS)
static void test_effective_realm_migration_preserves_logical_lifetime(void) {
  TEST_ASSERT_TRUE(turn_observe_add_realm("A"));
  TEST_ASSERT_TRUE(turn_observe_add_realm("B"));
  turn_observe_owner *owner = turn_test_start();
  turn_observe_session state = {0};
  turn_observe_bind(owner, &state, "A");
  turn_observe_created(owner, &state);
  turn_observe_data(owner, &state, 1);
  turn_test_seconds = 170;
  turn_observe_tick_begin(owner);
  turn_observe_bind(owner, &state, "B");
  turn_observe_created(owner, &state); /* REFRESH cannot create another lifecycle. */
  turn_observe_result(owner, &state, 0);
  turn_observe_visit(owner, &state);
  TEST_ASSERT_EQUAL_UINT64(1, owner->local.realm[1].bins[4]); /* quiet, le64k */
  TEST_ASSERT_EQUAL_UINT64(0, owner->local.realm[0].bins[4]);
  TEST_ASSERT_EQUAL_UINT64(1, owner->local.realm[1].results[0]);
  TEST_ASSERT_EQUAL_UINT64(1, owner->local.realm[0].created);
  TEST_ASSERT_EQUAL_UINT64(0, owner->local.realm[1].created);

  turn_observe_bind(owner, &state, "outside");
  turn_observe_data(owner, &state, 65536);
  turn_observe_result(owner, &state, 0);
  turn_observe_tick_begin(owner);
  turn_observe_visit(owner, &state);
  TEST_ASSERT_EQUAL_UINT64(0, owner->local.realm[1].bins[4]);
  TEST_ASSERT_EQUAL_UINT64(1, owner->local.realm[1].results[0]);
  turn_observe_bind(owner, &state, "A");
  TEST_ASSERT_EQUAL_UINT64(100, state.created);
  TEST_ASSERT_EQUAL_UINT64(170, state.last_data);
  TEST_ASSERT_EQUAL_UINT32(65537, state.bytes);
  turn_observe_visit(owner, &state);
  TEST_ASSERT_EQUAL_UINT64(1, owner->local.realm[0].bins[8]); /* recent, gt64k */
  turn_observe_closed(owner, &state);
  turn_observe_closed(owner, &state);
  TEST_ASSERT_EQUAL_UINT64(1, owner->local.realm[0].closed[TURN_CLOSE_OTHER]);

  state = (turn_observe_session){0};
  turn_observe_bind(owner, &state, "outside");
  turn_observe_created(owner, &state);
  turn_observe_data(owner, &state, 7);
  turn_test_seconds = 240;
  turn_observe_tick_begin(owner);
  turn_observe_bind(owner, &state, "B");
  turn_observe_visit(owner, &state);
  TEST_ASSERT_EQUAL_UINT64(170, state.created);
  TEST_ASSERT_EQUAL_UINT64(1, owner->local.realm[1].bins[4]);
  TEST_ASSERT_EQUAL_UINT32(7, state.bytes);
  turn_observe_closed(owner, &state);
  TEST_ASSERT_EQUAL_UINT64(0, owner->local.realm[1].created);
  TEST_ASSERT_EQUAL_UINT64(1, owner->local.realm[1].closed[TURN_CLOSE_OTHER]);

  state = (turn_observe_session){0};
  turn_observe_bind(owner, &state, "outside");
  turn_observe_created(owner, &state);
  turn_observe_closed(owner, &state); /* No realm-1 indexing outside coverage. */
  TEST_ASSERT_EQUAL_UINT8(0, state.active);
  TEST_ASSERT_TRUE(sizeof(state) <= 32);
}

static void test_events_are_closed_bounded_and_cumulative(void) {
  turn_observe_owner *owner = turn_test_start();
  turn_observe_session state = {0};
  turn_observe_bind(owner, &state, "default");
  TEST_ASSERT_EQUAL(1, state.realm);
  turn_observe_created(owner, &state);
  turn_observe_created(owner, &state);
  const int codes[] = {0, 300, 400, 403, 420, 437, 440, 441, 442, 443, 508, 599};
  for (unsigned i = 0; i < sizeof(codes) / sizeof(*codes); ++i) {
    turn_observe_result(owner, &state, codes[i]);
  }
  const turn_quota_cause causes[] = {TURN_QUOTA_TOTAL, TURN_QUOTA_USER, TURN_QUOTA_BANDWIDTH, TURN_QUOTA_OTHER};
  for (unsigned i = 0; i < 4; ++i) {
    state.quota_cause = causes[i];
    turn_observe_result(owner, &state, 486);
  }
  turn_observe_result(owner, &state, 401);
  turn_observe_result(owner, &state, 438);
  for (unsigned i = 0; i < 16; ++i) {
    TEST_ASSERT_EQUAL_UINT64(1, owner->local.realm[0].results[i]);
  }
  state.quota_cause = TURN_QUOTA_TOTAL;
  turn_observe_result(owner, &state, 420);
  TEST_ASSERT_EQUAL_UINT64(2, owner->local.realm[0].results[4]);
  TEST_ASSERT_EQUAL_UINT64(1, owner->local.realm[0].results[10]);
  state.close_reason = TURN_CLOSE_EXPIRED;
  turn_observe_closed(owner, &state);
  turn_observe_closed(owner, &state);
  TEST_ASSERT_EQUAL_UINT64(1, owner->local.realm[0].created);
  TEST_ASSERT_EQUAL_UINT64(1, owner->local.realm[0].closed[TURN_CLOSE_EXPIRED]);
}

static void test_activity_thresholds_and_large_payload(void) {
  turn_observe_owner *owner = turn_test_start();
  turn_observe_session state = {0};
  turn_observe_bind(owner, &state, "default");
  turn_observe_created(owner, &state);
  turn_observe_tick_begin(owner);
  turn_observe_visit(owner, &state);
  TEST_ASSERT_EQUAL_UINT64(1, owner->local.realm[0].bins[0]);
  turn_test_seconds = 160;
  turn_observe_tick_begin(owner);
  turn_observe_visit(owner, &state);
  TEST_ASSERT_EQUAL_UINT64(1, owner->local.realm[0].bins[3]);
  const unsigned clock_calls = turn_test_clock_calls;
  turn_observe_data(owner, &state, 65536);
  TEST_ASSERT_EQUAL_UINT32(65536, state.bytes);
  turn_observe_visit(owner, &state);
  TEST_ASSERT_EQUAL_UINT64(1, owner->local.realm[0].bins[7]);
  turn_observe_data(owner, &state, 1);
  turn_observe_data(owner, &state, SIZE_MAX);
  TEST_ASSERT_EQUAL_UINT32(65537, state.bytes);
  turn_observe_visit(owner, &state);
  TEST_ASSERT_EQUAL_UINT64(1, owner->local.realm[0].bins[8]);
  TEST_ASSERT_EQUAL(clock_calls, turn_test_clock_calls);
  turn_test_seconds = 220;
  turn_observe_tick_begin(owner);
  turn_observe_visit(owner, &state);
  TEST_ASSERT_EQUAL_UINT64(1, owner->local.realm[0].bins[5]);
}

static void test_all_nine_bins(void) {
  turn_observe_owner *owner = turn_test_start();
  owner->now = 100;
  for (unsigned i = 0; i < 9; ++i) {
    turn_observe_session state = {.created = i / 3 ? 0 : 90,
                                  .last_data = i / 3 == 1 ? 0 : 90,
                                  .bytes = i % 3 == 0   ? 0
                                           : i % 3 == 1 ? 65536
                                                        : 65537,
                                  .realm = 1,
                                  .active = 1};
    turn_observe_visit(owner, &state);
  }
  for (unsigned i = 0; i < 9; ++i) {
    TEST_ASSERT_EQUAL_UINT64(1, owner->local.realm[0].bins[i]);
  }
}

static void test_contention_and_clock_failure_preserve_freshness(void) {
  turn_observe_owner *owner = turn_test_start();
  turn_observe_publish(owner, 1000);
  owner->local.realm[0].created = 9;
  pthread_mutex_lock(&owner->lock);
  turn_observe_publish(owner, 1001);
  pthread_mutex_unlock(&owner->lock);
  turn_observe_snapshot out = {0};
  turn_observe_collect(&out);
  TEST_ASSERT_EQUAL_UINT64(0, out.realm[0].created);
  TEST_ASSERT_EQUAL_UINT64(1000, out.timestamp);
  turn_test_quota_result = -1;
  turn_observe_publish(owner, 1002);
  turn_observe_collect(&out);
  TEST_ASSERT_EQUAL_UINT64(9, out.realm[0].created);
  TEST_ASSERT_EQUAL_UINT64(1001, out.timestamp);
  turn_test_clock_failure = true;
#if defined(WINDOWS)
  owner->clock_ok = false; /* GetTickCount64 itself has no failure result. */
#else
  TEST_ASSERT_FALSE(turn_observe_tick_begin(owner));
#endif
  turn_observe_publish(owner, 2000);
  turn_observe_collect(&out);
  TEST_ASSERT_EQUAL_UINT64(1001, out.timestamp);
  TEST_ASSERT_EQUAL_UINT64(9, out.realm[0].created);
}

static void test_workers_unknown_realm_and_repeated_collection(void) {
  turn_observe_owner *one = turn_test_start();
  turn_observe_owner *two = turn_observe_owner_new();
  one->local.realm[0].created = 2;
  two->local.realm[0].created = 3;
  turn_observe_publish(one, 1000);
  turn_observe_snapshot out = {0};
  turn_observe_collect(&out);
  TEST_ASSERT_EQUAL_UINT64(0, out.timestamp);
  turn_observe_publish(two, 1001);
  turn_observe_collect(&out);
  TEST_ASSERT_EQUAL_UINT64(1000, out.timestamp);
  TEST_ASSERT_EQUAL_UINT64(5, out.realm[0].created);
  turn_observe_collect(&out);
  TEST_ASSERT_EQUAL_UINT64(5, out.realm[0].created);
  turn_observe_publish(two, 1010);
  turn_observe_collect(&out);
  TEST_ASSERT_EQUAL_UINT64(1000, out.timestamp);
  turn_test_quota_result = 0;
  turn_observe_publish(one, 1002);
  turn_observe_collect(&out);
  TEST_ASSERT_EQUAL_UINT64(0, out.timestamp);
  TEST_ASSERT_FALSE(out.quota[0].known);
}

static void test_clock_outage_does_not_invent_allocation_age(void) {
  turn_observe_owner *owner = turn_test_start();
  turn_observe_publish(owner, 1000);
  owner->clock_ok = false;
  turn_observe_session state = {0};
  turn_observe_bind(owner, &state, "default");
  turn_observe_created(owner, &state);
  turn_test_seconds = 1000;
  turn_observe_tick_begin(owner);
  turn_observe_visit(owner, &state);
  turn_observe_publish(owner, 2000);
  turn_observe_snapshot snapshot = {0};
  turn_observe_collect(&snapshot);
  TEST_ASSERT_EQUAL_UINT64(1000, snapshot.timestamp);
  TEST_ASSERT_EQUAL_UINT64(0, snapshot.realm[0].created);
  turn_observe_closed(owner, &state);
  turn_observe_tick_begin(owner);
  turn_observe_publish(owner, 2001);
  turn_observe_collect(&snapshot);
  TEST_ASSERT_EQUAL_UINT64(2001, snapshot.timestamp);
  TEST_ASSERT_EQUAL_UINT64(1, snapshot.realm[0].created);
  TEST_ASSERT_EQUAL_UINT64(1, snapshot.realm[0].closed[TURN_CLOSE_OTHER]);
}

static void test_clock_outage_activity_requires_a_known_timestamp(void) {
  turn_observe_owner *owner = turn_test_start();
  turn_observe_session state = {0};
  turn_observe_bind(owner, &state, "default");
  turn_observe_created(owner, &state);
  owner->clock_ok = false;
  turn_observe_data(owner, &state, 1);
  turn_test_seconds = 200;
  turn_observe_tick_begin(owner);
  turn_observe_visit(owner, &state);
  TEST_ASSERT_FALSE(owner->ready);
  turn_observe_data(owner, &state, 1);
  turn_observe_tick_begin(owner);
  turn_observe_visit(owner, &state);
  TEST_ASSERT_TRUE(owner->ready);
  TEST_ASSERT_EQUAL_UINT64(1, owner->local.realm[0].bins[7]);
}

static void test_sweep_component_cost_and_bounds(void) {
  turn_observe_owner *owner = turn_test_start();
  turn_observe_session state = {.realm = 1, .active = 1, .created = 100, .last_data = 100};
  clock_t maximum = 0;
  void (*volatile visit)(turn_observe_owner *, const turn_observe_session *) = turn_observe_visit;
  for (unsigned sample = 0; sample < 100; ++sample) {
    clock_t start = clock();
    for (unsigned i = 0; i < 18000; ++i) {
      visit(owner, &state);
    }
    clock_t elapsed = clock() - start;
    if (elapsed > maximum) {
      maximum = elapsed;
    }
  }
  printf("observation bounds: session=%zu owner=%zu fixed-realms=%zu; maximum 18000-visit component sweep=%.3f ms\n",
         sizeof(state), sizeof(*owner), sizeof(turn_observe_realms), 1000.0 * maximum / CLOCKS_PER_SEC);
  TEST_ASSERT_LESS_OR_EQUAL(32, sizeof(state));
  TEST_ASSERT_LESS_OR_EQUAL(16 * 1024, sizeof(*owner));
}
#endif

int main(void) {
  UNITY_BEGIN();
  RUN_TEST(test_config_is_bounded_exact_and_frozen);
  RUN_TEST(test_default_and_runtime_disabled);
#if !defined(TURN_NO_PROMETHEUS)
  RUN_TEST(test_effective_realm_migration_preserves_logical_lifetime);
  RUN_TEST(test_events_are_closed_bounded_and_cumulative);
  RUN_TEST(test_activity_thresholds_and_large_payload);
  RUN_TEST(test_all_nine_bins);
  RUN_TEST(test_contention_and_clock_failure_preserve_freshness);
  RUN_TEST(test_workers_unknown_realm_and_repeated_collection);
  RUN_TEST(test_clock_outage_does_not_invent_allocation_age);
  RUN_TEST(test_clock_outage_activity_requires_a_known_timestamp);
  RUN_TEST(test_sweep_component_cost_and_bounds);
#endif
  return UNITY_END();
}
