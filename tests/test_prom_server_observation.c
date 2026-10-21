#if defined(TURN_NO_PROMETHEUS)
#include <unity.h>
void setUp(void) {}
void tearDown(void) {}
static void test_exporter_compiled_out(void) { TEST_IGNORE_MESSAGE("exporter is compiled out"); }
int main(void) {
  UNITY_BEGIN();
  RUN_TEST(test_exporter_compiled_out);
  return UNITY_END();
}
#else
/* SPDX-License-Identifier: BSD-3-Clause */
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unity.h>

/* Track actual client allocations, including realloc's temporary old+new peak. */
static struct {
  void *pointer;
  size_t size;
} turn_test_allocations[8192];
static size_t turn_test_retained, turn_test_peak;
static pthread_mutex_t turn_test_heap_lock = PTHREAD_MUTEX_INITIALIZER;
static void turn_test_account(void *pointer, size_t size) {
  if (!pointer) {
    return;
  }
  for (size_t i = 0; i < 8192; ++i) {
    if (!turn_test_allocations[i].pointer) {
      turn_test_allocations[i].pointer = pointer;
      turn_test_allocations[i].size = size;
      turn_test_retained += size;
      if (turn_test_retained > turn_test_peak) {
        turn_test_peak = turn_test_retained;
      }
      return;
    }
  }
  abort();
}
static void *turn_test_malloc(size_t size) {
  void *pointer = malloc(size);
  pthread_mutex_lock(&turn_test_heap_lock);
  turn_test_account(pointer, size);
  pthread_mutex_unlock(&turn_test_heap_lock);
  return pointer;
}
static void *turn_test_calloc(size_t count, size_t size) {
  void *pointer = calloc(count, size);
  pthread_mutex_lock(&turn_test_heap_lock);
  turn_test_account(pointer, count * size);
  pthread_mutex_unlock(&turn_test_heap_lock);
  return pointer;
}
static void turn_test_free(void *pointer) {
  pthread_mutex_lock(&turn_test_heap_lock);
  for (size_t i = 0; pointer && i < 8192; ++i) {
    if (turn_test_allocations[i].pointer == pointer) {
      turn_test_retained -= turn_test_allocations[i].size;
      turn_test_allocations[i].pointer = NULL;
      break;
    }
  }
  pthread_mutex_unlock(&turn_test_heap_lock);
  free(pointer);
}
static void *turn_test_realloc(void *pointer, size_t size) {
  if (!pointer) {
    return turn_test_malloc(size);
  }
  pthread_mutex_lock(&turn_test_heap_lock);
  size_t old_size = 0;
  for (size_t i = 0; i < 8192; ++i) {
    if (turn_test_allocations[i].pointer == pointer) {
      old_size = turn_test_allocations[i].size;
      break;
    }
  }
  pthread_mutex_unlock(&turn_test_heap_lock);
  void *replacement = turn_test_malloc(size);
  if (!replacement) {
    return NULL;
  }
  memcpy(replacement, pointer, old_size < size ? old_size : size);
  turn_test_free(pointer);
  return replacement;
}
#define malloc turn_test_malloc
#define calloc turn_test_calloc
#define realloc turn_test_realloc
#define free turn_test_free
#include "../src/prometheus/prom.c"
#undef malloc
#undef calloc
#undef realloc
#undef free
static size_t turn_test_counter_calls, turn_test_zero_counter_calls;
static size_t turn_test_activity_calls, turn_test_zero_activity_calls;
static int turn_test_counter_add(prom_counter_t *counter, double delta, const char **labels) {
  ++turn_test_counter_calls;
  turn_test_zero_counter_calls += delta == 0;
  return prom_counter_add(counter, delta, labels);
}
#define prom_counter_add turn_test_counter_add
static int turn_test_gauge_set(prom_gauge_t *gauge, double value, const char **labels);
#define prom_gauge_set turn_test_gauge_set
#include "prom_server.c"
#undef prom_counter_add
#undef prom_gauge_set
static int turn_test_gauge_set(prom_gauge_t *gauge, double value, const char **labels) {
  if (gauge == turn_observe_activity_metric) {
    ++turn_test_activity_calls;
    turn_test_zero_activity_calls += value == 0;
  }
  return prom_gauge_set(gauge, value, labels);
}

turn_params_t turn_params;
const char *socket_type_name(SOCKET_TYPE type) {
  (void)type;
  return "fixture";
}
uint32_t ratelimit_get_collisions(void) { return 0; }
uint32_t ratelimit_count_occupied(void) { return 0; }
uint32_t ratelimit_get_capacity(void) { return 1; }

void setUp(void) {}
void tearDown(void) {}
static int turn_test_quota(const char *realm, turn_observe_quota *out) {
  (void)realm;
  *out = (turn_observe_quota){0, 0, 0, true};
  return 1;
}

static size_t turn_test_sample_count(const char *body) {
  size_t count = 0;
  for (const char *line = body; *line;) {
    if (*line != '#') {
      ++count;
    }
    const char *next = strchr(line, '\n');
    if (!next) {
      break;
    }
    line = next + 1;
  }
  return count;
}
static void *turn_test_scraper(void *argument) {
  (void)argument;
  for (unsigned i = 0; i < 10; ++i) {
    char *body = turn_prometheus_bridge();
    if (!body || !strstr(body, "turn_allocations_created_total")) {
      abort();
    }
    turn_test_free(body);
  }
  return NULL;
}
static void test_actual_exporter_bounds_and_concurrent_render(void) {
  for (unsigned r = 0; r < 16; ++r) {
    char realm[STUN_MAX_REALM_SIZE + 1] = {0};
    memset(realm, '\\', sizeof(realm) - 1);
    realm[0] = (char)('a' + r);
    realm[1] = '"';
    realm[sizeof(realm) - 1] = 0;
    TEST_ASSERT_TRUE(turn_observe_add_realm(realm));
  }
  turn_observe_start("unused", true, turn_test_quota);
  turn_observe_owner *owner = turn_observe_owner_new();
  turn_observe_publish(owner, 1000);
  prom_collector_registry_default_init();
  const size_t before = turn_test_retained;
  turn_test_counter_calls = turn_test_zero_counter_calls = 0;
  turn_test_activity_calls = turn_test_zero_activity_calls = 0;
  turn_observe_metrics_init();
  TEST_ASSERT_EQUAL_size_t(320, turn_test_counter_calls);
  TEST_ASSERT_EQUAL_size_t(320, turn_test_zero_counter_calls);
  TEST_ASSERT_EQUAL_size_t(144, turn_test_activity_calls);
  TEST_ASSERT_EQUAL_size_t(144, turn_test_zero_activity_calls);
  const size_t collector = turn_test_retained - before;
  char *body = prom_collector_registry_bridge(PROM_COLLECTOR_REGISTRY_DEFAULT);
  TEST_ASSERT_NOT_NULL(body);
  TEST_ASSERT_EQUAL(513, turn_test_sample_count(body));
  const size_t new_text = strlen(body);
  TEST_ASSERT_LESS_OR_EQUAL(1024 * 1024, new_text);
  turn_test_free(body);
  TEST_ASSERT_LESS_OR_EQUAL(2 * 1024 * 1024, collector + sizeof(turn_observe_last_export));
  /* One old family gives a measured L; the same formatter renders the entire body. */
  prom_counter_t *old =
      prom_collector_registry_must_register_metric(prom_counter_new("old_fixture", "Old data", 0, NULL));
  prom_counter_add(old, 1, NULL);
  char *with_old = prom_collector_registry_bridge(PROM_COLLECTOR_REGISTRY_DEFAULT);
  const size_t old_text = strlen(with_old) - new_text;
  turn_test_free(with_old);
  const size_t heap_before_bodies = turn_test_retained;
  turn_test_peak = turn_test_retained;
  char *bodies[8] = {0};
  for (size_t i = 0; i < 8; ++i) {
    bodies[i] = prom_collector_registry_bridge(PROM_COLLECTOR_REGISTRY_DEFAULT);
    TEST_ASSERT_NOT_NULL(bodies[i]);
  }
  const size_t retained_bodies = turn_test_retained - heap_before_bodies;
  const size_t peak_bodies = turn_test_peak - heap_before_bodies;
  TEST_ASSERT_LESS_OR_EQUAL(16 * (old_text + 1024 * 1024), retained_bodies);
  TEST_ASSERT_LESS_OR_EQUAL(20 * (old_text + 1024 * 1024), peak_bodies);
  for (size_t i = 0; i < 8; ++i) {
    turn_test_free(bodies[i]);
  }
  TEST_ASSERT_EQUAL_size_t(heap_before_bodies, turn_test_retained);
  turn_ratelimit_hash_collisions =
      prom_collector_registry_must_register_metric(prom_counter_new("fixture_collisions", "", 0, NULL));
  turn_ratelimit_occupied_buckets =
      prom_collector_registry_must_register_metric(prom_gauge_new("fixture_occupied", "", 0, NULL));
  turn_test_counter_calls = turn_test_zero_counter_calls = 0;
  turn_test_activity_calls = 0;
  pthread_t threads[4] = {0};
  for (size_t i = 0; i < 4; ++i) {
    TEST_ASSERT_EQUAL(0, pthread_create(&threads[i], NULL, turn_test_scraper, NULL));
  }
  for (size_t i = 0; i < 4; ++i) {
    pthread_join(threads[i], NULL);
  }
  TEST_ASSERT_EQUAL_size_t(0, turn_test_counter_calls);
  TEST_ASSERT_EQUAL_size_t(0, turn_test_activity_calls);
  printf("actual exporter: collector=%zu new-text=%zu old-L=%zu retained-8-bodies=%zu peak-bodies=%zu; body heap "
         "released\n",
         collector, new_text, old_text, retained_bodies, peak_bodies);
}
static double turn_test_metric_value(prom_metric_t *metric, const char **labels) {
  for (prom_sample_t *sample = metric->samples; sample; sample = sample->next) {
    if (label_values_equal(metric, sample->label_values, labels)) {
      return sample->value;
    }
  }
  TEST_FAIL_MESSAGE("precreated metric sample missing");
  return -1;
}

static void test_counter_deltas_preserve_body_and_count_once(void) {
  char *before = turn_prometheus_bridge();
  TEST_ASSERT_NOT_NULL(before);
  const size_t sample_count = turn_test_sample_count(before);
  turn_test_counter_calls = turn_test_zero_counter_calls = 0;
  for (unsigned i = 0; i < 10; ++i) {
    char *body = turn_prometheus_bridge();
    TEST_ASSERT_NOT_NULL(body);
    TEST_ASSERT_EQUAL_STRING(before, body);
    turn_test_free(body);
  }
  turn_test_free(before);
  TEST_ASSERT_EQUAL_size_t(0, turn_test_counter_calls);

  turn_observe_owner *owner = turn_observe_owner_new();
  turn_observe_session session = {0};
  const char *realm = turn_observe_realm_name(0);
  turn_observe_bind(owner, &session, realm);
  const char *created_labels[] = {realm};
  const char *result_labels[] = {realm, "success", "none"};
  const char *closed_labels[] = {realm, "other"};
  for (unsigned batch = 1; batch <= 2; ++batch) {
    for (unsigned event = 0; event < batch; ++event) {
      turn_observe_created(owner, &session);
      turn_observe_result(owner, &session, 0);
      turn_observe_closed(owner, &session);
    }
    turn_observe_publish(owner, 1000 + batch);
    turn_test_counter_calls = turn_test_zero_counter_calls = 0;
    pthread_t threads[4] = {0};
    for (size_t i = 0; i < 4; ++i) {
      TEST_ASSERT_EQUAL(0, pthread_create(&threads[i], NULL, turn_test_scraper, NULL));
    }
    for (size_t i = 0; i < 4; ++i) {
      pthread_join(threads[i], NULL);
    }
    TEST_ASSERT_EQUAL_size_t(3, turn_test_counter_calls);
    TEST_ASSERT_EQUAL_size_t(0, turn_test_zero_counter_calls);
    const double total = batch == 1 ? 1 : 3;
    TEST_ASSERT_TRUE(total == turn_test_metric_value(turn_observe_created_metric, created_labels));
    TEST_ASSERT_TRUE(total == turn_test_metric_value(turn_observe_results_metric, result_labels));
    TEST_ASSERT_TRUE(total == turn_test_metric_value(turn_observe_closed_metric, closed_labels));
    turn_observe_metrics_refresh(false);
    TEST_ASSERT_EQUAL_size_t(3, turn_test_counter_calls);
    char *body = turn_prometheus_bridge();
    TEST_ASSERT_NOT_NULL(strstr(body, "old_fixture 1\n"));
    TEST_ASSERT_EQUAL_size_t(sample_count, turn_test_sample_count(body));
    turn_test_free(body);
  }
}

static void test_activity_changes_preserve_zeros_and_export_once(void) {
  turn_observe_owner *owner = turn_observe_owner_new();
  turn_observe_session sessions[2] = {{0}};
  const char *realm = turn_observe_realm_name(0);
  const char *labels[] = {realm, "new", "zero"};
  for (size_t i = 0; i < 2; ++i) {
    turn_observe_bind(owner, &sessions[i], realm);
    turn_observe_created(owner, &sessions[i]);
  }
  size_t sample_count = 0;
  for (int live = 2; live >= 0; --live) {
    if (live < 2) {
      turn_observe_closed(owner, &sessions[live]);
    }
    TEST_ASSERT_TRUE(turn_observe_tick_begin(owner));
    for (size_t i = 0; i < 2; ++i) {
      turn_observe_visit(owner, &sessions[i]);
    }
    turn_observe_publish(owner, 1010 + live);
    turn_test_activity_calls = turn_test_zero_activity_calls = 0;
    pthread_t threads[4] = {0};
    for (size_t i = 0; i < 4; ++i) {
      TEST_ASSERT_EQUAL(0, pthread_create(&threads[i], NULL, turn_test_scraper, NULL));
    }
    for (size_t i = 0; i < 4; ++i) {
      pthread_join(threads[i], NULL);
    }
    TEST_ASSERT_EQUAL_size_t(1, turn_test_activity_calls);
    TEST_ASSERT_EQUAL_size_t(live == 0 ? 1 : 0, turn_test_zero_activity_calls);
    TEST_ASSERT_TRUE(live == turn_test_metric_value(turn_observe_activity_metric, labels));
    char *body = turn_prometheus_bridge();
    TEST_ASSERT_NOT_NULL(body);
    TEST_ASSERT_NOT_NULL(strstr(body, "old_fixture 1\n"));
    if (!sample_count) {
      sample_count = turn_test_sample_count(body);
    }
    TEST_ASSERT_EQUAL_size_t(sample_count, turn_test_sample_count(body));
    char *again = turn_prometheus_bridge();
    TEST_ASSERT_NOT_NULL(again);
    TEST_ASSERT_EQUAL_STRING(body, again);
    TEST_ASSERT_EQUAL_size_t(1, turn_test_activity_calls);
    turn_test_free(again);
    turn_test_free(body);
  }
}

int main(void) {
  UNITY_BEGIN();
  RUN_TEST(test_actual_exporter_bounds_and_concurrent_render);
  RUN_TEST(test_counter_deltas_preserve_body_and_count_once);
  RUN_TEST(test_activity_changes_preserve_zeros_and_export_once);
  return UNITY_END();
}

#endif
