/* SPDX-License-Identifier: BSD-3-Clause */
#ifndef TURN_OBSERVABILITY_H
#define TURN_OBSERVABILITY_H

#include "ns_turn_defs.h"
#include "ns_turn_msg_defs.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define TURN_OBSERVE_REALMS 16
#define TURN_OBSERVE_RESULTS 16
#define TURN_OBSERVE_BINS 9

typedef enum { TURN_QUOTA_OTHER, TURN_QUOTA_TOTAL, TURN_QUOTA_USER, TURN_QUOTA_BANDWIDTH } turn_quota_cause;

typedef enum { TURN_CLOSE_DELETE, TURN_CLOSE_EXPIRED, TURN_CLOSE_OTHER } turn_close_reason;

typedef struct {
  uint64_t created;
  uint64_t last_data;
  uint32_t bytes;
  uint8_t realm;  /* zero means outside the immutable coverage set */
  uint8_t active; /* logical allocation lifetime, including time outside coverage */
  uint8_t timer_reason[2];
  uint8_t close_reason;
  uint8_t quota_cause;
} turn_observe_session;

typedef struct {
  uint64_t results[TURN_OBSERVE_RESULTS];
  uint64_t created;
  uint64_t closed[3];
  uint64_t bins[TURN_OBSERVE_BINS];
} turn_observe_counts;

typedef struct {
  uint64_t used;
  uint64_t total;
  uint64_t user;
  bool known;
} turn_observe_quota;

typedef struct {
  turn_observe_counts realm[TURN_OBSERVE_REALMS];
  turn_observe_quota quota[TURN_OBSERVE_REALMS];
  uint64_t timestamp;
  uint64_t quota_timestamp;
} turn_observe_snapshot;

typedef struct turn_observe_owner turn_observe_owner;
/* 1 = existing consistent snapshot; 0 = unknown realm; -1 = busy. */
typedef int (*turn_observe_quota_reader)(const char *, turn_observe_quota *);

bool turn_observe_add_realm(const char *name);
void turn_observe_start(const char *default_realm, bool enabled, turn_observe_quota_reader read_quota);
size_t turn_observe_realm_count(void);
const char *turn_observe_realm_name(size_t index);
uint8_t turn_observe_realm_index(const char *name);
turn_observe_owner *turn_observe_owner_new(void);
void turn_observe_bind(turn_observe_owner *owner, turn_observe_session *session, const char *realm);
void turn_observe_created(turn_observe_owner *owner, turn_observe_session *session);
void turn_observe_closed(turn_observe_owner *owner, turn_observe_session *session);
void turn_observe_data(turn_observe_owner *owner, turn_observe_session *session, size_t bytes);
void turn_observe_result(turn_observe_owner *owner, const turn_observe_session *session, int code);
bool turn_observe_tick_begin(turn_observe_owner *owner);
void turn_observe_visit(turn_observe_owner *owner, const turn_observe_session *session);
void turn_observe_publish(turn_observe_owner *owner, uint64_t unix_time);
void turn_observe_collect(turn_observe_snapshot *out);

#ifdef __cplusplus
}
#endif

#endif
