/* SPDX-License-Identifier: BSD-3-Clause */
#include "turn_observability.h"
#include "ns_turn_utils.h"
#include <pthread.h>
#include <string.h>
#include <time.h>
#if defined(WINDOWS)
#include <windows.h>
#endif

static char turn_observe_realms[TURN_OBSERVE_REALMS][STUN_MAX_REALM_SIZE + 1];
static size_t turn_observe_count;
static bool turn_observe_frozen;
static bool turn_observe_enabled;
static turn_observe_quota_reader turn_observe_read_quota;

struct turn_observe_owner {
  pthread_mutex_t lock;
  turn_observe_snapshot local;
  turn_observe_snapshot published;
  uint64_t now;
  bool clock_ok;
  bool ready;
  struct turn_observe_owner *next;
};
static turn_observe_owner *turn_observe_owners;
static turn_observe_owner *turn_observe_quota_owner;
static pthread_mutex_t turn_observe_owner_lock = PTHREAD_MUTEX_INITIALIZER;

_Static_assert(sizeof(turn_observe_session) <= 32, "allocation observation exceeds its budget");
_Static_assert(sizeof(turn_observe_owner) <= 16 * 1024, "worker observation exceeds its budget");

bool turn_observe_add_realm(const char *name) {
  if (turn_observe_frozen || !name || strlen(name) > STUN_MAX_REALM_SIZE) {
    return false;
  }
  for (size_t i = 0; i < turn_observe_count; ++i) {
    if (!strcmp(name, turn_observe_realms[i])) {
      return true;
    }
  }
  if (turn_observe_count == TURN_OBSERVE_REALMS) {
    return false;
  }
  strcpy(turn_observe_realms[turn_observe_count++], name);
  return true;
}

void turn_observe_start(const char *default_realm, bool enabled, turn_observe_quota_reader reader) {
  if (turn_observe_frozen) {
    return;
  }
  if (!turn_observe_count) {
    turn_observe_add_realm(default_realm);
  }
  turn_observe_read_quota = reader;
#if defined(TURN_NO_PROMETHEUS)
  (void)enabled;
#else
  turn_observe_enabled = enabled;
#endif
  turn_observe_frozen = true;
}

size_t turn_observe_realm_count(void) { return turn_observe_count; }
const char *turn_observe_realm_name(size_t index) { return turn_observe_realms[index]; }
uint8_t turn_observe_realm_index(const char *name) {
  if (turn_observe_enabled) {
    for (size_t i = 0; i < turn_observe_count; ++i) {
      if (!strcmp(name, turn_observe_realms[i])) {
        return (uint8_t)(i + 1);
      }
    }
  }
  return 0;
}

static bool turn_observe_monotonic(uint64_t *seconds) {
#if defined(WINDOWS)
  *seconds = GetTickCount64() / 1000;
  return true;
#else
  struct timespec ts = {0};
  if (clock_gettime(CLOCK_MONOTONIC, &ts)) {
    return false;
  }
  *seconds = (uint64_t)ts.tv_sec;
  return true;
#endif
}

turn_observe_owner *turn_observe_owner_new(void) {
  if (!turn_observe_enabled) {
    return NULL;
  }
  turn_observe_owner *owner = turn_calloc(1, sizeof(*owner));
  if (pthread_mutex_init(&owner->lock, NULL)) {
    abort();
  }
  owner->clock_ok = turn_observe_monotonic(&owner->now);
  owner->ready = owner->clock_ok;
  pthread_mutex_lock(&turn_observe_owner_lock);
  owner->next = turn_observe_owners;
  turn_observe_owners = owner;
  if (!turn_observe_quota_owner) {
    turn_observe_quota_owner = owner;
  }
  pthread_mutex_unlock(&turn_observe_owner_lock);
  return owner;
}

void turn_observe_bind(turn_observe_owner *owner, turn_observe_session *session, const char *realm) {
  if (owner) {
    session->realm = turn_observe_realm_index(realm);
  }
}

void turn_observe_created(turn_observe_owner *owner, turn_observe_session *session) {
  if (owner && !session->active) {
    session->active = 1;
    session->created = session->last_data = owner->clock_ok ? owner->now : UINT64_MAX;
    session->timer_reason[0] = session->timer_reason[1] = TURN_CLOSE_EXPIRED;
    session->close_reason = TURN_CLOSE_OTHER;
    if (session->realm) {
      ++owner->local.realm[session->realm - 1].created;
    }
  }
}

void turn_observe_closed(turn_observe_owner *owner, turn_observe_session *session) {
  if (owner && session->active) {
    if (session->realm) {
      ++owner->local.realm[session->realm - 1].closed[session->close_reason];
    }
    session->active = 0;
  }
}

void turn_observe_data(turn_observe_owner *owner, turn_observe_session *session, size_t bytes) {
  if (owner && session->active) {
    session->last_data = owner->clock_ok ? owner->now : UINT64_MAX;
    const uint32_t remaining = 65537 - session->bytes;
    session->bytes += bytes >= remaining ? remaining : (uint32_t)bytes;
  }
}

void turn_observe_result(turn_observe_owner *owner, const turn_observe_session *session, int code) {
  if (!owner || !session->realm || code == 401 || code == 438) {
    return;
  }
  static const int codes[] = {0, 300, 400, 403, 420, 437, 440, 441, 442, 443};
  size_t index = 15;
  for (size_t i = 0; i < sizeof(codes) / sizeof(*codes); ++i) {
    if (code == codes[i]) {
      index = i;
      break;
    }
  }
  if (code == 486) {
    index = session->quota_cause == TURN_QUOTA_TOTAL       ? 10
            : session->quota_cause == TURN_QUOTA_USER      ? 11
            : session->quota_cause == TURN_QUOTA_BANDWIDTH ? 12
                                                           : 13;
  } else if (code == 508) {
    index = 14;
  }
  ++owner->local.realm[session->realm - 1].results[index];
}

bool turn_observe_tick_begin(turn_observe_owner *owner) {
  if (!owner) {
    return false;
  }
  owner->clock_ok = turn_observe_monotonic(&owner->now);
  owner->ready = owner->clock_ok;
  if (owner->clock_ok) {
    for (size_t i = 0; i < turn_observe_count; ++i) {
      memset(owner->local.realm[i].bins, 0, sizeof(owner->local.realm[i].bins));
    }
  }
  return owner->clock_ok;
}

void turn_observe_visit(turn_observe_owner *owner, const turn_observe_session *session) {
  if (owner && owner->clock_ok && session->active && session->realm) {
    if (session->created == UINT64_MAX || session->last_data == UINT64_MAX) {
      owner->ready = false;
      return;
    }
    const size_t activity = owner->now - session->created < 60 ? 0 : owner->now - session->last_data >= 60 ? 1 : 2;
    const size_t bytes = !session->bytes ? 0 : session->bytes <= 65536 ? 1 : 2;
    ++owner->local.realm[session->realm - 1].bins[activity * 3 + bytes];
  }
}

void turn_observe_publish(turn_observe_owner *owner, uint64_t unix_time) {
  if (!owner || !owner->clock_ok || !owner->ready) {
    return;
  }
  if (owner == turn_observe_quota_owner && turn_observe_read_quota) {
    turn_observe_quota quota[TURN_OBSERVE_REALMS] = {0};
    bool ready = true;
    bool busy = false;
    for (size_t i = 0; i < turn_observe_count; ++i) {
      const int result = turn_observe_read_quota(turn_observe_realms[i], &quota[i]);
      busy |= result < 0;
      ready &= result > 0;
    }
    if (!busy) {
      memcpy(owner->local.quota, quota, sizeof(quota));
      owner->local.quota_timestamp = ready ? unix_time : 0;
    }
  }
  if (!pthread_mutex_trylock(&owner->lock)) {
    owner->local.timestamp = unix_time;
    owner->published = owner->local;
    pthread_mutex_unlock(&owner->lock);
  }
}

void turn_observe_collect(turn_observe_snapshot *out) {
  memset(out, 0, sizeof(*out));
  pthread_mutex_lock(&turn_observe_owner_lock);
  bool first = true;
  for (turn_observe_owner *owner = turn_observe_owners; owner; owner = owner->next) {
    turn_observe_snapshot copy = {0};
    pthread_mutex_lock(&owner->lock);
    copy = owner->published;
    pthread_mutex_unlock(&owner->lock);
    if (first || copy.timestamp < out->timestamp) {
      out->timestamp = copy.timestamp;
    }
    first = false;
    for (size_t r = 0; r < turn_observe_count; ++r) {
      for (size_t j = 0; j < TURN_OBSERVE_RESULTS; ++j) {
        out->realm[r].results[j] += copy.realm[r].results[j];
      }
      out->realm[r].created += copy.realm[r].created;
      for (size_t j = 0; j < 3; ++j) {
        out->realm[r].closed[j] += copy.realm[r].closed[j];
      }
      for (size_t j = 0; j < TURN_OBSERVE_BINS; ++j) {
        out->realm[r].bins[j] += copy.realm[r].bins[j];
      }
    }
    if (owner == turn_observe_quota_owner) {
      memcpy(out->quota, copy.quota, sizeof(out->quota));
      out->quota_timestamp = copy.quota_timestamp;
    }
  }
  if (out->quota_timestamp < out->timestamp) {
    out->timestamp = out->quota_timestamp;
  }
  pthread_mutex_unlock(&turn_observe_owner_lock);
}
