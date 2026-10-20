# Prometheus setup

coturn exposes a Prometheus metrics endpoint (default `:9641/metrics`) when
started with `--prometheus`.

## Vendored Prometheus client

coturn ships a minimal, self-contained Prometheus client under
[`src/prometheus`](../src/prometheus) and builds it straight from those
sources.

The vendored client implements the slice of the API coturn uses —
counters, gauges, a single default registry, and the text-exposition
serializer. Histograms, summaries, custom registries and a bundled HTTP
handler are out of scope; coturn serves the endpoint with its own
libmicrohttpd handler in
[`src/apps/relay/prom_server.c`](../src/apps/relay/prom_server.c).

The exporter's only external dependency is **libmicrohttpd**.

## Install libmicrohttpd

### Ubuntu / Debian

```
sudo apt install libmicrohttpd-dev
```

### macOS (Homebrew)

```
brew install libmicrohttpd
```

### From source

[libmicrohttpd](https://www.gnu.org/software/libmicrohttpd/) — download from
https://git.gnunet.org/libmicrohttpd.git

```
git clone https://git.gnunet.org/libmicrohttpd.git
cd libmicrohttpd
./autogen.sh
./configure --prefix=`pwd`/install --disable-doc --disable-examples \
    --disable-tools
make install
```

## Build

The exporter is always compiled in; libmicrohttpd is a required build
dependency (provided by vcpkg on Windows). The runtime `--prometheus` flag
controls whether it is started. To point CMake at a non-standard libmicrohttpd
install prefix, set `MicroHTTPD_ROOT`:

```
cmake -S . -B build -DMicroHTTPD_ROOT=/path/to/libmicrohttpd/install
cmake --build build
```

The exporter is always compiled in (libmicrohttpd is a required build
dependency); the runtime `--prometheus` flag controls whether it is started.

## HTTPS (optional)

By default the metrics endpoint is served over plain HTTP. To serve it over
HTTPS instead, pass `--prometheus-tls` (requires libmicrohttpd built with TLS
support). `--prometheus-tls` implies `--prometheus`, so it enables the exporter
on its own — there is no need to pass both. The certificate and key default to
the server's own `--cert` / `--pkey`; override them with `--prometheus-cert` /
`--prometheus-key`:

```
# Reuse the server's TLS material:
turnserver --prometheus-tls --cert server.pem --pkey server.key

# Or use a dedicated certificate for the metrics endpoint:
turnserver --prometheus-tls \
    --prometheus-cert metrics.pem --prometheus-key metrics.key
```

Then scrape with `https://<host>:9641/metrics`. If `--prometheus-tls` is set
but no certificate/key can be loaded, the exporter logs an error and does not
start.

## UDP 401 mitigation metrics

When the optional UDP 401 response rate limit is enabled, use:

```
unauthorized-ratelimit
unauthorized-ratelimit-rps=10
prometheus
```

The rate limit is disabled by default. It applies only to UDP `401 Unauthorized`
responses, which can otherwise be used in spoofed-source reflection attacks.

When Prometheus is enabled, the exporter provides the following counters for
this path whether or not mitigation is enabled. The dropped response counter
increments only when `unauthorized-ratelimit` suppresses responses.

| Metric | Type | Meaning |
|---|---|---|
| `turn_unauthenticated_401_requests` | counter | UDP requests requiring a `401 Unauthorized` response. |
| `turn_unauthenticated_401_responses` | counter | UDP `401 Unauthorized` responses emitted. |
| `turn_unauthenticated_401_dropped_responses` | counter | UDP `401` responses suppressed by the rate limit. |

The rate-limit hash table is also instrumented. These values are computed
lazily when Prometheus scrapes `/metrics`, so they add no cost to the hot path:

| Metric | Type | Meaning |
|---|---|---|
| `turn_ratelimit_hash_collisions` | counter | Requests whose source hashed to a bucket already owned by a different live address (distinct sources sharing a budget — the mitigation's false-positive surface). |
| `turn_ratelimit_occupied_buckets` | gauge | Buckets currently holding a live (non-expired) window. |
| `turn_ratelimit_total_buckets` | gauge | Table capacity in buckets. |

`turn_ratelimit_occupied_buckets / turn_ratelimit_total_buckets` is the table
load factor; a sustained high ratio or a climbing `turn_ratelimit_hash_collisions`
rate means distinct attackers are colliding into shared buckets. See
[docs/401-ratelimit.md](401-ratelimit.md) for the full design.

## Allocation capacity and activity

`--prometheus-observe-realm=NAME` selects exact realms (repeatable, up to 16
unique names of at most 763 bytes). Without it, only the final default realm is
observed. Duplicates are ignored. Invalid lists fail before listeners start.
Selection is fixed until restart, including across realm-limit reloads.

Other realms are excluded. A configured but nonexistent realm has zero event
and activity samples, no quota samples and an unready snapshot. Telemetry does
not create realms or derive labels from client-supplied values.

| Metric | Type | Labels and meaning |
|---|---|---|
| `turn_quota_used` | gauge | `realm`: acquired quota units, including before relay creation |
| `turn_quota_limit` | gauge | `realm,scope`: effective `total` and per-normalized-`user` limits, 0 = unlimited |
| `turn_allocate_results_total` | counter | `realm,code,cause`: final ALLOCATE responses prepared for transmission |
| `turn_allocations_created_total` | counter | `realm`: successful logical allocations |
| `turn_allocations_closed_total` | counter | `realm,reason`: final removal (`client_delete`, `expired`, `other`) |
| `turn_allocations_by_activity` | gauge | `realm,activity,peer_bytes`: live allocations in nine bins |
| `turn_observability_snapshot_timestamp_seconds` | gauge | no labels: oldest required producer publication, Unix seconds, 0 = not ready |

### Results and activity

Allowed `(code,cause)` pairs are `(success,none)`, `(508,capacity)`,
`(486,total_quota)`, `(486,user_quota)`, `(486,bandwidth_quota)`, `(486,other)`,
and codes 300, 400, 403, 420, 437, 440, 441, 442, 443 with cause `other`.
Unknown errors use `(other,other)`. Responses 401/438 are excluded.
Quota causes reflect the admission decision. Asynchronous authentication counts
its final response once. Retransmissions producing another response count again:
these are responses, not unique users or confirmed deliveries.

Lifecycle counters count logical allocations, regardless of address families,
relay sockets or quota units. REFRESH and mobility do not create another lifecycle.
The final endpoint's removal determines the close reason. Transport and
administrative teardown use `other`.

Events use the server-selected realm at event time. After an OAuth realm change,
activity and subsequent events follow the new realm without synthetic lifecycle
events. Thus created minus closed is not per-realm occupancy. Age and payload
state survive time outside observed realms, including allocations created there.

| Label | Values |
|---|---|
| `activity` | `new`: age <60 s. `quiet`: age ≥60 s and no accepted data for ≥60 s. `recent`: otherwise. Before first data, activity age starts at creation. |
| `peer_bytes` | Lifetime payload in both directions: `zero` = 0, `le_64k` = 1–65536, `gt_64k` = 65537+, including transfers above 4 GiB. |

Payload counts after forwarding and bandwidth checks, excluding framing,
padding, control messages and forbidden packets. Queue admission counts even if
delivery later fails. TCP congestion rejection, TLS shutdown and full DTLS
backlogs do not count. Direct UDP retains best-effort admission for nonnegative
send results, including handled send errors. Metrics cannot identify games,
torrents or useful traffic.

The new families add at most `32 * R + 1` series: 33 for one realm, 513 for 16.
Event/activity samples start at zero. Existing metrics and their semantics are
unchanged. Optional username labels remain separately unbounded and disabled by
default. Counters reset on restart. Gauges converge within two one-second sweeps
after changes stop. Failed publication retains old values and timestamps.

### Queries

Require `up{job="turn"} == 1` and fresh data. For 15-second scrapes and one-second
evaluation, allow samples up to 30 seconds old and producer lag up to 5 seconds:

```promql
(turn_observability_snapshot_timestamp_seconds > bool 0)
* on(job,instance)
(time() - timestamp(turn_observability_snapshot_timestamp_seconds) >= bool 0)
* on(job,instance)
(time() - timestamp(turn_observability_snapshot_timestamp_seconds) <= bool 30)
* on(job,instance)
(abs(timestamp(turn_observability_snapshot_timestamp_seconds)
     - turn_observability_snapshot_timestamp_seconds) <= bool 5)
```

Adjust sample age for other scrape intervals and synchronize clocks. The lag
check also rejects future producer timestamps. A successful scrape alone does
not prove freshness.

Check all six families and the timestamp per target. Global `absent(metric)`
can hide a missing target. Example:

```promql
(up{job="turn"} == 1)
unless on(job,instance)
count by(job,instance) (turn_allocations_created_total)
```

Quota occupancy, for positive total limits only:

```promql
(100 * turn_quota_used
 / on(job,instance,realm) turn_quota_limit{scope="total"})
and on(job,instance,realm) (turn_quota_limit{scope="total"} > 0)
```

Keep realms separate and do not substitute per-user limits. Missing quota does
not mean unlimited. Add identity labels to vector matching if `job,instance`
is not unique.

Calculate rates before aggregation to handle counter resets. ALLOCATE responses
per second, using a one-minute window for 15-second scrapes:

```promql
sum by(job,instance,realm) (rate(turn_allocate_results_total[1m]))
```

Refusal ratio, absent when there are no attempts:

```promql
(sum by(job,instance,realm)
  (rate(turn_allocate_results_total{code!="success"}[1m]))
 / sum by(job,instance,realm) (rate(turn_allocate_results_total[1m])))
and on(job,instance,realm)
(sum by(job,instance,realm) (rate(turn_allocate_results_total[1m])) > 0)
```

Keep authentication failures separate. Display unsupported binaries, failed
scrapes, stale data and unknown realms distinctly. Never replace missing data
with zero.

### Exporter limits

HTTP and HTTPS allow eight concurrent connections with a ten-second idle timeout.
Extra clients may wait or be disconnected, without a guaranteed HTTP error.
Active slow readers can hold slots indefinitely, so restrict endpoint access.
These limits do not affect TURN listeners.

Collector storage is bounded by 32 bytes/session, 16 KiB/worker and 2 MiB fixed
state. New serialized families use at most 1 MiB, including escaped names.
With `L` bytes of existing metrics, eight response bodies use at most
`16 * (L + 1 MiB)`, or `20 * (L + 1 MiB)` during formatter reallocation.
Bodies are freed after responses. These bounds exclude library, TLS, kernel and
existing dynamic-metric memory, so they are not total RSS limits.

Disabled Prometheus collection, including `TURN_NO_PROMETHEUS` builds, keeps no
new state. Packet handling adds no clock syscalls, heap allocations or shared
telemetry locks. Snapshot publication does not block workers.
