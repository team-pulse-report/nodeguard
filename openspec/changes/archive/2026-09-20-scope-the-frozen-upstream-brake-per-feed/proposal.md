# Scope the frozen-upstream brake per feed

## Why

One global `FEEDS_MAX_STALE_S=1209600` (14 days) is applied to every feed
regardless of how often that feed's publisher actually changes it, and on a
slow-moving feed it fails every run once the publisher pauses.

`spamhaus_drop_v6` is a 92-entry list of IPv6 netblocks that Spamhaus itself
updates only when the underlying listings change. Measured over the 4.8 years
of a third-party mirror that polled hourly and committed only on a content
change (2019-05-17 to 2024-02-25, 82 content changes, 81 intervals): mean
interval 21.5 days, median 9, p75 30, p90 54, p95 93, longest 111. Thirty of
those 81 intervals, 37 percent, exceed the 14-day threshold. The brake is set
below the feed's own mean change interval, so it is not detecting an
anomaly; it fires on the feed's ordinary behaviour.

Observed live on both gateways on 2026-09-20: `nodeguard-feeds.service` has
been failing on every 6-hour cycle since 2026-09-18, on `gateway-home` since
its 2026-09-19 boot and on `gateway-office` continuously, with
`feeds: FAILED spamhaus_drop_v6: upstream frozen past 1209600s; entries
decay`. The feed itself is healthy: it fetched 200 OK and parsed 92 records
in the same run, and its content last changed on 2026-09-04, 16 days earlier.

`spamhaus_drop_v4` carries 1712 entries and changes every few days, so it
never approaches the threshold. The brake is therefore calibrated to how
volatile a feed is rather than to the risk that its publisher has died, and
the feed it fails is the one that legitimately has nothing new to say.

The consequence is not only a red unit. A FAILED feed performs zero
withdrawals and gets no TTL re-stamp, so `spamhaus_drop_v6`'s entries decay
out of the block map while the publisher is alive and the data is current.
The unit also fails as a whole, which masks a genuine failure of either
other feed behind an alarm that is already red for a benign reason.

## What Changes

- A per-feed frozen-upstream threshold overrides the global default, so a
  feed whose publisher legitimately pauses for weeks can be given a
  threshold that matches its measured cadence while every other feed keeps
  the conservative default.
- The FAILED message names the threshold that was actually applied, so an
  operator reading it can tell a tuned feed that has genuinely gone dark
  from a feed that was never tuned.
- The global default is unchanged at 14 days. Feeds that do not declare an
  override behave exactly as they do today.

## Impact

- Affected code: `bin/nodeguard-feeds` (config defaults, the frozen-upstream
  brake, the FAILED message), `hosts/example-gateway/feeds.conf`.
- Affected specs: `feed-loading`.
- No map-format, unit, or template change. Feed state, journal, and kv keys
  keep their meaning.
- Rollout is a human follow-up: deploy the loader to both gateways and set
  `FEEDS_MAX_STALE_S_SPAMHAUS_DROP_V6` in each host's `feeds.conf`. No
  interactive confirm is needed, because unlike the churn brake this path
  holds nothing for an operator to accept; the feed simply stops failing and
  resumes normal refresh on its next cycle.

## Out of scope

- Replacing the content-digest staleness signal with the publisher's own
  metadata timestamp. Both Spamhaus DROP bodies carry a `timestamp` field
  that advances on every regeneration even when the entry list does not, so
  it distinguishes "publisher paused" from "server wedged" far better than a
  body digest can. That is a better instrument and a larger change; it is
  recorded as a roadmap item rather than smuggled in here.
- Changing what the brake does when it trips, the fetch-failure path, or the
  double interactive gate that governs enforcement.
- Any heuristic that scales the threshold by feed size or entry count. An
  explicit per-feed number is auditable; a heuristic would silently extend
  the threshold for exactly the small feeds where a wedged publisher is
  cheapest to miss.
