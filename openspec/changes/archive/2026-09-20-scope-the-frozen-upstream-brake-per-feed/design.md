# Design

## Why the brake fires on healthy data

The staleness clock is `last_changed_ts`, advanced only when a fetch returns
`ok` and the body digest differs from the last one recorded, seeded from the
upstream `Last-Modified` header when present. It therefore measures how long
the publisher has gone without changing the list, not whether the publisher
is reachable. Reachability already has its own failure path: a fetch that
errors fails the feed immediately and never reaches this check.

That makes the brake a detector for one narrow condition, a publisher that is
still serving but has stopped curating, and that condition is only
distinguishable from ordinary quiet by how long it lasts. The threshold is
the entire instrument, so it has to be set from each feed's measured cadence.

## Choosing the threshold for spamhaus_drop_v6

Measured from a third-party mirror that polled hourly and committed only on a
content change, over 2019-05-17 to 2024-02-25 (1745 days, 82 content changes,
81 intervals):

| statistic | days |
|---|---|
| mean | 21.5 |
| median | 9 |
| p75 | 30 |
| p90 | 54 |
| p95 | 93 |
| max | 111 |

Intervals exceeding a candidate threshold:

| threshold | intervals over it | share |
|---|---|---|
| 14 days (current global) | 30 of 81 | 37 percent |
| 30 days | 20 of 81 | 25 percent |
| 45 days | 11 of 81 | 14 percent |
| 60 days | 8 of 81 | 10 percent |
| 90 days | 4 of 81 | 5 percent |

90 days (`7776000`) is the value taken. It sits at roughly p95, so the brake
is expected to fire on about one interval in twenty rather than more than one
in three, and a publisher that has genuinely stopped is still caught inside a
quarter while its entries continue to refresh normally until then. Anything
at or below 60 days keeps the alarm ringing often enough that an operator
learns to ignore it, which is the failure mode that hid this condition on
`gateway-office` for two days.

The number is deliberately per host config rather than a new default in the
loader. The measured cadence is a property of the feed as published, but the
tolerance for a decayed v6 blocklist is a property of the deployment, and the
example config is the place a reader looks for both.

## Why not make the default smarter

A heuristic that scaled the threshold by entry count would have fixed this
case automatically, and would also have quietly extended the threshold for
every small feed added later. A small feed is precisely where a wedged
publisher costs least to miss and where an explicit, reviewed number is
cheapest to supply. The override convention already exists in this loader for
`FEEDS_MIN_`, `FEEDS_MAX_`, and `FEEDS_MAX_CHURN_PCT_`; a fourth user of it
adds no new concept.

## The better instrument, deferred

Both Spamhaus DROP bodies end with a metadata record carrying a `timestamp`
that advances on every regeneration even when the entry list is byte
identical. On 2026-09-20 `drop_v6` served a timestamp 16 days newer than its
last content change. That field separates "publisher paused" from "server
wedged" directly, which is what this brake is actually trying to ask, and it
would let the threshold be short again.

It is not taken here because it is a different signal with its own failure
modes (a publisher that stamps but never curates would read as healthy, and
the field is not present on `dshield_top20`), so it needs its own proposal
and its own tests rather than riding along with a threshold change. Recorded
as a roadmap item in `docs/design.md`.
