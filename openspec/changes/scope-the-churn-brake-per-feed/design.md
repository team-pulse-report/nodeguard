# Design: scope the churn brake per feed

## 1. What the brake is for, and why a percentage stops serving it

The churn brake exists to catch a feed whose composition changed so far from
its last applied set that the change itself is the warning: an upstream
compromise, a truncated or substituted body that passed the parser, a
publisher who repurposed a list. It holds inserts and withdrawals and waits
for a human, which is the right response to that class of event.

A percentage measures that well on a large baseline, where normal daily
movement is a small fraction of the set. It measures nothing useful on a
small one. With 19 baseline entries, six changing is 31.6 percent, so the
brake fires on ordinary movement and keeps firing. The statistic has no
resolution at that size, and no single global number can serve both a
19-entry rotating list and a several-thousand-entry allocation list.

## 2. Evidence

Measured on both gateways, 2026-09-07:

```
CHURN-HELD dshield_top20: entry delta 13 or coverage delta 3328
exceeds 30 percent of baseline (19 entries, 4864 coverage)
SUMMARY dshield_top20: ENFORCE CHURN-HELD insert=0 refresh=0 withdraw=0 skip=0
```

Both arms are at 68 percent, over twice the threshold. The hold was already
present at 12:14 UTC, well before that day's deploy, so it is the steady
state of this feed rather than a transient. `ng.feeds_churn_held=1` on both
hosts.

The divergence it caused is the part worth keeping in view. The gateway
reports 1782 map entries and the remote node 1763; the difference is exactly
`dshield_top20`'s 19 entries. The gateway holds what it applied before the
brake latched and cannot refresh it, and the remote node lost its copy when
bpffs cleared at reboot and cannot reload it. Same configuration, same
loader, different enforcement, and nothing in the datapath says so.

## 3. Decision: an explicit per-feed number

`FEEDS_MAX_CHURN_PCT` stays the default for every feed. A feed may override
it with `FEEDS_MAX_CHURN_PCT_<FEED_ID>`, the feed id uppercased with the same
underscores it already uses (`dshield_top20` gives
`FEEDS_MAX_CHURN_PCT_DSHIELD_TOP20`). The lookup is the override if present,
otherwise the global.

Rejected: exempting feeds below some entry count, or switching to an absolute
delta under that size. Both are heuristics that decide on the operator's
behalf, and both weaken the brake precisely where a total replacement is
cheapest to mount: swapping all 19 entries of a small feed is a realistic
attack, and a size-based exemption would wave it through. An explicit number
per feed keeps the decision where it belongs, in reviewed configuration, and
leaves it visible in a diff.

The value is validated on load like the other integer settings.

One correction worth recording, because it changes what a sensible override
looks like. The metric is the symmetric difference over the baseline size, so
every key removed AND every key added counts: swapping 7 of 10 entries is 14
over 10, or 140 percent, and a total replacement is 200 percent, not 100. The
global 30 is therefore tighter than it reads, and a feed like `dshield_top20`
moving 13 of 19 entries scores about 137 percent. A useful override for a
rotating feed is above 100, and 200 or more disables the brake for that feed
entirely. This was caught by the first test written against the change, which
asserted that 100 would pass a wholly replaced feed and failed.

## 4. Where it lands

The brake reads one global today (`bin/nodeguard-feeds`, the `pct` binding
just above the per-feed loop). The change moves that read inside the loop so
each feed resolves its own threshold, and carries the resolved number into
the hold message. Nothing else in the loop changes: both arms, the symmetric
difference, the coverage comparison, the `accepted` bypass and the
`enforcing` check all keep their current behaviour.

Telemetry: `ng.feeds_churn_held` keeps its meaning, so the existing WARNING
trigger is untouched. The hold line gains the applied threshold, which is
what an operator needs to tell "this feed is tuned and still moved too far"
from "this feed was never tuned".

## 5. Cross-change note

This does not clear the standing hold on either host. Clearing it is the
existing `apply --feed dshield_top20 --confirm` path, which shows the pending
diff, records the approval, and re-baselines on the next successful run. That
stays a human action: the brake's entire value is that a person looked.
