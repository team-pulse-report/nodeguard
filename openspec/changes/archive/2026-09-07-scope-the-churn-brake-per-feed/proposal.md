# Scope the churn brake per feed

## Why

One global `FEEDS_MAX_CHURN_PCT=30` is applied to every feed regardless of
how large or how volatile that feed is, and on a small high-rotation feed it
holds every single run.

`dshield_top20` is a 19-entry list of the currently most active attacking
networks; rotating is what it is for. Its last run moved 13 of 19 entries and
3328 of 4864 covered addresses, both 68 percent, so it trips a 30 percent
brake and will keep tripping it every day forever. Measured on both gateways
on 2026-09-07: `ng.feeds_churn_held=1` on each, with the hold first logged at
12:14 UTC, hours before anything was deployed.

`spamhaus_drop_v4` carries thousands of slow-moving entries and never comes
close to the same threshold. The brake is therefore not calibrated to risk,
it is calibrated to feed size, and the feed it disables is the one tracking
what is attacking right now.

The consequence is worse than a stuck alarm. A held feed's inserts and
withdrawals do not apply, so the two hosts have silently diverged: the
gateway still carries the entries it applied before the hold, now frozen and
ageing, while the remote node lost them at reboot and cannot reload them.
Coverage differs between hosts with nothing in the enforcement path saying
so.

## What Changes

- A per-feed churn threshold overrides the global default, so a feed whose
  normal behaviour is heavy rotation can be given a threshold that matches
  it while every other feed keeps the conservative default.
- The hold message and the exported telemetry name the threshold that was
  actually applied, so an operator reading either can tell a tuned feed from
  a defaulted one without opening the config.
- The global default is unchanged at 30 percent. Feeds that do not declare
  an override behave exactly as they do today.

## Impact

- Affected code: `bin/nodeguard-feeds` (config defaults, the churn brake,
  the hold message), `hosts/example-gateway/feeds.conf`.
- Affected specs: `feed-loading`.
- No map-format, unit, or template change. The kv key `ng.feeds_churn_held`
  keeps its meaning and its trigger.
- Rollout is a human follow-up: deploy the loader to both gateways, set the
  override for `dshield_top20`, then run the interactive confirm once per
  host to clear the standing hold and re-baseline the feed.

## Out of scope

- Clearing the current hold. That is an operator action through the existing
  `apply --feed <id> --confirm` path and is deliberately not automated here.
- Changing what the brake does when it trips, or the double interactive gate
  that governs enforcement.
- Any absolute-delta or feed-size heuristic. An explicit per-feed number is
  auditable; a heuristic that silently exempts small feeds would weaken the
  brake exactly where a total replacement is cheapest to mount.
