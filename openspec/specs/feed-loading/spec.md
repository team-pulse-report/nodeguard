# feed-loading Specification

## Purpose
Load reputable threat-intel CIDR feeds (Spamhaus DROP v4/v6, DShield
top-20) into nodeguard's block maps on a TTL that fails open by expiry, so
a stale or unreachable feed withdraws nothing and simply decays toward no
enforcement. This capability defines how feeds are fetched, validated, and
gated (entry-count, aggregate-coverage, churn, and staleness brakes, plus
the double activation gate of `FEEDS_APPLY` config and an interactive
`apply --confirm`), how ownership is tracked through a journaled
content-addressed store so the loader never withdraws entries written by
the responder or an operator, and how its state is exported for monitoring.
It exists to widen coverage against known-bad sources without adding a
second failure mode to the datapath.

## Requirements

### Requirement: Feed source selection SHALL exclude allocation-status lists
The loader SHALL consume only curated attacker-reputation feeds fetched
directly from their publishers, and SHALL NOT consume aggregate lists
whose composition includes allocation-status entries (bogons, RFC1918,
CGNAT), independently of downstream guards.

#### Scenario: firehol level1 is never fetched
- WHEN the loader configuration is inspected
- THEN no configured source resolves to an aggregate containing bogon or
  private address space, and the never-block guards remain as defense in
  depth rather than the primary control

### Requirement: Every failure SHALL decay to no enforcement
Feed entries SHALL carry an absolute in-kernel TTL such that a dead
timer, unreachable upstream, invalid download, or wedged host results in
all feed-driven enforcement expiring without any component running.

#### Scenario: upstream outage
- WHEN every fetch of a feed fails for longer than the TTL window
- THEN that feed's entries expire in-kernel and monitoring has raised
  per-feed staleness alerts before expiry completes

#### Scenario: TTL re-stamp requires a successful exchange
- WHEN a run cannot complete a successful HTTP exchange for a feed
- THEN the run does not extend any TTL for that feed from cached data

### Requirement: A FAILED feed SHALL perform zero withdrawals
Withdrawal SHALL be computed per feed against that feed's own desired
set, and a feed that failed fetch, validation, staleness, canary, or
churn checks SHALL leave its journaled entries and map entries untouched.

#### Scenario: transient upstream error
- WHEN one feed returns a server error while others succeed
- THEN the failed feed's existing entries remain and age out by TTL only,
  and the diff records no planned withdrawal for it

### Requirement: Feed entries SHALL never displace foreign entries
Every map mutation SHALL be guarded by comparing the live expiry value
against the journaled written value under the per-key lock; a live entry
not written by the loader SHALL never be modified or deleted.

#### Scenario: collision with a responder block
- WHEN a desired feed CIDR equals a key holding a live responder entry
- THEN the loader skips it, records the skip, and the responder entry is
  unaffected

#### Scenario: operator unblocks a feed entry
- WHEN the operator deletes a feed-owned key and the CIDR remains in the
  feed
- THEN the next run re-inserts it and logs that the allowlist is the
  durable suppression mechanism

### Requirement: Anomalous feed content SHALL abort rather than shrink
The loader SHALL abort the affected feed or run, with zero writes, when
candidates cover the watchdog canary address, when the aggregate address
space of a desired set exceeds the coverage cap, when the allowlist
snapshot is unavailable or empty, or when composition churn exceeds the
brake threshold pending interactive confirmation.

#### Scenario: canary coverage
- WHEN any candidate range covers the configured canary address
- THEN the entire supplying feed is FAILED for the run with zero writes,
  preserving the watchdog's over-block tripwire

#### Scenario: churn brake
- WHEN a feed's composition changes beyond the configured fraction of its
  last applied set
- THEN inserts and withdrawals are held, refreshes of still-desired keys
  proceed, and enforcement of the new composition waits for an
  interactive confirmation

### Requirement: Enforcement SHALL require a double interactive gate
A feed SHALL write to the maps only when both the deployed configuration
lists it for enforcement and a host-local approval record written by an
interactive confirm command contains it; dry-run with reviewable diffs
SHALL be the default for every new feed.

#### Scenario: config edit alone
- WHEN a feed is added to the enforcement list but never confirmed
- THEN runs produce diffs only, and the config-approval mismatch signal
  raises an alert

#### Scenario: deploy reverts a live config edit
- WHEN a deploy overwrites the host configuration and disarms enforcement
- THEN the mismatch signal alerts within two cycles while entries decay
  open

### Requirement: Feed activity SHALL be observable per feed
The loader SHALL export per-run and per-feed state (success timestamps,
snapshot age, entry and rejection counts, churn hold, journal reset) to
persistent storage consumed by the existing kv chain, with per-feed
staleness and failed-open alerts.

#### Scenario: reboot does not false-alarm
- WHEN a host reboots
- THEN previously recorded success timestamps remain visible and no
  staleness alert fires without a genuinely missed cycle

### Requirement: A hostile feed body SHALL fail only its own feed
Any exception raised by a feed parser or by per-feed validation while
processing a fetched body SHALL fail that one feed through the normal
FAILED path (recorded in the diff, body preserved for inspection,
entries left to age out by TTL) and SHALL NOT terminate the run or
affect any other feed. A body whose cidr or records fields are not the
expected types SHALL be rejected as a validation failure of that feed,
never silently accepted as a bogus network and never permitted to
select an exception class the per-feed handler does not contain. This
requirement governs the per-feed parse and validation boundary only:
the run-level content gates (canary coverage, entry caps, coverage
caps, churn brake) continue to abort the affected feed or run per the
existing anomalous-content requirement.

#### Scenario: non-numeric records trailer
- WHEN a syntactically valid Spamhaus JSONL body arrives whose
  metadata trailer carries a records field that is not an integer (a
  string, list, null, or boolean)
- THEN that feed alone is FAILED for the run with a validation
  message, the offending body is saved for inspection, and every other
  configured feed completes normally

#### Scenario: cidr field of the wrong type
- WHEN a Spamhaus record line carries a cidr field that is not a
  string (for example a JSON integer or boolean, which the address
  parser would otherwise silently accept as a bogus /32 network)
- THEN that feed is FAILED for the run with a validation message and
  no entry derived from the wrong-typed field is planned or written

#### Scenario: parser raises an unanticipated exception class
- WHEN a feed body causes the parser to raise an exception outside the
  anticipated validation classes
- THEN the exception is contained at the per-feed boundary exactly as
  a validation failure is: the feed is FAILED, the run continues, and
  the run exits with its normal per-feed failure reporting

### Requirement: An unexpected run crash SHALL NOT arm crash-adoption from remote content
The loader SHALL clear its run-in-progress marker before exiting
nonzero when an unexpected exception escapes a run that has performed
no map write, so remote content can never arm crash-adoption mode; a
run that has already written map entries SHALL leave the marker set,
preserving bounded crash-adoption as the recovery for a genuine
mid-write crash.

#### Scenario: unexpected crash before any write
- WHEN an unexpected exception escapes the run loop after the
  run-in-progress marker was set but before any map mutation occurred
- THEN the marker is cleared, the diff and metrics still land so the
  failure alarms, the process exits nonzero, and the next run reports
  no crash-adoption mode

#### Scenario: unexpected crash after writes preserves recovery
- WHEN an unexpected exception escapes the run loop after at least one
  map mutation was performed
- THEN the run-in-progress marker remains set and the next same-boot
  run enters bounded crash-adoption mode as designed

### Requirement: Feed bodies SHALL be accepted over https only
The loader SHALL fetch feeds only from https URLs and SHALL discard any
response whose final URL, after following any redirects, is not https;
the discard SHALL fail that one feed through the normal failed path,
with zero writes, zero withdrawals, and no conditional-GET state
persisted, while other feeds proceed.

#### Scenario: an upstream redirect to cleartext is refused
- WHEN a configured https feed URL answers with a redirect chain whose
  final hop is an http or other non-https URL
- THEN the body is discarded without being parsed, the feed is recorded
  failed with a status naming the non-https final URL, its existing
  entries age out by TTL only, and the failure surfaces through the
  existing per-feed staleness alerting if it persists

#### Scenario: a non-https configured URL never leaves the host
- WHEN a feed definition carries a URL whose scheme is not https
- THEN the loader refuses the feed before issuing any request and
  records it failed for the run
