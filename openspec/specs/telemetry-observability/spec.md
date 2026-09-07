# telemetry-observability Specification

## Purpose
Give nodeguard operators a truthful, fail-open view of what the XDP
firewall and Suricata pipeline are doing, without ever letting observation
change enforcement. This capability defines the count-only kernel telemetry
(the `stats2` protocol-sanity counters, every branch resolving to
XDP_PASS), the once-a-minute userspace kv export whose every metric fails
toward visible-unknown rather than a silent zero, the O(1) single-writer
sweep cache that keeps blocklist-sized work off the minute path, the
untrainable gateway-local anomaly detector that never mutates the kill
switch, and the Zabbix master/dependent template and fleet-scaling
dashboards built on top. It exists so a 2am reader can tell "attached and
quiet" from "blind", and so adding a host is a group membership change, not
a dashboard rewrite.

## Requirements

### Requirement: Kernel telemetry SHALL be count-only in every enforcement state
Every branch added for telemetry SHALL resolve to XDP_PASS; sanity
anomalies SHALL be counted on every packet that passes IP header
validation, in every enforcement state, including while the kill switch
is latched.

#### Scenario: crafted probes are counted and pass
- WHEN NULL, XMAS, SYN+FIN, SYN+RST, low-TTL, and fragmented probes are
  sent through the program in the netns rehearsal
- THEN each corresponding stats2 counter increments, at most one flag
  counter per packet, and every probe still reaches a listening socket

#### Scenario: kill-switch latch does not blind the counters
- WHEN the kill switch is latched and scan traffic continues to arrive
- THEN the stats2 counters keep advancing, because the sanity block
  executes before the kill-switch gate, and no packet is dropped by any
  telemetry branch

#### Scenario: malformed TCP header falls through uncounted
- WHEN a packet passes IP header validation but its TCP header fails
  the bounds check
- THEN no parsefail counter increments for it (the IP header was valid)
  and the packet continues through the normal verdict path

### Requirement: Map changes SHALL be additive and reloads hitless in both directions
Telemetry SHALL add a new pinned map, never resize an existing pinned
map; the map list used by build, spec generation, cleanup, and identity
verification SHALL be derived from the object rather than hardcoded;
and reload SHALL be hitless in both the forward and rollback
directions.

#### Scenario: forward reload with the new pin present
- WHEN the new object is reloaded after create-maps has pinned stats2
- THEN the identity check verifies every referenced pin matches the
  pinned id, the core six maps are all present, existing counters stay
  monotonic across the swap, and no carrier transition occurs

#### Scenario: rollback reload ignores the unreferenced pin
- WHEN the previous object, which does not reference stats2, is
  reloaded while the stats2 pin exists
- THEN the reload succeeds hitlessly, the pin remains in place
  unreferenced, and its counters are preserved for a later roll-forward

#### Scenario: pre-load guard refuses spec-listed-but-unpinned
- WHEN reload or attach is invoked while any map listed in the
  installed spec has no pin under the pin directory
- THEN the loader is not invoked, and the error names the exact
  recovery command that runs create-maps against the installed spec

#### Scenario: spec generation cannot silently omit a map
- WHEN the build generates the map spec from a throwaway load
- THEN the build fails unless the derived pin set contains the core six
  maps and equals the object's BTF-declared map set

### Requirement: Every metric SHALL fail toward visible unknown, never silent zero
A value that cannot be read SHALL be omitted from the kv output so its
dependent item goes unsupported, accompanied by an explicit fail flag
where the failure is a local tool breaking; no read or parse failure
SHALL ever be rendered as a zero.

#### Scenario: stats read failure with the pin present
- WHEN the stats pin exists but the dump or parse fails
- THEN no counter lines are emitted, ng.stats_read_fail=1 is emitted,
  and the counters' unsupported state plus the fail flag both raise
  Warning triggers

#### Scenario: suricatasc failure omits the keys
- WHEN the suricatasc call times out, errors, or fails to parse
- THEN the kernel_drops and suricata_alerts lines are omitted entirely,
  their items go unsupported, and a trigger on the unsupported state
  fires, so a wedged capture never reads as zero drops

#### Scenario: reboot truncates the sweep cache
- WHEN the host reboots and map creation runs
- THEN the map-statistics cache and hits snapshot are truncated, the
  count keys are omitted until the first post-boot sweep completes, and
  pre-reboot totals are never served against freshly emptied maps

#### Scenario: prog_match is absent when the expectation file is missing
- WHEN the interface is attached but the expected-program-id file does
  not exist
- THEN no prog_match line is emitted and the item goes unsupported,
  rather than reporting a silent 1 or a false-paging 0

### Requirement: The minute path SHALL be O(1) with a single-writer sweep cache
The 1-minute kv collection SHALL perform no work proportional to
blocklist population; map counts, utilization, and top-blocked SHALL be
sourced exclusively from a cache file written atomically by exactly one
writer, the 10-minute sweep, which also exports its own walk duration.

#### Scenario: the live walk is unreachable from the kv path
- WHEN the kv code path of the status tool is inspected
- THEN no invocation of the live list dump is reachable from it; the
  live count runs only in the operator-invoked human-output branch

#### Scenario: feeds does not write the cache
- WHEN a feeds apply completes and fresh counts are wanted
- THEN feeds triggers a one-off sweep run instead of writing the cache
  itself, so the file never reflects a single writer's partial view of
  maps that have three writers

#### Scenario: a stalled sweep is visible
- WHEN the sweep stops running
- THEN the cache keys keep their last values while a first-class age
  key grows past its alarm threshold and an independent trigger on the
  sweep timer's state fires

### Requirement: Anomaly detection SHALL be untrainable by its own subject and SHALL never mutate enforcement
The gateway-local detector SHALL exclude at-or-above-threshold cycles
from baseline updates with a bounded adaptation streak, SHALL discard
and reseed on any regime change (kill-switch, attach, feeds-enforce
state, or a reload within the cycle), and SHALL never modify the kill
switch, latch files, or any map.

#### Scenario: an attack cannot train the detector into silence
- WHEN deltas at or above the trip threshold arrive on consecutive
  cycles
- THEN the mean and deviation are not updated by those cycles, the trip
  fires after the configured consecutive count, and only after the
  bounded skip streak is exhausted does the baseline absorb the new
  level

#### Scenario: recovery from a latch does not false-trip
- WHEN the kill-switch state changes between cycles, such as the
  once-per-boot re-arm ending a multi-hour latch
- THEN that cycle is discarded and the baseline state reseeded, so the
  recovery surge cannot fire an anomaly against a decayed baseline

#### Scenario: the detector observes only
- WHEN an anomaly trips
- THEN the cumulative count and timestamp are exported and a CRITICAL
  journal line records metric, delta, and threshold, and no enforcement
  state of any kind is changed

#### Scenario: shadow mode precedes enforcement of attention
- WHEN the detector first ships
- THEN it runs in shadow mode, exporting a shadow count while the real
  count stays zero, and thresholds are promoted only after a reviewed
  shadow window cross-checked against reload journal lines

### Requirement: Template migration SHALL preserve item identity
The generated v2 template SHALL carry over every existing object's uuid
and display name verbatim from the committed v1, minting new uuids only
for genuinely new objects, and the live import SHALL be gated by a
scratch-template rehearsal proving itemids survive the upgrade. A
designed removal SHALL be sanctioned in the recorded-removals file
(kind, identifier, reason, date) in the same commit that removes the
object from the generator; an unsanctioned disappearance SHALL fail
the check, a sanction entry naming an object the generator still emits
SHALL fail as stale-sanction drift, and the committed template SHALL
be regenerated in the same commit as any generator edit so the
generator and the committed artifact cannot diverge.

#### Scenario: regeneration does not churn identity
- WHEN the generator renders the v2 template
- THEN every object present in v1 keeps its uuid and byte-identical
  display name, verified by the checker against the committed v1, so
  no item is deleted and recreated and no history is lost

#### Scenario: scratch rehearsal gates the live import
- WHEN the v2 template is ready for the live server
- THEN v1 then v2 are first imported into a scratch template, itemid
  preservation across the upgrade is confirmed, and at least one
  dependent item is shown parsing a real kv blob, before the live
  template is touched

#### Scenario: dependent parsing is proven against real output
- WHEN the template checker runs in the build
- THEN every generated preprocessing regex is executed against a
  captured real kv file and every templated field extracts a value,
  and template keys are cross-checked against the documented kv key
  list

#### Scenario: retired static per-feed items cannot be resurrected
- WHEN the generator runs after the static per-feed items and their
  triggers are retired in favor of the discovered per-feed prototypes
- THEN the generated template contains no static per-feed item or
  trigger, each removal is recorded in the sanction file with its
  reason and date, and the checker passes against the pre-removal
  baseline only because of those sanction entries

#### Scenario: a stale sanction is visible drift
- WHEN a sanction entry names an object the generator still emits
- THEN the checker fails the build, so a sanction can never land ahead
  of its removal or silently outlive a reintroduction

#### Scenario: the sanction guard survives regeneration
- WHEN the committed template has been regenerated after a removal, so
  a sanctioned object is in neither the baseline nor the generated
  template, and a later edit reintroduces it
- THEN the checker still fails, because staleness is judged against
  what the generator emits rather than against the baseline

### Requirement: Dashboards SHALL scale with the fleet without widget rework
The Zabbix host group SHALL be the canonical fleet definition; every
widget that supports group or pattern addressing SHALL use it, and
per-host-enumerated widgets SHALL be generated from live group
membership, so onboarding a host requires no code or widget edit.

#### Scenario: synthetic third host drill
- WHEN the generator plan is run with a synthetic third host added to
  the group
- THEN the plan output covers the new host in every dashboard with no
  code edit, and item name patterns match the new host's items without
  change

#### Scenario: no fleet identity in the public generator
- WHEN the public generator directory is reviewed
- THEN no real host name, host-name prefix, or server URL appears in
  it; the group name, host pattern, and URL arrive from the private
  wrapper, and the token arrives only via the environment

### Requirement: Documentation SHALL be refreshed and verified against the tree
The design document, ADRs, changelog, README, legend, and configuration
examples SHALL be updated to describe the shipped system, with every
factual claim re-verified against the tree in the same sitting rather
than patched by diff.

#### Scenario: stale claims are removed with evidence
- WHEN the design document's risk and roadmap sections are revised
- THEN risks the tree proves resolved are removed, new measured risks
  are added with their citations and mitigations, and each retained
  claim is grep-verified against the current tree

### Requirement: Responder liveness SHALL be a first-class heartbeat
The responder SHALL write a heartbeat timestamp into its kv file on
every flush, including idle ticks with no new alerts, at least once
per minute while its event loop is alive; the exporter SHALL derive a
first-class age from that timestamp, omitted when the source is
absent; the responder SHALL export the alert-to-decision lag measured
from the EVE record's own timestamp; and a divergence between rising
Suricata alert counts and flat responder-consumed counts SHALL raise a
trigger.

#### Scenario: a wedged responder becomes visible
- WHEN the responder process hangs while its systemd unit remains
  active
- THEN the heartbeat timestamp stops advancing even though the last kv
  values are still served, the derived age grows past its threshold,
  and a Warning trigger fires within minutes

#### Scenario: an idle responder still proves liveness
- WHEN no alert arrives for an extended period
- THEN the kv file is still rewritten at least once per minute with an
  advancing heartbeat timestamp, so quiet and dead are
  distinguishable

#### Scenario: alive but not consuming is caught by divergence
- WHEN the Suricata alert counter rises across the evaluation window
  while the responder's consumed-alert counter stays flat
- THEN the divergence trigger fires, catching a responder that is
  running but reading nothing

#### Scenario: lag is measured, not assumed
- WHEN the responder consumes an alert
- THEN it exports the lag between the EVE record's own timestamp and
  the moment of processing, and an absent or unparseable record
  timestamp never crashes the event loop and never emits a fabricated
  value

### Requirement: Enrichment and ruleset freshness SHALL be timestamped by their producers on success only
The geo enrichment run SHALL stamp its output with a timestamp written
only on successful completion; the ruleset update unit SHALL record a
last-success epoch only when the update itself succeeded, persisted
across reboot; the exporter SHALL derive ages or export the epochs
with absent sources omitted; and staleness triggers SHALL fire when
either producer stops succeeding.

#### Scenario: a silently failing geo run ages out
- WHEN geo runs fail persistently, including failures the run swallows
  while exiting zero
- THEN the geo timestamp is not refreshed, the derived age grows, and
  a Warning trigger fires after a few missed timer periods

#### Scenario: a chronically failing ruleset update pages
- WHEN the ruleset update fails for two consecutive daily cycles
- THEN the last-success staleness trigger fires, because the success
  stamp is written only on a successful update and its age now exceeds
  two cycles plus the timer's randomized-delay margin

#### Scenario: the freshness stamp is the last artifact of the run
- WHEN a geo run computes its country statistics and then fails while
  rendering or publishing the attack map
- THEN no timestamp is written, so the derived age keeps growing
  instead of reporting a fresh run over a frozen map

#### Scenario: never-ran states stay visibly unknown
- WHEN the geo run has never completed or no update success stamp
  exists
- THEN the corresponding keys are omitted, their items go unsupported,
  and no freshness value is fabricated as zero or as current

### Requirement: Graphed counters SHALL be plotted as rates and incident-relevant failure counters SHALL carry triggers
Every graphed cumulative counter SHALL be plotted through a
change-per-second rate twin whenever it shares a graph with per-second
series; the feeds journal-reset and map-error counters SHALL carry
Warning triggers; a sustained expired-entry pass rate SHALL carry a
Warning trigger; and the discovered per-feed staleness triggers SHALL
alert at operational severities after the parity window, not at
Information.

#### Scenario: dry-run divergence is readable on the graph
- WHEN the alert-to-block graph renders
- THEN the responder decision series are the per-second rate twins of
  the cumulative counters, so a divergence between would-block and
  issued reads directly instead of being flattened by monotonic lines

#### Scenario: a lost CAS journal pages
- WHEN the feeds loader reports its journal was lost and rebuilt
  insert-only
- THEN a Warning trigger fires on that flag as soon as it is reported

#### Scenario: persistent map-write failures page
- WHEN the feeds map-error counter is nonzero across two full feed
  cycles plus margin
- THEN a Warning trigger fires, distinguishing a persistent per-key
  write failure from a one-off blip

#### Scenario: sustained expired-entry passes page
- WHEN the expired-pass rate stays strictly positive on every sample
  for longer than a full sweep period plus margin
- THEN a Warning trigger fires, because corpses are outliving the
  sweep that should delete them and an expired more-specific entry may
  be shadowing a live broader block

#### Scenario: per-feed staleness alerts at operational severity
- WHEN a discovered feed goes stale, decays to failed-open, or freezes
  upstream after the parity window has closed
- THEN the prototype triggers fire at Warning, Average, and Warning
  severity respectively, with their no-data guards intact

### Requirement: Telemetry-chain death SHALL page once, not four times
The no-data-based warnings for a dead kv export chain SHALL declare a
template trigger dependency on the frozen-kv High trigger, referenced
by its stable trigger name so the dependency survives regeneration and
import, while value-based warnings that represent independent failures
SHALL carry no such dependency. A depended-on trigger SHALL be
recalculated on a timer and not only when values arrive, so that it can
enter Problem, and therefore suppress its dependents, in the very state
where the export has stopped. A trigger that mixes a value clause with
a no-data clause SHALL be split before the dependency is attached, so
no dependency can suppress a value-based fault. Warnings that restate a
fault a more specific trigger already names SHALL depend on that
trigger.

#### Scenario: a dead export chain pages one High
- WHEN the watchdog timer dies or the kv runtime directory is wiped
- THEN the frozen-kv High trigger fires and the dependent no-data
  warnings are suppressed by the dependency, so the operator gets one
  page naming the actual failure instead of four overlapping alerts

#### Scenario: independent failures still page on their own
- WHEN a value-based warning condition holds while the kv chain is
  fresh, such as a stats read failure with an advancing kv timestamp
- THEN that trigger fires normally, because only the no-data-based
  warnings depend on the frozen-kv trigger

#### Scenario: a value clause is never suppressed by a no-data clause
- WHEN a stats read failure is reported while the frozen-kv High
  trigger is itself in Problem, for example on a host whose clock has
  skewed past the fuzzytime window
- THEN the value-based stats-unreadable warning still fires, because
  the no-data half was split into its own trigger and only that half
  carries the dependency

#### Scenario: a stopped responder pages once
- WHEN the responder unit is stopped while its kv file survives on
  tmpfs and Suricata keeps alerting
- THEN the unit-down Warning fires and the heartbeat-age and
  not-consuming Warnings are suppressed as dependents, so the operator
  gets the fault once and those two keep their meaning for a unit that
  is active but wedged

#### Scenario: regeneration preserves the dependency wiring
- WHEN the template is regenerated
- THEN every declared dependency still references its master trigger
  by its stable name, and the dependent triggers import with the
  dependency intact
