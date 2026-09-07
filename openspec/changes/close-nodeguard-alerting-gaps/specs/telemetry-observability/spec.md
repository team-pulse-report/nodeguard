## MODIFIED Requirements

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

## ADDED Requirements

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
