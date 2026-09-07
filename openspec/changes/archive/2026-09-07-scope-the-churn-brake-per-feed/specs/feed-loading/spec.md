# feed-loading

## MODIFIED Requirements

### Requirement: Anomalous feed content SHALL abort rather than shrink
The loader SHALL abort the affected feed or run, with zero writes, when
candidates cover the watchdog canary address, when the aggregate address
space of a desired set exceeds the coverage cap, when the allowlist
snapshot is unavailable or empty, or when composition churn exceeds the
brake threshold in force for that feed pending interactive confirmation.
The churn threshold SHALL be resolvable per feed, so that a feed whose
normal behaviour is heavy rotation can carry a threshold matching it while
every other feed keeps the conservative default.

#### Scenario: canary coverage
- WHEN any candidate range covers the configured canary address
- THEN the entire supplying feed is FAILED for the run with zero writes,
  preserving the watchdog's over-block tripwire

#### Scenario: churn brake
- WHEN a feed's composition changes beyond the threshold in force for that
  feed, measured against its last applied set
- THEN inserts and withdrawals are held, refreshes of still-desired keys
  proceed, and enforcement of the new composition waits for an
  interactive confirmation

#### Scenario: a feed carries its own threshold
- WHEN a feed declares a churn threshold of its own
- THEN that value decides whether the feed is held, the global default is
  not applied to it, and no other feed's threshold changes

#### Scenario: a feed declares nothing
- WHEN a feed declares no threshold of its own
- THEN the global default applies to it unchanged, so a configuration that
  declares no overrides behaves exactly as it did before

#### Scenario: the operator can tell which threshold was applied
- WHEN a feed is held by the churn brake
- THEN the emitted hold record names the threshold that was applied to that
  feed, so a tuned feed that still moved too far is distinguishable from a
  feed that was never tuned
