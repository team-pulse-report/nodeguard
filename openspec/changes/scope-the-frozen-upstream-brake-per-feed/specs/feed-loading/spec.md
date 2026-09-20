# feed-loading

## ADDED Requirements

### Requirement: The frozen-upstream brake SHALL be resolvable per feed
The loader SHALL FAIL a feed whose last-changed content is older than the
frozen-upstream threshold in force for that feed, performing zero writes and
no TTL re-stamp so its entries decay. That threshold SHALL be resolvable per
feed, so that a feed whose publisher legitimately pauses for weeks can carry
a threshold matching its measured cadence while every other feed keeps the
conservative default.

#### Scenario: a feed carries its own threshold
- WHEN a feed declares a frozen-upstream threshold of its own
- THEN that value decides whether the feed is FAILED as frozen, the global
  default is not applied to it, and no other feed's threshold changes

#### Scenario: a feed declares nothing
- WHEN a feed declares no frozen-upstream threshold of its own
- THEN the global default applies to it unchanged, so a configuration that
  declares no overrides behaves exactly as it did before

#### Scenario: a tuned feed still goes dark
- WHEN a feed carrying its own threshold has not changed content for longer
  than that threshold
- THEN it is FAILED as frozen exactly as a defaulted feed would be, so
  raising a threshold defers the brake rather than removing it

#### Scenario: the operator can tell which threshold was applied
- WHEN a feed is FAILED by the frozen-upstream brake
- THEN the emitted record names the threshold that was applied to that feed,
  so a tuned feed that has genuinely gone dark is distinguishable from a feed
  that was never tuned

#### Scenario: a slow publisher does not fail its peers
- WHEN one feed is FAILED as frozen while other feeds in the same run
  succeed
- THEN each succeeding feed applies and re-stamps normally, and only the
  frozen feed's entries decay
