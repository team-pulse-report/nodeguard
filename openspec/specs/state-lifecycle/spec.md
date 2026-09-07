# state-lifecycle Specification

## Purpose

How persisted state is invalidated when the thing it describes goes
away. Kernel maps vanish at reboot, resolution can fail transiently,
and entries expire; the requirements here keep userspace state from
outliving its subject, whether that means a journal window surviving
the block it tracked, an allowlist entry deleted by one bad lookup, or
a live entry overwritten by a blind write.

## Requirements

### Requirement: Responder block windows SHALL NOT suppress blocking across a reboot
The responder journal SHALL record the boot id it was written under,
and on load under a different or unknown boot id SHALL treat every
persisted block window as expired while retaining offense history, so
that a repeat offender is re-blocked on its first qualifying alert
after a reboot instead of riding out a window the kernel no longer
enforces.

#### Scenario: prior-boot window does not shield a repeat offender
- WHEN the host reboots and a source whose journaled blocked_until
  still lies in the future sends an alert that passes every gate
- THEN the responder issues a new block for it rather than downgrading
  the alert to a sighting, and the block's TTL reflects the retained
  offense count

#### Scenario: warm restart preserves windows
- WHEN the responder process restarts without a reboot
- THEN journaled windows load unchanged and an alert from a source
  inside its window is still recorded as a sighting only, because the
  kernel entry genuinely covers it

#### Scenario: legacy journal is treated as prior-boot
- WHEN a journal written before boot-id recording is loaded
- THEN its windows are treated as expired and its records load without
  error, failing toward one redundant block rather than a suppressed
  one

### Requirement: Protected-remote allow generation SHALL retain last-good entries on failure
The allow-map generation SHALL keep a persistent last-good snapshot per
dynamic directive (resolve, derp) and SHALL serve the snapshot's
entries when the directive's live lookup fails, so a transient DNS or
tailscaled failure never removes a protected remote from the live allow
maps; the generation run SHALL export its entry count and degraded
state so the failure is observable.

#### Scenario: transient resolve failure keeps the protection
- WHEN a resolve directive's name lookup fails during generation and a
  last-good snapshot for that name exists
- THEN the snapshot's addresses are included in the generated allow
  set, the reconcile does not delete them from the live maps, and the
  run is marked degraded

#### Scenario: DERP fetch failure keeps the relays allowlisted
- WHEN the DERP map fetch or parse fails and a last-good DERP snapshot
  exists
- THEN the snapshot's relay addresses remain in the generated set and
  in the live allow maps

#### Scenario: success refreshes the snapshot
- WHEN a directive's live lookup succeeds
- THEN its last-good snapshot is atomically replaced with the fresh
  result and the fresh result alone is what generation uses

#### Scenario: degraded generation is visible
- WHEN any directive was served from its snapshot or failed with no
  snapshot
- THEN the exported allow kv carries a nonzero degraded flag alongside
  the entry count, and a fully successful run exports the flag as zero

### Requirement: Generated allow entries SHALL be refreshed periodically without a datapath interruption
A timer SHALL re-run allow generation and reconciliation on a fixed
period between boots, and the refresh SHALL use only the hitless
reload path, never a unit restart that propagates to the XDP attach.

#### Scenario: stale entries converge without a reboot
- WHEN a protected name's address or the DERP map changes while the
  host stays up
- THEN the live allow maps reflect the change within one refresh
  period plus its randomized delay, with no deploy and no reboot

#### Scenario: refresh causes no carrier blip
- WHEN the refresh timer fires
- THEN the maps unit is reloaded, not restarted, no detach of the XDP
  program occurs, and the interface carrier state does not change

### Requirement: CLI block writes SHALL read the existing entry before writing
The block command SHALL look up the current map value under the block
lock before writing; it SHALL refuse to overwrite a permanent entry
(expiry 0) unless the explicit deliberate-override flag is given, and
SHALL carry the hit counter forward when refreshing a live TTL entry.

#### Scenario: automation cannot demote a permanent block
- WHEN the responder re-blocks an address that holds a permanent entry
- THEN the write is refused with a nonzero exit naming the entry as
  permanent, the permanent entry and its hit count are unchanged, and
  the responder logs the failure

#### Scenario: operator override is explicit
- WHEN an operator re-blocks a permanently blocked target and passes
  the deliberate-override flag
- THEN the entry is rewritten as requested with its hits carried
  forward

#### Scenario: re-blocking a live entry preserves its hits
- WHEN a live TTL entry is blocked again with a new TTL
- THEN the stored expiry is replaced and the accumulated hit count is
  carried forward unchanged, so the sweep's hits-delta ranking still
  sees the source

#### Scenario: an expired entry is treated as absent
- WHEN the existing entry's expiry is nonzero and already past
- THEN the write proceeds without the override flag and the new entry
  starts with zero hits

### Requirement: Inserting a covering block entry SHALL delete contained expired entries
A userspace writer SHALL, when inserting a block entry broader than a
host route, delete under the same block-lock hold expired entries
strictly contained within the inserted network, re-verifying each
candidate's expiry immediately before deletion; live and permanent
contained entries SHALL never be deleted by this path. A bulk
reconcile run MAY bound its deletion candidates to the entries already
expired when the run began; an entry that expires mid-run MAY be left
to the periodic sweep backstop.

#### Scenario: feed CIDR insert clears a shadowing corpse
- WHEN the feeds loader inserts a CIDR that strictly contains a
  host-route entry that was already expired when the reconcile run
  began
- THEN the expired entry is deleted in the same lock hold, so no
  address inside the CIDR passes via the expired more-specific match
  while the CIDR is live

#### Scenario: a corpse arising mid-reconcile waits for the sweep
- WHEN an entry contained in a to-be-inserted CIDR expires after the
  reconcile run snapshotted its expired-entry set
- THEN the insert is not required to delete it, and the periodic sweep
  removes it as the backstop

#### Scenario: operator CIDR block clears contained corpses
- WHEN an operator blocks a CIDR that strictly contains one or more
  expired entries
- THEN those entries are deleted as part of the block operation and
  the new entry answers for the whole range

#### Scenario: a contained entry that came back alive survives
- WHEN a contained entry was expired in the writer's snapshot but has
  been re-blocked by another writer before the deletion is applied
- THEN the under-lock re-verification finds it live and leaves it in
  place, and only entries still expired at deletion time are removed
