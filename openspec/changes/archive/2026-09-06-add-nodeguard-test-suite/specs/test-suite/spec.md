## ADDED Requirements

### Requirement: The repository SHALL carry a hermetic stdlib-only unit test suite
The repository SHALL contain a Python unittest suite under `tests/`
that uses only the standard library and runs to completion on any
machine with python3: no root privileges, no network access, no
bpftool, and no bpffs. Every subprocess boundary (bpftool, the block
wrapper, the allow-dump call) and the feed HTTP transport SHALL be
replaced by fakes inside the tests; the modules under test SHALL be
the shipped files themselves, with the extensionless `bin/` scripts
loaded from their file paths.

#### Scenario: run on a developer machine
- WHEN `python3 -m unittest discover -s tests` is invoked from the
  repository root on a machine with only python3 available
- THEN the suite passes or fails purely on the repository's content,
  performs no network request, spawns no bpftool process, and writes
  only under temporary directories it creates and removes

#### Scenario: tests exercise the shipped files
- WHEN the suite imports the responder, feeds loader, or map CLI
- THEN it loads the exact files under `bin/` (including the
  extensionless scripts, via their file paths), so a defect in a
  shipped file cannot be masked by a diverging test copy

### Requirement: The build SHALL run the unit test suite before any rehearsal step
build/build.sh SHALL run the unit test suite as a distinct step before
the compile and before any network-namespace step, and a test failure
SHALL fail the build.

#### Scenario: failing test blocks the build
- WHEN any unit test fails during a build/build.sh run
- THEN the build exits nonzero before the netns rehearsal begins and
  no artifact is produced

#### Scenario: suite runs before expensive steps
- WHEN build/build.sh runs with a tree whose unit tests fail
- THEN the failure is reported before compile output or rehearsal
  output appears, so the cheapest gate runs first

### Requirement: The suite SHALL cover the security-critical decision paths
The suite SHALL cover, at minimum: all seven responder gates in their
documented order, including the blocked_until window suppression that
persists across a reboot; the Spamhaus and DShield parsers and the
feed gates driven with hostile and truncated bodies; responder TTL
escalation and journal pruning, including corrupt-journal quarantine;
the watchdog EWMA detector's seed, adapt, trip, regime-reseed, and
discard paths; and ngmap.py's key and value encode/decode round-trips
plus the NEVER_BLOCK and containment guards.

#### Scenario: responder gate order is pinned
- WHEN a fixture eve.json line is constructed to fail exactly one of
  the seven gates
- THEN a dedicated test asserts that line is refused at that gate with
  the gate's documented outcome (drop, WOULD BLOCK log, sighting, or
  skip), and a companion fixture passing all gates asserts the block
  (or dry-run WOULD BLOCK) outcome

#### Scenario: window suppression is pinned as current behavior
- WHEN an alert arrives for a source whose journal record carries a
  blocked_until timestamp in the future
- THEN the test asserts the responder records a sighting and issues no
  new block, with the test annotated as the behavior finding S3 will
  change, so that fix must edit a failing test rather than slip in
  silently

#### Scenario: hostile feed bodies cannot pass a parser
- WHEN Spamhaus bodies with a non-numeric records trailer field, a
  non-string cidr, a missing or misplaced trailer, or a truncated
  record set, and DShield bodies with malformed columns or non-/24
  rows, are driven through the parsers
- THEN each is rejected as a validation failure and no test observes
  an uncaught exception escaping the parsing boundary

#### Scenario: TTL escalation and pruning are exact
- WHEN a source completes successive real block windows
- THEN tests assert the TTL doubles per completed offense and clamps
  at TTL_MAX, that dry-run offenses raise shadow_hits and never the
  offense count, and that records idle past the pruning horizon are
  dropped while a corrupt journal file is quarantined rather than
  crashing startup

#### Scenario: EWMA detector paths are exercised without a host
- WHEN crafted kv snapshots are fed through the extracted watchdog
  detector across successive simulated cycles
- THEN tests assert baseline seeding, bounded adaptation under
  anomalous cycles, a single trip at the configured consecutive-cycle
  threshold in both shadow and on modes, regime-change reseeding, and
  the discard paths for prog_id change, negative delta, and stale kv

#### Scenario: encoder round-trips and guards hold
- WHEN v4 and v6 networks across prefix lengths are encoded to map key
  bytes and decoded back, and when addresses in every NEVER_BLOCK
  range are checked
- THEN round-trips are identity, every NEVER_BLOCK address is refused
  with its reason, and a broad CIDR containing a protected range is
  refused by the containment guard

### Requirement: Defect fixes in this change SHALL land test-first
Each crash-class defect fixed by this change SHALL be accompanied by a
regression test that fails against the pre-fix code and passes after
the fix, and the test SHALL remain in the suite.

#### Scenario: regression tests pin the two fixed crashes
- WHEN the suite runs against a tree where either the feeds parser
  TypeError fix or the map CLI integer-range fix is reverted
- THEN the corresponding regression test fails
