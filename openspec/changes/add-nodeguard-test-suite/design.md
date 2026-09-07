# NodeGuard unit test suite and the two crash fixes it starts with

Design for openspec/changes/add-nodeguard-test-suite. Covers evaluation
findings T1 (no test suite), S4 (Spamhaus TypeError crashes the feeds
run), and K3 (out-of-range integers stack-trace ngmap.py). Every code
claim below is cited as path:line against the tree at authoring time.

Governing constraints, inherited from the repo conventions
(openspec/project.md):

- Stdlib only; no pip dependencies anywhere, including the tests.
- The suite must run on any machine with python3: no root, no network,
  no bpftool, no bpffs. Everything that crosses a subprocess or
  transport boundary is faked.
- The two bug fixes are test-first: each lands with a test that fails
  against the current code and passes after the fix.
- No behavior change in production beyond the two fixes. The two
  testability seams (responder extraction, watchdog env paths) preserve
  behavior exactly and are covered by the new tests.

## 1. Where the tests live and how they gate the build

New top-level `tests/` directory:

```
tests/
  ngtest.py              shared harness: loaders, heredoc extractor, fakes
  test_ngmap.py          encoders, guards, CLI refusals, K3 regression
  test_feeds.py          parsers, gates, S4 regression, run() containment
  test_responder.py      seven gates, TTL escalation, journal, rate caps
  test_watchdog_anom.py  EWMA seed/adapt/trip/reseed/discard paths
```

Invocation is `python3 -m unittest discover -s tests -v` from the repo
root. build/build.sh gains that line as its own `== unit tests ==` step
inserted after the toolchain install (build/build.sh:16-17) and before
the compile (build/build.sh:19-21), which also places it before both
netns uses (the spec-generation netns at build/build.sh:36 and the
rehearsal at build/build.sh:101). Rationale for the position: the suite
is the cheapest gate in the file and needs nothing the container
installs except python3, so it runs first and a broken tree spends no
compile or rehearsal time. Inside the container the repo root is /work
(build/build.sh:12), so the step is
`python3 -m unittest discover -s "$REPO/tests" -v`; under
`set -euo pipefail` (build/build.sh:10) a test failure fails the build
with no extra plumbing.

CONTRIBUTING.md's verification list (CONTRIBUTING.md:39-43) gains the
unittest invocation next to py_compile, and the Python style line
(CONTRIBUTING.md:33) is extended to name the suite.

The suite is not installed by deploy/deploy.sh and never reaches the
gateways; the on-host py_compile check (deploy/deploy.sh:147) is
unchanged.

## 2. Importing extensionless bin/ scripts

The programs under test mostly have no .py extension
(bin/nodeguard-responder, bin/nodeguard-feeds); only bin/ngmap.py is a
normal module. Decision: load by file path with
`importlib.machinery.SourceFileLoader` wrapped in
`importlib.util.spec_from_loader` plus `module_from_spec`, the
established pattern for repos that ship extensionless executables.
`spec_from_file_location` alone does not work here because it selects a
loader from the file suffix and an extensionless path yields none.

Two facts about the tree make this safe and simple:

- Import-time side effects are absent. bin/nodeguard-responder guards
  its loop behind `if __name__ == "__main__"`
  (bin/nodeguard-responder:469-473) and defines only constants,
  functions, and classes at module level; bin/nodeguard-feeds does the
  same for its entry point (bin/nodeguard-feeds:944 and the guard at
  the file's end).
- bin/nodeguard-feeds performs `sys.path.insert(0,
  "/usr/local/lib/nodeguard")` then `import ngmap`
  (bin/nodeguard-feeds:47-48). On a dev machine that directory does not
  exist, so the harness prepends the repo's `bin/` directory to
  sys.path before loading the feeds module, and `import ngmap` resolves
  to the repo's own bin/ngmap.py. The build rehearsal already relies on
  exactly this resolution order (`sys.path.insert(0, "/work/bin")` then
  `import ngmap` at build/build.sh:133-134), so the harness copies a
  proven pattern rather than inventing one.

The harness (tests/ngtest.py) exposes `load_bin(module_name, filename)`
returning the loaded module, caching per test run so ngmap is one shared
instance (the feeds tests patch `ngmap` attributes and must patch the
same object the feeds module holds).

Every hardcoded absolute path in the modules under test is a
module-level constant (for example CONF, RESP_KV, NGMAP, BLOCK at
bin/nodeguard-responder:38-41 and CONF, ENV, STATE_DIR, STATE,
APPROVED, KV, DIFF, BOOT_ID_PATH at bin/nodeguard-feeds:50-57;
BLOCK_LOCK at bin/ngmap.py:105), so tests point them at
tempfile.TemporaryDirectory contents by assignment, with
unittest.TestCase.setUp/tearDown restoring the originals. The derived
f-string constants (STATE and friends) are evaluated at import time, so
each is patched individually, never via STATE_DIR alone.

## 3. Fakes at the subprocess and transport boundaries

- bpftool: every map operation in bin/ngmap.py funnels through the
  single `bpftool()` helper (bin/ngmap.py:64-73). Tests that need map
  behavior replace the higher-level helpers instead (`update_map`,
  `dump_map`, `lookup_value`, `delete_key`, `allow_entries_live`) with
  an in-memory dict-backed fake, because those carry the semantics the
  callers depend on (lookup miss returns None per bin/ngmap.py:118-134;
  delete of an absent key returns False per bin/ngmap.py:172-186). The
  `block_lock()` flock file (bin/ngmap.py:108-115) is redirected to a
  temp path so lock-discipline code still executes.
- The responder's block action is `subprocess.run([BLOCK, src,
  str(ttl)])` (bin/nodeguard-responder:450-451) and its allow snapshot
  is `subprocess.run(["python3", NGMAP, "allow-dump"], ...)`
  (bin/nodeguard-responder:135-137). After the section 5 extraction,
  tests inject a recording fake for the block call and a stub allow
  provider; AllowCache itself gets dedicated tests with
  unittest.mock.patch.object on the module's `subprocess` attribute,
  covering the documented None contract (unreadable cache fails toward
  NOT blocking, bin/nodeguard-responder:129-150).
- The feeds transport is the single `fetch()` function
  (bin/nodeguard-feeds:138-161), returning `(status, body, hdrs)`.
  Tests patch the module's `fetch` attribute with canned responses;
  no urllib request is ever constructed. The allow snapshot boundary
  (`allow_snapshot()` at bin/nodeguard-feeds:231-237, calling
  `ngmap.allow_entries_live()`) is patched the same way.

## 4. S4: hostile Spamhaus body must cost one feed, not the run

Confirmed mechanics. parse_spamhaus validates line shape with
ValueError raises (bin/nodeguard-feeds:174-188) but the trailer check
`int(trailer.get("records", -1))` (bin/nodeguard-feeds:189) raises
TypeError when records is a list, dict, or null: the parser's only
confirmed TypeError escape. The cidr path is different, verified by
direct interpreter test: `ipaddress.ip_network(obj["cidr"],
strict=True)` (bin/nodeguard-feeds:185) raises ValueError for every
JSON-producible non-string except integers and booleans (list, dict,
null, and float all raise ValueError, which the caller already
catches), while a JSON integer or boolean is silently ACCEPTED as a
bogus network (ip_network(123) yields 0.0.0.123/32, ip_network(True)
yields 0.0.0.1/32). The caller's catch is `(ValueError, json.JSONDecodeError,
UnicodeDecodeError)` only (bin/nodeguard-feeds:359), so the TypeError
propagates out of obtain(), out of _run_inner(), and out of run(),
whose only handler is for SystemExit (bin/nodeguard-feeds:682-691).
The run dies for all feeds after `state["run_in_progress"] = True` was
persisted (bin/nodeguard-feeds:678-679) and before the normal clear
(bin/nodeguard-feeds:730), so the next same-boot run arms bounded
crash-adoption mode (bin/nodeguard-feeds:298-302).

Fix, three layers, each with its own failing-first test:

1. Type checks in the parser: reject a non-string `cidr` and a
   non-integer `records` (bool excluded, since bool is an int subclass)
   with ValueError, keeping the trailer count comparison
   (bin/nodeguard-feeds:189-191) on validated input. Upstream sends a
   JSON integer records field and string cidr fields; anything else is
   a hostile or broken body. The records check closes the confirmed
   TypeError crash (list, dict, null); the cidr check closes the
   silent acceptance of JSON integers and booleans as bogus /32
   networks, and is defense in depth under layer 2's broadened catch
   rather than a crash fix.
2. Containment at the obtain() boundary: the parser call
   (bin/nodeguard-feeds:358) is body-driven code, so its catch broadens
   to `Exception`, failing that one feed through the existing FAILED
   path with the last-bad snapshot (bin/nodeguard-feeds:360-364) and
   logging the exception class. SystemExit is not an Exception subclass,
   so GateAbort (a SystemExit per bin/nodeguard-feeds:257-259) still
   propagates; the blast radius of any parser surprise, bug or attack,
   becomes one feed.
3. Honest crash state in run(): a new `self.writes` counter increments
   immediately after each successful map mutation in reconcile's
   one_key (the update_map calls at bin/nodeguard-feeds:581, 592, 600,
   610, 621) and withdraw_key (the delete_key call at
   bin/nodeguard-feeds:651). run() gains an `except Exception` sibling
   to the SystemExit handler: log the failure, mark all feeds failed,
   run finish() so the diff and kv still land and the failure alarms,
   and clear run_in_progress if and only if `self.writes == 0`, then
   re-raise so the unit exits nonzero. When writes have happened,
   run_in_progress stays set deliberately: crash-adoption is the
   designed recovery for a mid-write crash (bin/nodeguard-feeds:298-302
   and the adoption branch at bin/nodeguard-feeds:616-628), and this
   change must not weaken it. Layer 2 makes reaching this handler from
   feed content impossible; layer 3 covers the unexpected.

Tests (tests/test_feeds.py): direct parser tests with hostile bodies,
split by what they prove. Failing-first against the current code:
records as list, null, or dict (the confirmed TypeError crash), and
records as boolean or numeric string plus cidr as JSON integer or
boolean (silently accepted today, rejected once the type checks
land). Pinned current behavior that stays green across the fix:
records as non-numeric string and cidr as list, dict, or null
(already ValueError validation failures), trailer not last per
bin/nodeguard-feeds:179-180, missing trailer, truncated body whose
trailer count mismatches, undecodable UTF-8, and DShield rows with
too few columns, non-/24 masks, and end addresses that are not the
broadcast, per bin/nodeguard-feeds:204-212. Run-level tests prove a
TypeError body fails only its feed while a sibling feed completes,
and that an injected unexpected exception with zero writes leaves
run_in_progress cleared so the next run does not report adoption
mode.

## 5. Responder: extracting the gate pipeline so the contract is testable

The seven gates are documented as an ordered contract
(bin/nodeguard-responder:8-21) but live inline in main()'s for-loop
(bin/nodeguard-responder:318-466), reachable only through an infinite
`follow()` tail (bin/nodeguard-responder:230-266). Running the daemon
as a subprocess against a temp eve.json would test them, but slowly and
flakily, and it could not inject the allow cache's None path on demand.

Decision: behavior-preserving extraction. A module-level
`handle_event(line, st, now)` takes one raw eve.json line and a state
object and performs exactly the current loop body from the json.loads
(bin/nodeguard-responder:342-343) through the block/dry-run outcome
(bin/nodeguard-responder:442-459); a `make_state(conf)` constructor
builds the state (journal, allow provider, minute deque, hour_seen,
capped_episode, sec counters, and an injectable `block_fn` defaulting
to the current subprocess.run call at bin/nodeguard-responder:450-451).
main() keeps the follow loop, the daily prune scheduling
(bin/nodeguard-responder:324-326), the malformed-count reporting
(bin/nodeguard-responder:327-331), the sids.conf mtime reload
(bin/nodeguard-responder:332-340), and the kv flush; the INVARIANT
comment at bin/nodeguard-responder:8-10 is updated to name
handle_event as the other half of the contract. The extraction moves
code without reordering any gate; the new tests are the check that the
move preserved behavior, and the netns rehearsal plus py_compile remain
as before.

Test coverage (tests/test_responder.py), one test per gate plus the
interactions:

1. event_type gate: non-alert events touch nothing
   (bin/nodeguard-responder:347-349).
2. severity/opt-in gate: sev != 1 without opt-in is dropped; sids.conf
   `block` promotes (bin/nodeguard-responder:367-370, parsing at
   bin/nodeguard-responder:92-116).
3. ignore gate: an ignored SID short-circuits first
   (bin/nodeguard-responder:367-368).
4. anti-spoofing gate: non-TCP without udp-ok logs WOULD BLOCK (not
   eligible); TCP with pkts_toclient < 1 or pkts_toserver < 2 logs the
   no-bidirectional-evidence line (bin/nodeguard-responder:378-386).
5. direction gate: dest outside HOME_NETS, or a non-global source, is
   skipped (bin/nodeguard-responder:395-399).
6. allowlist gate: protected sources skip; a None (undeterminable)
   answer fails toward NOT blocking (bin/nodeguard-responder:401-408).
7. rate caps: the minute cap and the distinct-per-hour cap suppress
   new blocks while journaling sightings, with the capped_episode
   logging collapse (bin/nodeguard-responder:417-437).

Plus: TTL escalation doubles per completed offense and clamps at
TTL_MAX (`min(ttl_base * (2 ** rec.get("count", 0)), ttl_max)` at
bin/nodeguard-responder:439), and only real blocks increment count
while dry-run increments shadow_hits (Journal.offense at
bin/nodeguard-responder:216-227); journal pruning drops records idle
past 30 days (bin/nodeguard-responder:186-191); a corrupt journal is
quarantined to .corrupt and started fresh
(bin/nodeguard-responder:175-183); dry-run and enforce account the
caps identically (the caps run before the enforce branch at
bin/nodeguard-responder:417-448).

The window-suppression case, which is also the post-reboot case
(finding S3, out of scope here): an alert whose source has a journaled
`blocked_until` in the future is recorded as a sighting and not
re-blocked (bin/nodeguard-responder:410-415). The test pins this
current behavior with a comment naming S3, so the future boot_id fix
changes a test deliberately instead of silently.

The rate-cap journaling behavior (item 7 above) is likewise pinned as
current behavior with a forward annotation: finding S6 (change
harden-nodeguard-control-plane, tasks 4.1 and 4.2) will debounce
Journal.save and stop creating journal records for previously unseen
sources while a cap is active. The gate 7 test and the escalation
suite's rate-cap tests therefore carry a comment naming S6, exactly
like the S3 annotation above, so that change edits failing tests
deliberately instead of tripping over them.

## 6. K3: ngmap.py refuses out-of-range integers cleanly

Confirmed mechanics. main() converts only RuntimeError to die()
(bin/ngmap.py:625-626). cmd_set_config packs argparse-typed ints
directly (bin/ngmap.py:457-458): a negative slot breaks `<I`, a
negative value or one at or above 2^64 breaks `<Q`, each raising
struct.error and stack-tracing; slot 0 is range-checked
(bin/ngmap.py:454-455) but only for the wg_port meaning. cmd_block
packs `expiry = mono_ns() + a.ttl * 10**9` (bin/ngmap.py:255-256), so
a huge --ttl overflows `<Q` the same way; nonpositive TTLs are already
refused (bin/ngmap.py:245-247). A positive out-of-range slot is
harmless by comparison (bpftool rejects it and the RuntimeError path
die()s), but the traceback cases land exactly in the kill-switch
workflow (`set-config 1 1`).

Fix:

1. cmd_set_config range-checks before packing: slot in 0 to 4294967295
   and value in 0 to 18446744073709551615, die()ing with the offending
   number and the permitted range. The bounds are the packed widths
   (`<I`, `<Q`), stated as named constants beside the pack calls.
2. cmd_block computes expiry and die()s when it exceeds the 64-bit
   ceiling, phrasing the error in terms of --ttl.
3. Backstop: main()'s conversion widens to `except (RuntimeError,
   struct.error)` so no residual pack site anywhere in the file can
   ever stack-trace an operator; struct.error is the module's
   documented exception class.

Tests (tests/test_ngmap.py): failing-first regressions asserting
SystemExit with a nonzero code and a diagnostic on stderr (not
struct.error) for negative slot, negative value, value == 2^64, and an
overflowing --ttl; plus the positive controls (slot 1 value 1 packs and
calls the faked update_map; a maximal in-range value round-trips).

Also in tests/test_ngmap.py, the T1-mandated guard coverage:
key_bytes/decode_key round-trips for v4 and v6 networks across prefix
lengths (bin/ngmap.py:89-92 and bin/ngmap.py:142-146),
bytes_to_args/args_to_bytes round-trips (bin/ngmap.py:95-103), every
NEVER_BLOCK family refused by is_protected with its reason string
(bin/ngmap.py:50-56 and bin/ngmap.py:222-231), contains_protected
refusing a CIDR that swallows a protected or allowlisted range
(bin/ngmap.py:211-219), and cmd_block's refusal ladder: short prefix
without --i-mean-it, --permanent without --i-mean-it, nonpositive
--ttl, protected target, and a broad target containing a protected
range (bin/ngmap.py:236-254).

## 7. Watchdog EWMA: a path seam for the embedded detector

The detector is a Python heredoc inside bash
(bin/nodeguard-watchdog:24-179, delimited by ANOMPY), with three
hardcoded state paths: the kv snapshot it reads
(bin/nodeguard-watchdog:27), its baseline state
(bin/nodeguard-watchdog:28), and its output kv
(bin/nodeguard-watchdog:29). Tunables already arrive via environment
(bin/nodeguard-watchdog:30-34), set by the bash wrapper at
bin/nodeguard-watchdog:24.

Decision: tests extract the heredoc source from the script file at run
time (the text between the `<<'ANOMPY'` line and the terminating
ANOMPY line; the harness fails loudly if the markers are missing or
ambiguous, and bin/nodeguard-watchdog:246 uses a different delimiter so
the match is unique) and exec it in-process with a controlled
os.environ and captured stdout, catching the detector's deliberate
SystemExit (bin/nodeguard-watchdog:99-102). To point the three paths
at a temp directory, the constants become env-overridable with their
current values as defaults, mirroring how the tunables already work:
`os.environ.get("WD_ANOM_KV", "/run/zabbix/nodeguard.kv")` and
likewise for STATE and OUT. The bash wrapper sets none of the new
variables, so production behavior is bit-identical; the alternative of
textually rewriting the constants in the extracted source was rejected
as fragile against reformatting, and moving the detector into its own
installed file was rejected because it would grow deploy.sh's manifest,
which is finding R2's territory, not this change's.

Test coverage (tests/test_watchdog_anom.py), driving successive cycles
through the extracted detector with crafted kv and state files:

- First cycle seeds last values; unseeded metrics grow an EWMA entry
  only on a non-anomalous cycle (bin/nodeguard-watchdog:143-147).
- Steady deltas update mean and deviation with ALPHA 0.05 and keep
  consec at 0 (bin/nodeguard-watchdog:156-159, 175-176).
- A burst past max(FLOOR, m + K * d) (bin/nodeguard-watchdog:129-131)
  counts consecutive anomalous cycles and fires exactly once at TRIP
  (bin/nodeguard-watchdog:160-173), incrementing anomaly_shadow_count
  in shadow mode and anomaly_count in on mode.
- An anomalous cycle updates no metric's baseline until its skip streak
  reaches ADAPT, after which adaptation is forced
  (bin/nodeguard-watchdog:148-155).
- A regime change (killswitch, attach_state, feeds_enforce) reseeds the
  baseline (bin/nodeguard-watchdog:67-68, 104-106); a prog_id change
  discards one cycle keeping the baseline
  (bin/nodeguard-watchdog:107-110); a negative delta discards likewise
  (bin/nodeguard-watchdog:122-124, 132-135); a stale, missing-ts, or
  unchanged-ts kv discards without touching state
  (bin/nodeguard-watchdog:99-102).
- The output kv is written in every path, including discards
  (write_out at bin/nodeguard-watchdog:89-95, 178).

## 8. Spec placement

Three delta files, one per affected capability:

- `specs/test-suite/spec.md` (new capability, ADDED): the suite's
  existence, hermeticity, build gating, and coverage floor. A new
  capability rather than a rider on an existing one because the suite
  spans four capabilities' code and gates the build for all of them; no
  single behavioral capability owns it, and folding it into one would
  misfile the requirements for the other three.
- `specs/feed-loading/spec.md` (ADDED against the baseline capability):
  the S4 behavior as two requirements, one for per-feed parser
  exception containment and one for the run-crash run-in-progress
  marker semantics, so a future change touching only the marker state
  machine does not have to restate the containment text. These are new
  requirements, not modifications: the existing "Anomalous feed
  content SHALL abort rather than shrink"
  (openspec/specs/feed-loading/spec.md:70) governs run-level gate
  refusals of valid-but-suspicious content (canary coverage, entry and
  coverage caps, churn brake), and the containment requirement scopes
  itself to the per-feed parse and validation boundary and says the
  gates continue to abort, so the two cannot read as contradictory.
  S4 is about parser exception containment for invalid content, a
  distinct behavior.
- `specs/xdp-enforcement/spec.md` (ADDED): the K3 CLI refusal behavior.
  ngmap.py is the map-management CLI of the xdp-enforcement capability,
  which lives in the still-open add-nodeguard-firewall change rather
  than the baseline, so only ADDED requirements are valid here. Archive
  ordering is safe in both directions: if add-nodeguard-firewall
  archives first (its remaining gate is node-3 enforcement,
  ~2026-09-13), this requirement joins the established capability; if
  this change archives first, it seeds the capability directory and the
  firewall change's requirements merge in later. The requirement is
  named so it collides with nothing in
  openspec/changes/add-nodeguard-firewall/specs/xdp-enforcement/spec.md.

## 9. What the suite deliberately does not test

- The XDP program itself: kernel behavior is exercised by the build.sh
  netns rehearsal with real packets (build/build.sh:150-236), which is
  the right layer for it.
- bpftool's real semantics: the lookup-miss regression guard already
  lives in the rehearsal (build/build.sh:128-141) where a real bpftool
  exists. The unit fakes encode the documented contract, not the tool.
- Timers, units, and deploy: findings R1, R2, R3 belong to other
  changes.
- The Zabbix generator suite: build.sh already gates template drift
  (build/build.sh:284-289).
