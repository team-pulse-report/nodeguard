# Tasks: add-nodeguard-test-suite

Every task is local repo work plus local verification. Deploying the
fixed scripts to the gateways is a human follow-up recorded in
proposal.md, not a task here.

## 1. Harness and ngmap coverage (with the K3 fix)

- [ ] 1.1 Write tests/ngtest.py part 1 (loaders): `load_bin(
      module_name, filename)` loading extensionless bin/ scripts via
      importlib.machinery.SourceFileLoader with a per-run module
      cache; prepend the repo's bin/ to sys.path before loading the
      feeds module so its `import ngmap` (bin/nodeguard-feeds:47-48)
      resolves to the repo copy; heredoc extractor for the watchdog
      ANOMPY block that fails loudly on a missing or ambiguous marker
- [ ] 1.2 Write tests/ngtest.py part 2 (fakes): shared in-memory fake
      for the ngmap map helpers (update_map, dump_map, lookup_value,
      delete_key, allow_entries_live) honoring the miss-is-None and
      delete-absent-is-False contracts
- [ ] 1.3 Write tests/test_ngmap.py part 1: key_bytes/decode_key and
      bytes_to_args/args_to_bytes round-trips for v4 and v6 across
      prefix lengths; is_protected refusal with reason for an address
      in every NEVER_BLOCK range and for live allow entries;
      contains_protected refusal of a CIDR swallowing a protected or
      allowlisted range
- [ ] 1.4 Write tests/test_ngmap.py part 2: cmd_block refusal ladder
      (short prefix without --i-mean-it, --permanent without
      --i-mean-it, nonpositive --ttl, protected target, broad target
      containing a protected range) against the fakes, with
      BLOCK_LOCK redirected to a temp path; positive control asserting
      a permitted block writes the expected key and value bytes
- [ ] 1.5 K3 failing-first regressions: set-config with negative slot,
      negative value, and value == 2^64, and block with an
      expiry-overflowing --ttl, each asserting SystemExit nonzero with
      a one-line stderr diagnostic and no struct.error; confirm all
      four FAIL against the current code
- [ ] 1.6 Implement the K3 fix in bin/ngmap.py: range checks in
      cmd_set_config (slot fits `<I`, value fits `<Q`, bounds as named
      constants), expiry-ceiling refusal in cmd_block phrased in terms
      of --ttl, and `struct.error` added to main()'s die() conversion;
      1.5 tests now pass, 1.3 and 1.4 stay green;
      `python3 -m py_compile bin/ngmap.py` clean

## 2. Feeds parsers and gates (with the S4 fix)

- [ ] 2.1 Write tests/test_feeds.py part 1 (parsers): valid Spamhaus
      and DShield fixtures pass; hostile Spamhaus bodies rejected as
      validation failures, split by what they prove: the S4
      failing-first set, each confirmed to FAIL against the current
      code (records as list, null, or dict, which raise TypeError
      today; records as boolean or numeric string, and cidr as JSON
      integer or boolean, which are silently accepted today), and the
      pinned current-behavior set that stays green across the fix
      (records as non-numeric string; cidr as list, dict, or null;
      missing trailer; trailer not final line; truncated body with
      mismatched trailer count; undecodable bytes); hostile DShield
      bodies rejected (fewer than 3 columns, non-/24 mask, end not
      the broadcast address)
- [ ] 2.2 Implement the S4 parser layer in bin/nodeguard-feeds:
      type-check cidr (str) and records (int, bool excluded) in
      parse_spamhaus, raising ValueError; broaden the obtain() parser
      catch (bin/nodeguard-feeds:359) to Exception, logging the
      exception class and keeping the FAILED path plus last-bad
      snapshot; 2.1 passes; py_compile clean
- [ ] 2.3 Implement the S4 run layer: add a writes counter incremented
      after each successful map mutation in one_key and withdraw_key;
      add the `except Exception` handler in run() that marks all feeds
      failed, runs finish(), clears run_in_progress only when no write
      occurred, and re-raises; py_compile clean
- [ ] 2.4 Write tests/test_feeds.py part 2 (run-level S4
      containment), with fetch, allow_snapshot, and the ngmap helpers
      patched and all state paths pointed at a temp dir: a
      TypeError-provoking body fails one feed while a sibling feed
      completes and run_in_progress ends cleared; an injected
      unexpected exception with zero writes clears run_in_progress
      and the next Run does not report adoption mode; an injected
      unexpected exception after a write leaves run_in_progress set
- [ ] 2.5 Write tests/test_feeds.py part 3 (feed gates), on the same
      patched boundaries: canary coverage fails the whole feed, entry
      caps and coverage caps raise GateAbort, per-entry protected
      rejection, cross-feed dedupe ownership order, churn brake holds
      inserts and withdrawals, FAILED feed plans zero withdrawals per
      invariant W1

## 3. Responder gates, escalation, and journal

- [ ] 3.1 Behavior-preserving extraction in bin/nodeguard-responder:
      move the per-event body of main()'s loop
      (bin/nodeguard-responder:342-459) into module-level
      `handle_event(line, st, now)` with `make_state(conf)` bundling
      journal, allow provider, rate structures, sec counters, and an
      injectable block_fn defaulting to the current subprocess call;
      main() keeps follow(), prune scheduling, malformed reporting,
      sids reload, and kv flushing; update the INVARIANT comment
      (bin/nodeguard-responder:8-10) to name handle_event; py_compile
      clean and a manual diff review confirming no gate reordered
- [ ] 3.2 Write tests/test_responder.py part 1 (the seven gates): one
      test per gate driving a fixture line that fails exactly that
      gate and asserting its documented outcome, plus the all-gates
      pass fixture asserting a block via the recording block_fn in
      enforce mode and a WOULD BLOCK journal update in dry-run; the
      window-suppression test (future blocked_until yields a sighting
      and no block) annotated as the behavior finding S3 will change;
      the rate-cap gate test annotated as the behavior finding S6
      (harden-nodeguard-control-plane) will change
- [ ] 3.3 Write tests/test_responder.py part 2: TTL escalation doubles
      per completed offense and clamps at TTL_MAX; dry-run offenses
      raise shadow_hits and never count; rate caps suppress new blocks
      while journaling sightings, with identical accounting in both
      modes and the capped_episode log collapse, the sighting-journal
      and any save-per-sighting assertions annotated as behavior
      finding S6 (harden-nodeguard-control-plane, journal-save
      debounce and no record creation for unseen capped sources) will
      change; journal pruning drops
      records idle past 30 days; a corrupt journal file is quarantined
      to .corrupt and startup continues; AllowCache returns None on a
      failed allow-dump (patched subprocess) and handle_event then
      skips toward NOT blocking

## 4. Watchdog EWMA detector

- [ ] 4.1 Add the env seam in bin/nodeguard-watchdog: KV, STATE, and
      OUT in the ANOMPY heredoc (bin/nodeguard-watchdog:27-29) become
      os.environ.get lookups defaulting to the current literal paths;
      the bash wrapper is unchanged; `bash -n` and shellcheck clean on
      bin/nodeguard-watchdog
- [ ] 4.2 Write tests/test_watchdog_anom.py using the harness
      extractor and env-pointed temp paths, driving successive cycles:
      baseline seeding on non-anomalous cycles only; EWMA mean and
      deviation updates on steady deltas; a burst past
      max(FLOOR, m + K * d) trips exactly once at TRIP consecutive
      cycles, incrementing anomaly_shadow_count in shadow mode and
      anomaly_count in on mode; anomalous cycles update no baseline
      until ADAPT forces adaptation; regime change reseeds; prog_id
      change and negative delta each discard one cycle keeping the
      baseline; missing, unchanged, and stale kv_ts discard without
      touching state; the output kv is written on every path

## 5. Build wiring and verification

- [ ] 5.1 Wire the suite into build/build.sh as a `== unit tests ==`
      step (`python3 -m unittest discover -s "$REPO/tests" -v`) after
      the toolchain install and before the compile; update
      CONTRIBUTING.md's style and verification sections to name the
      suite; `bash -n` and shellcheck clean on build/build.sh
- [ ] 5.2 Full local verification gate: `python3 -m unittest discover
      -s tests -v` green from the repo root; `python3 -m py_compile`
      on every touched Python file (bin/ngmap.py, bin/nodeguard-feeds,
      bin/nodeguard-responder, tests/*.py); `bash -n` and shellcheck
      on bin/nodeguard-watchdog and build/build.sh; deliberate revert
      spot-check that the S4 and K3 regression tests fail when their
      fixes are backed out locally; `openspec validate
      add-nodeguard-test-suite --strict` passes
