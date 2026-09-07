# Proposal: add-nodeguard-test-suite

## Why

The userspace control plane is roughly 2,800 lines of security-critical,
stdlib-pure Python with zero automated tests: the responder's seven
gates and TTL escalation (473 lines), the feeds fetch/parse/gate/CAS
stack (962 lines), the watchdog's EWMA anomaly detector, and ngmap.py's
protection guards are verified only by py_compile and by production
(evaluation finding T1). The 2026-09-06 review confirmed the cost with
crash-class bugs in pure functions that a single-invocation test would
have caught, two of which this change fixes test-first:

- S4: a syntactically valid Spamhaus JSONL body whose metadata trailer
  carries a non-numeric records field raises TypeError at
  bin/nodeguard-feeds:189, past the ValueError-only handler at
  bin/nodeguard-feeds:359. The whole run dies for all feeds with
  state.json left at run_in_progress=True, which arms bounded
  crash-adoption mode on a later run. A remote party should not be able
  to crash the loader or arm adoption.
- K3: a negative slot or value, or a value at or above 2^64, reaches
  struct.pack in cmd_set_config (bin/ngmap.py:457) and raises
  struct.error, which main() (bin/ngmap.py:625) does not convert to
  die(); an oversized --ttl overflows the packed expiry in cmd_block
  (bin/ngmap.py:256) the same way. A kill-switch invocation that
  stack-traces mid-incident undermines operator confidence.

## What Changes

- New `tests/` directory: a stdlib-only Python unittest suite that runs
  on any machine with python3; no root, no network, no bpftool.
  Subprocess boundaries (bpftool, the nodeguard-block wrapper, the
  allow-dump call) and the HTTP transport are faked; the extensionless
  `bin/` scripts are imported from their file paths via importlib.
- Coverage per finding T1: the responder's seven gates including the
  blocked_until window suppression that a reboot leaves behind, hostile
  and truncated Spamhaus and DShield bodies driven through the parsers
  and gates, TTL escalation and journal pruning, the watchdog EWMA
  detector's seed/adapt/trip/reseed/discard paths, and ngmap.py encode
  and decode round-trips plus the NEVER_BLOCK guards.
- build/build.sh runs the suite as a gate before the compile and netns
  rehearsal steps, so a test failure fails the build first; the suite
  stays independently runnable via `python3 -m unittest discover -s
  tests`.
- Fix S4 test-first: type-check the Spamhaus cidr and records fields
  (the records check closes the confirmed TypeError crash; the cidr
  check closes silent acceptance of JSON integers and booleans as
  bogus /32 networks), contain any parser exception to the one feed
  via the existing FAILED path, and clear run_in_progress when an
  unexpected exception escapes a run that has written nothing.
- Fix K3 test-first: range-check slot and value in cmd_set_config,
  refuse a --ttl whose packed expiry cannot fit in 64 bits, and convert
  struct.error to die() in main() as a backstop.
- Two small testability seams, behavior-preserving in production: the
  responder's per-event gate pipeline is extracted from the main() loop
  body into a module-level function, and the watchdog's embedded
  anomaly detector reads its three state-file paths from environment
  variables that default to the current hardcoded values.
- CONTRIBUTING.md's verification list gains the unittest run.

## Impact

- Affected specs: new capability `test-suite`; delta on baseline
  `feed-loading` (hostile-body containment, S4); delta on
  `xdp-enforcement` (CLI integer-range refusal, K3). The
  xdp-enforcement capability is still owned by the open
  add-nodeguard-firewall change, so the delta here is ADDED
  requirements only; whichever change archives first seeds the
  capability and the other's requirements join it.
- Affected code: new tests/ (harness plus four test modules);
  bin/nodeguard-feeds (parser type checks, broadened parser catch,
  write counter, unexpected-exception handling in run());
  bin/ngmap.py (range checks in cmd_set_config and cmd_block,
  struct.error conversion in main()); bin/nodeguard-responder
  (behavior-preserving extraction of the per-event pipeline);
  bin/nodeguard-watchdog (env-overridable state paths in the ANOMPY
  heredoc, defaults unchanged); build/build.sh (unit-test gate);
  CONTRIBUTING.md (verification list); README.md, docs/code-map.md, and
  docs/design.md (the new tree and the new build gate recorded, and the
  build/build.sh line citations the gate shifted).
- Rollout: deploying the fixed bin/ scripts to devops-hive-node-2 and
  devops-hive-node-3 is a human follow-up via deploy/deploy.sh after
  this change is implemented and validated; it is deliberately not a
  task in this change. The test suite itself never ships to the hosts;
  it runs in the build container and on developer machines.
- Out of scope: finding B4 (install-geoip.sh NameError; build tooling,
  separate change), finding S3 (responder boot_id journal fix; the
  suite's window-suppression test documents current behavior and will
  be updated by that change), finding S6 (journal write amplification;
  the rate-cap tests document current behavior and are annotated for
  harden-nodeguard-control-plane), netns or integration tests beyond
  the
  existing build.sh rehearsal, coverage tooling or thresholds, CI
  systems other than build.sh, and any change to enforcement behavior,
  gate ordering, or the kernel program.
