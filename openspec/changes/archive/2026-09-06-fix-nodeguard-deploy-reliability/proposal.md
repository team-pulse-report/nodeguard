# Proposal: fix-nodeguard-deploy-reliability

## Why

The 2026-09-06 evaluation confirmed eight reliability and supply-chain
defects in the build, deploy, unit, and attach-lifecycle layers
(findings R1, R2, R3, B1, B2, B3, B4, B5). They cluster into three
failure classes:

1. Deploys that lie or under-ship. deploy.sh installs the geo unit and
   timer but never the nodeguard-geo executable, so a deploy.sh-built
   host fires a timer into 203/EXEC every 5 minutes forever with no
   alarm (R2). Verification runs after installation, so a verify
   failure leaves the new files live with no rollback; the map spec has
   no .prev rotation even though the object does, and the suricata -T
   validation that mkyaml.py promises never runs anywhere (B3). The
   nodeguard_kern.o.sha256 that ADR 0004 calls "the pairing evidence"
   is printed for a human to eyeball and compared against nothing (B1).
2. Provenance that cannot answer an incident. The build runs in a
   floating fedora:44 image with unpinned clang and records nothing
   about what produced the object, so "did the source change or just
   the compiler" is undecidable (B2). mkyaml.py hardcodes
   suricata-8.0.6-1.fc44 in its output header and nothing checks the
   stock file still matches the RPM on the hosts or flags an
   .rpmnew (B5). install-geoip.sh raises a NameError on every
   successful run and loses its range count (B4).
3. Lifecycle machinery that reports clean while broken. Every
   Type=oneshot unit ships without TimeoutStartSec, which systemd
   defaults to infinity for oneshots: one hung watchdog cycle stops the
   timer firing and halts canary, lifeline, WG-port refresh, and kv
   export until a human acts (R1). nodeguard-detach absorbs
   ng_prog_ids failures at both call sites and reports a clean detach,
   deleting the run files, while the program may still be attached and
   dropping: the dangerous direction for a fail-open design (R3).

## What Changes

- units/: TimeoutStartSec on every Type=oneshot unit, sized to its
  timer period (watchdog 55s, sweep 8min, geo 4min, feeds 30min,
  suricata-update 30min, maps 2min, xdp 2min); untimed external calls
  in the scripts those units run get timeout(1) wrappers. The
  design.md:482 mitigation cell is corrected: a hung oneshot leaves the
  unit activating and the timer stops firing, so "Timer unit alarm" is
  not the mitigation for a hang (R1).
- deploy/deploy.sh: ships, installs, and py_compile-verifies
  bin/nodeguard-geo (it is Python, so it joins the py_compile line, not
  bash -n); the systemd-analyze verify list is derived from the same
  glob that installs units so the two can never diverge again (R2).
  Verifies the local object against build/out/nodeguard_kern.o.sha256
  before staging, passes the expected hash into the remote heredoc, and
  fails before the .prev rotation; installs the .sha256 beside the
  object (B1). Runs the whole verification block against the staged
  copies before any install step, rotates nodeguard-maps.spec to .prev
  together with the object, and adds suricata -T to the verification
  block (B3). Checks the host's installed suricata NVR (arch-free rpm
  query) against the recorded stock version and flags a
  suricata.yaml.rpmnew (B5, deploy half).
- build/build.sh: writes a build-info provenance file into build/out
  beside the object (base image digest, clang and relevant rpm NVRs,
  git commit, build time); README gains pin-by-digest guidance for the
  builder image. This records provenance; it does not claim
  bit-reproducibility (B2).
- build/install-geoip.sh: the month is passed to the embedded Python as
  argv like the other two parameters, removing the f-string NameError
  and restoring the range-count summary line (B4).
- build/mkyaml.py: the stock suricata version moves out of the
  hardcoded header into a committed sidecar
  (build/suricata-stock.version) that mkyaml.py reads; build.sh fails
  if the sidecar is missing (B5, build half).
- bin/nodeguard-detach and bin/nodeguard-attach: capture the
  ng_prog_ids return code at both detach call sites (the initial
  listing and the grep-piped unload recheck) and in attach's initial
  listing; on failure log "attach state UNKNOWN, refusing to report
  clean detach", exit nonzero, and keep the run files (R3).

## Impact

- Affected specs: new capabilities deploy-integrity, build-provenance,
  operational-reliability (all ADDED; the xdp-enforcement,
  suricata-detection, and alert-to-block-response capabilities live in
  the still-open add-nodeguard-firewall change and are not touched).
- Affected code: units/nodeguard-watchdog.service,
  units/nodeguard-sweep.service, units/nodeguard-geo.service,
  units/nodeguard-feeds.service, units/suricata-update.service,
  units/nodeguard-maps.service, units/nodeguard-xdp.service;
  deploy/deploy.sh; build/build.sh; build/install-geoip.sh;
  build/mkyaml.py (plus new build/suricata-stock.version sidecar);
  bin/nodeguard-detach; bin/nodeguard-attach; bin/nodeguard-watchdog
  (timeout wrappers for its direct tailscale calls);
  bin/nodeguard-lib.sh (the timeout wrapper for the shared xdp-loader
  call inside ng_prog_ids, which must preserve that helper's
  three-valued rc contract: a timeout surfaces as nonzero rc, state
  UNKNOWN); docs/design.md line 482 (mitigation cell correction
  only); README.md (builder image pinning guidance).
- Same-file coordination with sibling changes (merge order, not
  conflict; no requirement is double-specified):
  units/suricata-update.service is also edited by
  close-nodeguard-alerting-gaps (ExecStartPost stamp writer); the
  oneshot units' [Service] sections also receive hardening blocks
  from harden-nodeguard-control-plane; deploy/deploy.sh is also
  edited by fix-nodeguard-state-lifecycle (whose new
  nodeguard-allow-refresh units the shared unit list will absorb
  automatically); build/build.sh is also edited by
  add-nodeguard-test-suite (test gate). Implementers should land
  these with the overlaps in view rather than clobbering each other.
- Rollout: applying the changed units, deploy.sh, and binaries to the
  live hosts (devops-hive-node-2 and devops-hive-node-3) is a human
  follow-up performed through the normal phased deploy.sh run after
  this change is implemented and verified locally; it is deliberately
  not a task in this change. Nothing here enables or starts anything.

## Out of scope

- The test suite (T1), state-survival fixes (S3, C1, K1, K2), unit
  hardening (S1, S2), and observability additions (O1 to O7) from the
  same evaluation; they belong to sibling changes.
- Bit-reproducible builds. B2 is resolved by recording provenance and
  pinning guidance, not by promising identical bytes across rebuilds.
- Any change to enforcement behavior, map layout, or the kernel object.
- Moving geo.kv out of /run/zabbix (that is finding S1, a different
  change); this change only fixes shipping the binary and its unit
  timeout.
