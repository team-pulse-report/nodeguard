# Tasks: fix-nodeguard-deploy-reliability

Deployment to the live hosts is a human follow-up (proposal.md,
Impact); every task below is repo implementation or local verification
only.

## 1. Unit timeouts (R1)

- [ ] 1.1 Add TimeoutStartSec to every Type=oneshot unit per the
      design table: nodeguard-watchdog.service 55s,
      nodeguard-sweep.service 8min, nodeguard-geo.service 4min,
      nodeguard-feeds.service 30min, suricata-update.service 30min,
      nodeguard-maps.service 2min, nodeguard-xdp.service 2min
- [ ] 1.2 Correct the docs/design.md:482 mitigation cell: a hung
      watchdog leaves the oneshot activating and the timer stops
      firing, so the mitigation is TimeoutStartSec converting the hang
      into a failed unit the existing alarms see, not "Timer unit
      alarm"
- [ ] 1.3 Sweep bin/nodeguard-watchdog (and any other script run by a
      timer unit) for untimed external calls (tailscale, xdp-loader,
      bpftool, suricatasc) and wrap each in timeout(1) with a bound
      well under the unit's TimeoutStartSec. The shared xdp-loader
      call lives in ng_prog_ids (bin/nodeguard-lib.sh:42-51); wrap it
      there, preserving the helper's three-valued rc contract (a
      timeout expiry returns nonzero with a logged error, which
      callers treat as state UNKNOWN, never as detached)
- [ ] 1.4 Verify: systemd-analyze verify passes locally on every
      changed unit where the tooling allows; bash -n and shellcheck
      clean on bin/nodeguard-watchdog

## 2. Detach and attach rc integrity (R3)

- [ ] 2.1 bin/nodeguard-detach: capture the ng_prog_ids rc at the
      initial listing (line 15); on nonzero rc log "attach state
      UNKNOWN, refusing to report clean detach", exit nonzero, delete
      no run files
- [ ] 2.2 bin/nodeguard-detach: rework the unload-failure recheck
      (line 30) to capture ng_prog_ids output and rc separately before
      grepping; a nonzero rc marks the detach failed and keeps the run
      files, same message as 2.1
- [ ] 2.3 bin/nodeguard-attach: capture the ng_prog_ids rc at the
      initial listing (line 12) instead of absorbing it with
      "|| existing="""; on nonzero rc fail the attach loudly in the
      existing "host runs OPEN" style
- [ ] 2.4 Verify: bash -n and shellcheck clean on both scripts; desk
      exercise the three-valued contract by stubbing ng_prog_ids
      (rc 0 with ids, rc 0 empty, rc 1) in a scratch harness and
      asserting exit codes and run-file retention for each case

## 3. Deploy manifest completeness (R2)

- [ ] 3.1 deploy/deploy.sh: add bin/nodeguard-geo to the scp list and
      the sbin install loop; add /usr/local/sbin/nodeguard-geo to the
      py_compile line (it is Python, not bash)
- [ ] 3.2 deploy/deploy.sh: materialize the staged unit list once in
      the remote heredoc (a single "$S"/*.service "$S"/*.timer glob
      expansion into a shell variable or array), rewrite the install
      command at deploy/deploy.sh:105-106 (currently nodeguard-*
      globs plus explicitly named suricata-update files) to consume
      that one list, and derive the systemd-analyze verify loop from
      the same list, replacing the hand-maintained eleven-unit list;
      install set and verify set must be one definition, not two
      expressions that can diverge
- [ ] 3.3 Verify: run the glob-derivation snippet locally against
      units/ plus a sample host dir and confirm the derived list
      contains every installed unit including nodeguard-geo.service
      and nodeguard-geo.timer; bash -n and shellcheck clean

## 4. Kernel object hash verification (B1)

- [ ] 4.1 deploy/deploy.sh: with --with-kernel, verify
      build/out/nodeguard_kern.o against
      build/out/nodeguard_kern.o.sha256 locally before staging; abort
      on mismatch or missing .sha256
- [ ] 4.2 deploy/deploy.sh: pass the expected hash into the remote
      heredoc; the remote side recomputes the staged object's hash and
      fails before the .prev rotation on mismatch; ship and install
      the .sha256 beside the object; replace the eyeball-only
      sha256sum print at line 165 with the comparison result
- [ ] 4.3 Verify: bash -n and shellcheck clean; rehearse the mismatch
      path locally by corrupting a scratch copy of the .sha256 and
      confirming the pre-staging check aborts

## 5. Verify-before-install, spec .prev, suricata -T (B3)

- [ ] 5.1 deploy/deploy.sh: move the whole verification block (bash
      -n, py_compile, unit verify, content greps, hash comparison,
      stock-version check) ahead of the first install command,
      operating on the staged copies under $S; the unit verify step
      runs over the staged unit files and filters
      executable-existence diagnostics for ExecStart/ExecStop paths
      whose basenames are present in $S (they are syntax-verified
      separately and installed by this run), so a first deploy to a
      bare host is not spuriously failed and an upgrade deploy does
      not silently verify against the old installed binaries (design
      section 6)
- [ ] 5.2 deploy/deploy.sh: add suricata -T against the staged
      suricata.yaml to the verification block, feeding verify_fail
      like the existing checks
- [ ] 5.3 deploy/deploy.sh: rotate nodeguard-maps.spec to .prev under
      the same only-when-different guard as the object, so object and
      spec roll back as a pair
- [ ] 5.4 Verify: bash -n and shellcheck clean; trace the heredoc by
      reading it top to bottom and confirming no install command
      precedes a verification step

## 6. Build provenance (B2)

- [ ] 6.1 build/build.sh: write build/out/nodeguard_kern.o.buildinfo
      beside the object with clang --version, rpm -q NVRs for the
      installed toolchain packages, the repo git commit (unknown if
      unavailable), the base image digest when discoverable (unknown
      otherwise), and the build UTC timestamp
- [ ] 6.2 README.md: add builder-image pin-by-digest guidance showing
      the concrete working invocation that populates the buildinfo
      digest field: resolve the digest on the host
      (docker inspect --format '{{index .RepoDigests 0}}' fedora:44),
      pass it with -e IMAGE_DIGEST="...", and run fedora@sha256:...
      as the image; name the buildinfo file as the audit trail and
      state explicitly that this records provenance and does not
      promise bit-reproducibility
- [ ] 6.3 Verify: bash -n and shellcheck clean on build/build.sh

## 7. install-geoip NameError and stock drift (B4, B5)

- [ ] 7.1 build/install-geoip.sh: pass MONTH into the embedded Python
      as argv alongside src and share; print the summary line from
      argv; remove the .replace hack
- [ ] 7.2 Verify B4: run the embedded preprocessor against a 3-row
      fixture CSV (gzipped, in the scratch area) and assert it prints
      the range count and month with no traceback; bash -n and
      shellcheck clean
- [ ] 7.3 Add build/suricata-stock.version containing
      suricata-8.0.6-1.fc44; build/mkyaml.py reads it and renders the
      generated header from it; build/build.sh fails if the sidecar is
      missing
- [ ] 7.4 deploy/deploy.sh: ship the sidecar; in the pre-install
      verification block compare the host's installed suricata NVR
      against it using the arch-free query
      rpm -q --qf '%{NAME}-%{VERSION}-%{RELEASE}' suricata (plain
      rpm -q prints the arch-qualified NVRA and would warn on every
      deploy), warn on drift, and warn on an existing
      /etc/suricata/suricata.yaml.rpmnew
- [ ] 7.5 Unit tests: stdlib unittest covering mkyaml.py sidecar
      handling (header rendered from the sidecar content; missing
      sidecar exits nonzero), runnable locally with python3 -m
      unittest
- [ ] 7.6 Verify: python3 -m py_compile on build/mkyaml.py and
      bin/nodeguard-geo; the new unit tests pass

## 8. Change gate

- [ ] 8.1 Full local gate: bash -n and shellcheck on every touched
      shell script; python3 -m py_compile on every touched Python
      file; the unit tests from 7.5 pass; openspec validate
      fix-nodeguard-deploy-reliability --strict passes
