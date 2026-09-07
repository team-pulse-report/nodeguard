# Tasks: harden-nodeguard-control-plane

Repo implementation and local verification only. Host-side deployment
and the per-unit rollout observations are human follow-ups recorded in
proposal.md under Impact.

## 1. kv relocation out of /run/zabbix (S1)

- [x] 1.1 bin/nodeguard-geo: GEO_KV to /run/nodeguard/geo.kv; rework
      write_atomic to unlink the temp path (ignore ENOENT), open via
      os.open with O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW and mode 0o644,
      write, os.replace; update the module docstring path;
      python3 -m py_compile passes
- [x] 1.2 bin/nodeguard-watchdog: kv export target to
      /run/nodeguard/nodeguard.kv (lines 15-17), the directory guard
      around it dropped as dead (see 5.5), anomaly reader path (lines 23
      and 27); bin/nodeguard-status: geo.kv read path (lines 185-188);
      bash -n and shellcheck clean on both
- [x] 1.3 etc/zabbix-userparameter-nodeguard.conf: both UserParameter
      lines read /run/nodeguard/nodeguard.kv; update the header comment
      naming the export path
- [x] 1.4 Update the path references this move invalidates
      (README.md:76; docs/design.md:144, 369, 503, 616) and grep the
      tree to confirm no writer or reader references /run/zabbix
      anywhere outside the archive directory
- [x] 1.5 tests/test_geo_write.py: a symlink pre-placed at the temp
      path is never followed (the link is removed, the write lands in
      a fresh regular file, and the symlink's target is never opened,
      truncated, or renamed over), files come out 0644 under a 077
      umask, rename is atomic; test passes

## 2. systemd hardening on all nine service units (S2)

- [x] 2.1 Add the common block (NoNewPrivileges, ProtectSystem=strict,
      ProtectHome, PrivateTmp) plus per-unit ReadWritePaths,
      CapabilityBoundingSet, and SystemCallFilter per the design
      section 2 tables to units/nodeguard-maps.service,
      nodeguard-xdp.service, nodeguard-responder.service, and
      nodeguard-watchdog.service
- [x] 2.2 Same for units/nodeguard-feeds.service,
      nodeguard-sweep.service, nodeguard-geo.service,
      suricata-update.service, and nodeguard-allow-refresh.service (the
      ninth unit, whose hardening fix-nodeguard-state-lifecycle deferred
      to this change)
- [x] 2.3 tests/test_units.py: parse every units/*.service file
      present and assert the common hardening block on all of them
      (not a frozen list, so a unit added by another change cannot
      ship unhardened), then assert both per-unit tables for the nine
      units those tables name; test passes

## 3. https-only feed bodies (S5)

- [x] 3.1 bin/nodeguard-feeds fetch(): refuse a non-https configured
      URL before the request; after urlopen, fail the feed when
      r.geturl() does not start with https://, both through the
      existing failed:* return contract; python3 -m py_compile passes
- [x] 3.2 tests/test_feeds_fetch.py: stub handler proving a redirect to
      http:// yields failed:* with no body and no persisted conditional
      GET state, and a same-scheme https redirect still succeeds; test
      passes

## 4. responder journal debounce and record cap (S6)

- [x] 4.1 bin/nodeguard-responder: Journal dirty flag and flush(now) at
      most once per JOURNAL_FLUSH_S; sightings and shadow offenses mark
      dirty; enforced offenses save immediately; flush wired into the
      idle-sentinel and per-event paths and a finally around the event
      loop; install a SIGTERM handler in main() that raises SystemExit
      so a systemd stop (SIGTERM, no KillSignal in the unit) unwinds
      through the finally instead of terminating without a flush;
      python3 -m py_compile passes
- [x] 4.2 bin/nodeguard-responder: in the rate-capped branch, create no
      journal record for a previously unseen source; count suppressed
      creations and include the count in the capped-episode log line
- [x] 4.3 tests/test_responder_journal.py: burst of sightings yields at
      most one save per flush interval; enforced offense saves
      immediately; capped unseen source creates no record and
      increments the suppressed counter; the SIGTERM handler is
      installed and raises SystemExit; exit flush persists dirty state
      on both the SystemExit (systemd stop) and KeyboardInterrupt
      paths; test passes

## 5. Review findings from the 2026-09-06 adversarial pass

- [x] 5.1 Prefix the bpffs entry as -/sys/fs/bpf/nodeguard in all seven
      units that declare it: the pin directory is created at runtime by
      nodeguard-maps and does not survive a reboot, so an unprefixed
      entry fails every one of those units at namespace setup
      (226/NAMESPACE) on every boot and leaves the host open; update
      tests/test_units.py's table and its absolute-path assertion to
      carry the prefix, and record the rule in design.md section 2
- [x] 5.2 Grant nodeguard-responder CAP_DAC_READ_SEARCH: measured on
      node-2 and node-3, /var/log/suricata is 0750 suricata:suricata, so
      root with no DAC capability cannot traverse it to reach eve.json
      and the daemon would crash-loop with enforcement dead; record the
      measurement in design.md and add the eve.json open to the rollout
      observations
- [x] 5.3 Grant nodeguard-watchdog CAP_DAC_OVERRIDE: the Suricata
      command socket is 0660 suricata:suricata on both hosts and
      connect(2) needs write permission, and the failure is silent
      (nodeguard-status omits both suricata keys on a socket error);
      add the suricatasc call to the design's per-unit table and the two
      keys to the rollout observations
- [x] 5.4 Correct suricata-update's rationale with the measured mode:
      /var/lib/suricata is 2770 suricata:suricata, not 0755, which makes
      its CAP_DAC_OVERRIDE required rather than provisional
- [x] 5.5 Drop the dead "[ -d /run/nodeguard ]" guard around the
      watchdog kv export (the script's own mkdir -p two lines earlier
      makes it always true) and keep the INVARIANT comment on the export
- [x] 5.6 Re-resolve the docs/design.md citations into
      bin/nodeguard-watchdog, bin/nodeguard-feeds, and
      bin/nodeguard-responder that this change's insertions shifted
- [x] 5.7 Add nodeguard-geo.service and nodeguard-geo.timer to
      deploy.sh's systemd-analyze verify loop, so the geo unit's new
      hardening block is syntax-checked on the host like every other
- [x] 5.8 tests/test_responder_journal.py: measure the second flush
      interval from journal.last_flush rather than the test's captured
      now, so the not-yet-due assertion states the interval it means
      instead of passing on sub-millisecond drift

## 6. Verification gate

- [x] 6.1 Run bash -n and shellcheck on every changed shell file,
      python3 -m py_compile on every changed Python file, the four new
      test modules via python3 -m unittest, and
      openspec validate harden-nodeguard-control-plane --strict; all
      pass with output captured
