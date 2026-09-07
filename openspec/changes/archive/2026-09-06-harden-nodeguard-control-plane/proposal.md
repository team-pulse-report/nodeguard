# Proposal: harden-nodeguard-control-plane

## Why

The 2026-09-06 evaluation confirmed four control-plane weaknesses that
share one root cause: the userspace daemons run as unconfined root while
handling attacker-influenced input, and two of their write paths trust
directories or upstreams they should not.

- S1 (defect): nodeguard-geo writes /run/zabbix/geo.kv via a predictable
  temp path opened with plain open(), which follows symlinks, inside a
  directory owned by the unprivileged zabbix user (verified live:
  /run/zabbix is zabbix:zabbix 0755, and fs.protected_symlinks does not
  cover this case). A compromised zabbix account can pre-place
  geo.kv.tmp as a symlink and have root truncate an arbitrary file every
  5 minutes. The watchdog's per-minute nodeguard.kv export into the same
  directory has the same exposure, and a zabbix-owned directory also
  lets that account replace the telemetry files wholesale, blinding
  monitoring silently.
- S2 (improvement): all service units run as full root with zero systemd
  hardening. The responder parses attacker-influenced eve.json forever;
  feeds parses internet-downloaded bodies on a timer. json.loads is
  memory-safe and no subprocess uses shell=True, so this is defense in
  depth rather than a known exploit, but today a parser bug equals total
  host compromise on both gateways.
- S5 (improvement): the feeds fetcher follows redirects with no scheme
  pinning, so an upstream 30x to http:// silently delivers blocklist
  content in cleartext to an on-path attacker; downstream gates bound
  the damage.
- S6 (improvement): the RATE_HOUR cap suppresses blocks but not journal
  records: during exactly the storm the caps exist for, every
  gate-passing alert from a new source rewrites the whole blocks.json
  (O(journal) serialization plus rename per alert line). Growth is
  bounded by the 30-day prune; the issue is churn, not unbounded size.

## What Changes

- Relocate every root-written kv file out of zabbix-owned /run/zabbix
  into root-owned /run/nodeguard (already created root:root 0755 by
  etc/tmpfiles-nodeguard.conf): the watchdog's nodeguard.kv export, and
  nodeguard-geo's geo.kv. The Zabbix agent's UserParameter lines read
  the new location; files are chmod 0644 explicitly so readability never
  depends on umask. nodeguard-geo's write_atomic additionally opens its
  temp file with O_CREAT|O_EXCL|O_NOFOLLOW as defense in depth.
  responder.kv already lives in /run/nodeguard and is the pattern.
- Add systemd hardening to all nine service units (the eight nodeguard
  units plus suricata-update): NoNewPrivileges=yes, ProtectSystem=strict
  with explicit per-unit ReadWritePaths, ProtectHome=yes,
  PrivateTmp=yes, a per-unit CapabilityBoundingSet, and
  SystemCallFilter=@system-service with bpf (and perf_event_open for the
  XDP loader unit) added explicitly where the unit's commands need
  bpf(2). Per-unit needs are derived from what each script actually
  touches and tabulated in design.md, including the three DAC
  capabilities the measured Suricata file and socket permissions make
  necessary (the responder's CAP_DAC_READ_SEARCH for the 0750
  /var/log/suricata, the watchdog's and suricata-update's
  CAP_DAC_OVERRIDE for the 0660 command socket and the 2770
  /var/lib/suricata). The bpffs pin entry carries systemd's "-" prefix
  because that directory is created at runtime and does not survive a
  reboot.
- Pin the feeds fetch to https after redirects: a response whose final
  URL (urllib's r.geturl()) is not https:// fails that one feed through
  the existing failed:* path (zero writes, zero withdrawals, staleness
  alerting unchanged), and a configured feed URL that is not https is
  refused up front.
- Debounce responder journal persistence: sightings and shadow offenses
  mark the journal dirty and a flush writes it at most once per flush
  interval (same 15s cadence as the existing responder.kv debounce);
  a real enforced offense still persists immediately, and the journal
  flushes on shutdown; the responder installs a SIGTERM handler so a
  systemd stop actually unwinds through that flush (Python's default
  SIGTERM disposition would otherwise terminate without it). While the
  rate cap is engaged, no new journal record is created for a
  previously unseen source; suppressed creations are counted and
  logged with the capped-episode message.

## Impact

- Affected specs: new capability control-plane-hardening (kv file
  ownership, unit confinement, journal storm behavior); feed-loading
  gains one ADDED requirement (https-only bodies).
- Affected code: bin/nodeguard-geo (GEO_KV path, write_atomic);
  bin/nodeguard-watchdog (kv export path, anomaly reader path);
  bin/nodeguard-status (geo.kv read path);
  etc/zabbix-userparameter-nodeguard.conf (both UserParameter lines);
  units/nodeguard-allow-refresh.service, nodeguard-feeds.service,
  nodeguard-geo.service, nodeguard-maps.service,
  nodeguard-responder.service, nodeguard-sweep.service,
  nodeguard-watchdog.service, nodeguard-xdp.service,
  suricata-update.service (hardening blocks);
  deploy/deploy.sh (the geo unit added to the unit verify loop);
  bin/nodeguard-feeds (fetch scheme pinning);
  bin/nodeguard-responder (Journal debounce and record-creation cap);
  README.md:76 and docs/design.md lines 144, 369, 503, 616 (the
  /run/zabbix path references this change invalidates); new unit tests
  under tests/.
- Cross-change notes (four sibling changes touch the same files):
  - add-nodeguard-test-suite extracts the responder's per-event gate
    pipeline out of main(), the same region as the S6 journal edits
    here; that overlap does not rebase trivially. Expected order: land
    this change first and let the extraction carry the debounce with
    it; if the suite lands first, the S6 edits are reworked onto the
    extracted pipeline instead of main().
  - fix-nodeguard-state-lifecycle edits the responder Journal for S3
    (boot_id, a disjoint function) and adds
    nodeguard-allow-refresh.service, whose hardening it explicitly
    defers to this change; the every-unit conformance test here fails
    until that unit carries the common block, and the unit gains a
    ReadWritePaths row once both changes have landed.
  - close-nodeguard-alerting-gaps edits the responder kv flush path
    (ng.resp_kv_ts on every flush) adjacent to the journal flush
    wiring, and adds a suricata-update ExecStartPost stamp write to
    /var/lib/nodeguard; this change's suricata-update ReadWritePaths
    includes /var/lib/nodeguard precisely so the stamp cannot fail on
    EROFS in either landing order.
  - fix-nodeguard-deploy-reliability adds TimeoutStartSec to the same
    unit files; those edits are directive-disjoint from the hardening
    block and merge cleanly in any order. Its R2 owns the deploy.sh unit
    manifest; this change adds only nodeguard-geo.service and
    nodeguard-geo.timer to the verify loop, so that the geo unit's new
    hardening block is checked on the host, and R2 should replace the
    hand list rather than extend it further.
- Rollout (human follow-up, not blocking tasks): deploy to node-2 and
  node-3 via deploy.sh, then verify on host: systemd-analyze security
  score per unit before and after; one observed full cycle per timer
  unit with journalctl checked for EPERM, EROFS, and avc denials; a
  tagged ng_log line landing in the journal at its stated priority
  from inside a hardened unit, the watchdog soft-off systemctl cycle
  completing, and a suricatasc reload succeeding (proving socket
  connects need no writable-mount exception); the responder opening
  /var/log/suricata/eve.json under its bounding set, and
  ng.suricata_drops and ng.suricata_alerts both still present in
  /run/nodeguard/nodeguard.kv after a hardened watchdog cycle, since
  either key going missing raises no alarm today; ownership of
  /var/lib/suricata and the /run/suricata socket re-checked before
  trimming any DAC capability; and
  zabbix_get or zabbix_agent2 -t against nodeguard.kv.raw proving the
  agent reads /run/nodeguard (agent SELinux denials are dontaudit'd, so
  test the item, not the audit log; if the read is denied, apply the
  fcontext labeling recorded in design.md). Capability sets start
  conservative and are trimmed only after these observations.

## Out of scope

- The full stdlib unittest suite (finding T1) and the crash-class parser
  fixes it gates (S4, K3, B4): a separate change. Tests added here cover
  only the behaviors this change introduces.
- S3 (journal boot_id) and every other state-lifecycle finding: owned by
  fix-nodeguard-state-lifecycle.
- Deploy and reliability findings (R1 timeouts, R2 manifest, R3 rc
  checks, B*): owned by fix-nodeguard-deploy-reliability.
- Sandboxing Suricata itself (stock Fedora RPM ships its own unit) and
  any SELinux policy authoring beyond the one fcontext labeling fallback
  for the agent read.
- Any enforcement behavior change: gates, caps, TTL escalation, and
  block semantics are untouched; this change alters only where files
  live, how units are confined, which bodies are accepted, and how often
  the journal is serialized.
