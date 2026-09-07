# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

There are no tagged releases yet; everything below is pre-release work on the
main branch.

## [Unreleased]

### Fixed

- 28 findings from a 36-agent adversarial review (1 blocker, 9 major, 18 minor), including: kill switch writes now verified by read-back with escalation to detach on failure; the sweep re-checks entries under an inter-process lock so a fresh re-block cannot be deleted; attach state is three-valued (attached, detached, unknown) end to end so a broken xdp-loader is never read as a pristine datapath; pre-existing dispatcher members are identity-checked, never blessed; the responder follows eve.json across logrotate without dropping alerts, counts offenses (block windows) rather than alert lines for TTL escalation, and accounts rate caps on attempts identically in dry-run and enforce modes; the IPv4 WireGuard-port pass ignores non-first fragments instead of misreading payload; the deploy owns /etc/logrotate.d/suricata, gates on systemd-analyze verify, and requires the suricata RPM up front; allowlist reconciliation gained a non-propagating systemctl reload verb so it never blips the WAN link.
- The 2026-09-06 adversarial evaluation, in four changes: OpenSpec change
  `fix-nodeguard-state-lifecycle` ("Fix state lifecycle across reboot,
  reload, and re-block paths"), `harden-nodeguard-control-plane` ("Harden
  control plane units, kv writes, transport, journal"),
  `fix-nodeguard-deploy-reliability` ("Verify deploys, time-bound oneshots,
  record build provenance"), and `close-nodeguard-alerting-gaps` ("Close
  alerting gaps with heartbeats, freshness stamps, triggers").

### Pending verification

- Everything under Unreleased was implemented and verified on a macOS
  workstation: the unit suite, `bash -n`, `shellcheck`, `py_compile`, the
  Zabbix template drift gate, and `openspec validate --strict`. The
  container-only gates have NOT run: `build/build.sh`'s kernel compile, BTF
  map-spec generation, and netns attach rehearsal, plus the live
  `systemd-analyze verify`, `suricata -T`, and `rpm` behaviour a real
  `deploy/deploy.sh` run exercises. Run `build/build.sh` on a Fedora 44
  x86_64 build host and re-read one full trace before deploying any of this
  to a gateway; the hardened units in particular change namespace and
  capability behaviour that only a live host can prove.


### Added

- XDP program (`src/nodeguard_kern.c`): a fail-open blocklist firewall loaded
  through the libxdp dispatcher. Per packet, in order: parse failure passes,
  kill switch passes, the host's live WireGuard UDP port hard-passes, an
  allowlist LPM lookup passes, and only an unexpired blocklist hit drops.
  Blocklist TTL expiry is enforced in the kernel against
  `bpf_ktime_get_ns()`, so a dead userspace can never leave a block enforced
  past its expiry. Map declarations in the C source are the single source of
  truth for map parameters.
- Map toolchain (`bin/ngmap.py`): the one place that encodes, decodes, and
  mutates the pinned BPF maps (LPM key layout, block values, config and stats
  slots), with a never-block range guard, plus the CLIs that shell into it:
  block, unblock, list, flush, off, on, status, and sweep
  (`bin/nodeguard-cli`, `bin/nodeguard-maps`, `bin/nodeguard-status`).
- Suricata alert-to-block responder (`bin/nodeguard-responder`): tails
  `eve.json` and inserts offender source addresses only when every gate
  passes: alert events only, severity 1 or an opted-in SID, an anti-spoofing
  gate requiring bidirectional TCP flow evidence (UDP and ICMP alerts are
  log-only unless a SID is promoted by hand), inbound only, an allowlist
  recheck, and rate caps. TTL doubles for repeat offenders up to a maximum;
  a journal records blocks and is pruned. `ENFORCE=no` dry-run is the
  mandatory first-run mode.
- Watchdog (`bin/nodeguard-watchdog`): per-minute lifeline probes over
  allowlisted paths detect datapath death, and a deliberately non-allowlisted
  canary probe detects over-blocking; either condition soft-disables
  enforcement through the kill switch, with latch, hourly re-alarm, and
  bounded once-per-boot auto re-arm semantics. Also refreshes the WireGuard
  port in the config map every cycle.
- Attach and reload discipline (`bin/nodeguard-attach`, `bin/nodeguard-detach`,
  `bin/nodeguard-reload`, `bin/nodeguard-canary`): dispatcher-only loading,
  post-attach verification that the attached program's maps are the pinned
  maps, unload by recorded program id (never `--all`), a hitless
  member-swap reload path, and a self-recovering canary wrapper for attaching
  on a host whose only access path rides the interface being modified.
- systemd units and timers (`units/`): map setup with pin verification and
  allowlist reconciliation, the XDP attach service, the responder service,
  a sweep timer for expired-entry garbage collection, the watchdog timer,
  and a daily Suricata ruleset update timer whose reload step fails open to
  the previous ruleset.
- Container build (`build/build.sh`): compiles the object in a stock Fedora
  container (no compiler on the target hosts), generates
  `nodeguard-maps.spec` from the object so the maps service and the object
  cannot drift, rehearses the exact production pin, attach, verify, and
  unload sequence in a network namespace, and renders per-host
  `suricata.yaml` files (`build/mkyaml.py`, with the stock yaml kept for
  drift comparison).
- Example host configuration (`hosts/example-gateway/`) using documentation
  addresses, and shared config (`etc/protected.conf`, `etc/sids.conf`,
  tmpfiles entry).
- Deploy script (`deploy/deploy.sh`): pushes and verifies files only; it
  enables and starts nothing (bring-up is phased and manual).
- arc42 design document (`docs/design.md`): architecture, failure-mode
  table, phased install plan, and rollback.
- Seven ADRs (`docs/adr/`) recording the load-bearing decisions and their
  rejected alternatives.
- OpenSpec change `add-nodeguard-firewall` (`openspec/`) specifying the XDP
  enforcement, Suricata detection, and alert-to-block response capabilities.
- Threat-intel feed loader (`bin/nodeguard-feeds`, OpenSpec change
  `add-nodeguard-feeds`): fetches Spamhaus DROP v4/v6 and DShield top-20,
  validates each body against that feed's real grammar, and reconciles the
  survivors into the block maps with a 25 h in-kernel TTL so every failure
  decays to no enforcement. Ownership is a journal plus compare-and-swap on
  the written expiry value (the block maps have other writers; a feed that
  failed a run performs zero withdrawals). Enforcement sits behind a double
  gate: the feed listed in `FEEDS_APPLY` in the deployed config AND recorded
  in `approved.json` by an interactive `apply --confirm`; `FEEDS_ENFORCE=no`
  dry-run with reviewable diffs is the mandatory first mode. Ships with a
  oneshot service and 6 h timer (`units/nodeguard-feeds.service`/`.timer`),
  a per-host `feeds.conf` (gates and caps: entry counts, aggregate address
  coverage, churn brake, staleness), `ng.feeds_*` kv fields persisted across
  reboot, and Zabbix items and triggers including per-feed staleness and the
  config/approval-drift tripwire.
- OpenSpec change `add-nodeguard-telemetry` (shipped on both hosts and
  archived 2026-09-06): a count-only `stats2` per-CPU map for
  protocol-sanity counters (TCP flag combinations, low TTL, fragments; every
  new branch still resolves to `XDP_PASS`), a uniform
  fail-to-unsupported kv discipline (a value that cannot be read is
  omitted plus an explicit fail flag, never a silent zero), map-population
  stats cached from the existing 10-minute sweep so the 1-minute path stays
  O(1) in blocklist size, two redundant anomaly layers (gateway-local EWMA
  in the watchdog plus Zabbix seasonal baselines with static ceilings), a
  generated master/dependent template v2, three fleet-scaling dashboards
  (Overview, Security, Capacity and Pipeline), and the `zbx/` generator
  suite that builds the template and dashboards.
- OpenSpec change `add-nodeguard-test-suite` ("Add stdlib test suite and
  contain parser crash paths"): a hermetic stdlib `unittest` suite over the
  userspace control plane (no root, no network, no bpftool, no write outside
  a temporary directory), run as `build/build.sh`'s first gate so a broken
  control plane never spends compile or rehearsal time, plus the parser
  crash paths it caught.

### Changed

- Telemetry shipped and archived (2026-09-06): the `stats2` object is
  deployed on both hosts, the three enhanced dashboards replaced the legacy
  Nodeguard board, `WD_ANOM_MODE=on` is live fleet-wide (alerting only; the
  detector never touches enforcement), and the remaining anomaly-detector
  maturation is carried as operational follow-up rather than a spec change.
  ADR 0007 moved from proposed to accepted with it.
- Responder enforcement enabled on the internet gateway, node-2
  (2026-09-06), after a 44 hour dry-run in which the anti-spoofing gate
  rejected all 362 single-packet reputation alerts and blocked nothing. The
  remote node (node-3) stays in dry-run until a clean week on node-2.
  Suricata's memory caps were finalized from the same production data
  (MemoryHigh 1.5 GiB, MemoryMax 3 GiB, against an observed 872 MB peak).
