# Proposal: fix-nodeguard-state-lifecycle

## Why

The 2026-09-06 evaluation confirmed four defects that share one theme:
state surviving past the event that invalidated it (findings S3, C1,
K1, K2).

- **S3 (medium)**: blocks.json persists wall-clock blocked_until
  windows up to 86400s, but the kernel maps and their CLOCK_MONOTONIC
  expiries vanish at reboot (ADR 0003). After a reboot a repeat
  offender passes gates 1 to 6 and is then skipped by the window check
  at bin/nodeguard-responder:411, because the responder believes a
  now-nonexistent kernel block covers it. The longest-escalated, most
  persistent attackers get the longest post-reboot free pass.
- **C1 (medium)**: one transient DNS or tailscaled failure during
  allow-map generation (bin/nodeguard-maps) silently drops the
  resolved-name and DERP-relay protections from the live allow maps,
  making the management fallback path blockable; DERP rides TCP/443,
  which the kernel's UDP-only WireGuard-port hard pass does not cover.
  In the other direction, generated entries go stale indefinitely
  because generation runs only at boot or deploy. Neither direction is
  observable.
- **K1 (medium)**: cmd_block (bin/ngmap.py:255) never reads the
  existing value: a manual permanent entry (expiry 0, reserved for
  manual entries) is silently demoted to a TTL block when the responder
  re-blocks the same address, and the overwrite zeroes hits, removing
  exactly the re-offending sources from the sweep's delta leaderboard.
  The feeds loader already does the correct read-modify-write under
  block_lock; the CLI path has no guard.
- **K2 (low)**: the kernel performs one LPM lookup only
  (src/nodeguard_kern.c:273), so an expired more-specific entry (a
  responder /32) inside a live broader block (a feed CIDR) returns
  XDP_PASS for that host while the rest of the CIDR drops, until the
  sweep deletes the corpse (worst case about 10 minutes). Fail-open
  direction and single address, but neither ADR 0003 nor any spec
  records the interaction.

## What Changes

All four fixes are userspace only; src/nodeguard_kern.c is not touched.

- **Responder journal boot scoping (S3)**: blocks.json gains a
  reserved `_meta` record carrying the boot id (the pattern the feeds
  loader already uses for its own state, bin/nodeguard-feeds:57 and
  :695 to :701). On load, a journal written under a different or
  unknown boot id has every blocked_until window treated as expired;
  offense counts and history are retained, so escalation still applies
  to the re-block. A warm restart in the same boot preserves windows
  unchanged.
- **Allow-generation last-good retention plus refresh (C1)**: the
  resolve and derp directives in bin/nodeguard-maps keep a per-directive
  last-good cache under /var/lib/nodeguard/allow-cache/; a failed
  resolve or DERP fetch falls back to the cached entries instead of
  omitting the protection. A new nodeguard-allow-refresh.timer
  periodically re-runs generation through the sanctioned hitless verb
  (`systemctl reload nodeguard-maps`, which does not propagate to
  nodeguard-xdp and causes no carrier blip). nodeguard-maps exports an
  allow kv (entry count, generation-failure and served-stale flags,
  reconcile timestamp) to root-owned /run/nodeguard, and
  nodeguard-status --kv includes it.
- **cmd_block read-modify-write (K1)**: cmd_block looks up the
  existing value inside block_lock before writing; it refuses to
  overwrite a permanent (expiry 0) entry unless --i-mean-it is passed
  (the responder never passes it), and carries hits forward when
  refreshing a live TTL entry. An expired entry is treated as absent.
- **Contained-corpse deletion at insert (K2)**: when a userspace writer
  inserts a block entry broader than a host route, it deletes expired
  entries strictly contained inside the new entry, under the same
  block_lock hold, re-verifying expiry before each delete exactly as
  the sweep does. Applied in cmd_block and in the feeds reconcile
  insert path. Live contained entries are never touched. ADR 0003
  gains a dated, labelled amendment section documenting the LPM
  shadowing window and this closure; the ADR is not rewritten.

## Impact

- Affected specs: new capability `state-lifecycle` (added
  requirements only; the core enforcement capabilities live in the
  still-open add-nodeguard-firewall change and are not modified here).
- Affected code: bin/nodeguard-responder (Journal load/save, `_meta`
  boot id); bin/nodeguard-maps (directive last-good cache, allow kv
  export); bin/nodeguard-status (--kv includes the allow kv);
  bin/ngmap.py (cmd_block read-modify-write, contained-expired purge
  helper); bin/nodeguard-feeds (insert-path corpse deletion); new
  units/nodeguard-allow-refresh.service and .timer; deploy/deploy.sh
  (ship the new units); docs/adr/0003 (amendment section only).
- Rollout: this change lands in the repository and is verified
  locally. Deployment to the live hosts (devops-hive-node-2 and
  devops-hive-node-3) is a separate human-driven follow-up using the
  existing deploy.sh push plus `systemctl reload nodeguard-maps`, a
  responder restart, and `systemctl enable --now
  nodeguard-allow-refresh.timer` (deploy.sh installs unit files but
  deliberately enables and starts nothing, so the new timer does not
  run until a human enables it), per the phased bring-up discipline in
  docs/design.md; it is deliberately not a task in this change.
- Risk: every fix moves state toward expiry or refusal, never toward a
  new drop path; the fail-open contract is unchanged.

## Out of scope

- Any kernel change (a second LPM lookup or in-kernel corpse handling);
  the kernel keeps exactly one lookup per family by design.
- Zabbix template, trigger, and dashboard wiring for the new kv keys
  (including a trigger on sustained pass_expired rate); that belongs to
  the observability change tracking findings O1 to O7.
- The automated test suite of finding T1 beyond unit tests for the
  logic this change touches.
- The nodeguard-flush variant of the S3 hazard (journal windows
  suppress re-blocking after a same-boot flush); recorded as a residual
  in design.md with rationale.
- systemd hardening of the new units beyond a start timeout (finding
  S2 is a separate change).
