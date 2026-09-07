# Design: harden-nodeguard-control-plane

Covers evaluation findings S1 (root symlink write into /run/zabbix), S2
(no systemd hardening on any unit), S5 (feed redirect scheme pinning),
and S6 (responder journal write amplification). Every code claim below
was re-verified against the tree on 2026-09-06.

Governing constraints carried from the project conventions:

- Every component fails open; nothing here adds a drop path or changes a
  gate. Over-tight confinement fails a unit loudly (oneshot failure or
  daemon restart), which the existing Zabbix triggers and journal
  CRITICALs surface; it cannot fail silently into wrong enforcement.
- deploy.sh pushes files only; every host-side verification step is a
  human action recorded in proposal.md under Impact, not a task.

## 1. S1: kv files move to root-owned /run/nodeguard

### The defect, located

- bin/nodeguard-geo:37 sets GEO_KV = "/run/zabbix/geo.kv".
  write_atomic (bin/nodeguard-geo:159-164) opens the predictable
  path + ".tmp" with open(tmp, mode), which follows symlinks, then
  os.replace()s it over the destination. Called for the kv at
  bin/nodeguard-geo:202 and for the SVG at :204 (the SVG goes to
  /var/lib/nodeguard, a root-owned directory, and is not exposed).
- bin/nodeguard-watchdog:15-17 writes /run/zabbix/nodeguard.kv.tmp by
  shell redirection and mv -f's it over /run/zabbix/nodeguard.kv every
  minute. Same predictable-temp-in-foreign-directory pattern.
- The anomaly detector reads the same file (bin/nodeguard-watchdog:23
  and the KV constant at :27).
- The agent reads it via both UserParameter lines
  (etc/zabbix-userparameter-nodeguard.conf:7 and :10), and
  nodeguard-status cats geo.kv into the snapshot
  (bin/nodeguard-status:185-188).

/run/zabbix is created by the zabbix-agent package and owned
zabbix:zabbix 0755 (verified live on both hosts during the evaluation).
fs.protected_symlinks only guards symlinks in sticky world-writable
directories, so it does not apply. A compromised zabbix account can
therefore pre-place geo.kv.tmp (or nodeguard.kv.tmp) as a symlink and
every timer cycle makes root truncate and rewrite the target.

### Decision: move the files, do not just harden the opens

New locations: /run/nodeguard/nodeguard.kv and /run/nodeguard/geo.kv.
The directory already exists root:root 0755 via tmpfiles
(etc/tmpfiles-nodeguard.conf:1, "d /run/nodeguard 0755 root root -")
and via mkdir -p in the scripts (bin/nodeguard-watchdog:10,
bin/nodeguard-maps:8). The responder already writes its kv there
(bin/nodeguard-responder:39, RESP_KV = "/run/nodeguard/responder.kv"),
so this move completes an existing pattern rather than inventing one.

O_NOFOLLOW|O_EXCL alone (the report's alternative) was rejected as the
primary fix because it closes only the write-redirect half. The deeper
problem is integrity of the read path: files the agent trusts sitting in
a directory the zabbix user owns means that account can unlink and
recreate nodeguard.kv wholesale with fabricated content, silently
blinding monitoring. Directory ownership fixes both directions at once;
the watchdog's shell-redirection writer also cannot express O_NOFOLLOW
cleanly.

Concrete edits:

1. bin/nodeguard-geo:37: GEO_KV = "/run/nodeguard/geo.kv". write_atomic
   (bin/nodeguard-geo:159-164) changes to: os.unlink the temp path
   first (ignoring ENOENT, so a crashed prior run cannot wedge it),
   open via os.open(tmp, O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW, 0o644),
   write, then os.replace as today. The explicit 0o644 mode replaces
   umask dependence. The guarantee, stated precisely because the test
   asserts it: a symlink pre-existing at the temp path is unlinked,
   never followed; its target is never opened, truncated, or renamed
   over, and the write lands in a freshly created regular file.
   O_EXCL|O_NOFOLLOW closes the unlink-to-open race; both flags are
   defense in depth now that the directory is root-owned.
2. bin/nodeguard-watchdog:15-17: target /run/nodeguard/nodeguard.kv;
   the existing chmod 0644 before mv stays (it is what makes the file
   agent-readable regardless of umask). The "[ -d /run/zabbix ]" guard
   becomes "[ -d /run/nodeguard ]" (created at :10 anyway).
3. bin/nodeguard-watchdog:23 and :27: the anomaly reader follows the
   new path.
4. etc/zabbix-userparameter-nodeguard.conf:7 and :10: both
   UserParameter lines read /run/nodeguard/nodeguard.kv.
5. bin/nodeguard-status:185-188: read /run/nodeguard/geo.kv.
6. Doc lines the move invalidates: README.md:76, docs/design.md:144,
   :369, :503 (the /run/nodeguard row gains the kv exports), :616.
   Only these path references change here; the full docs sweep is the
   D-findings change.

### Agent readability mechanism

DAC: directory 0755 root:root (tmpfiles), files 0644 by explicit mode.
The agent runs as zabbix and needs only world-read; nothing under
/run/nodeguard is ever written by a non-root identity, which is the
whole point.

SELinux is the known risk. Precedent on this fleet: zabbix agent
denials are dontaudit'd (the /var/lib/zabbix incident), so a denial
would present as an unsupported item with an empty ausearch. The move
changes the file label from zabbix_var_run_t (inherited in /run/zabbix)
to var_run_t (default in /run/nodeguard). Verification is behavioral,
at rollout: zabbix_agent2 -t nodeguard.kv.raw (or zabbix_get from the
proxy) must return the snapshot. Fallback if denied: label the tree for
the agent while keeping root DAC ownership, via
semanage fcontext -a -t zabbix_var_run_t "/run/nodeguard(/.*)?" plus
restorecon, and a matching "Z" line in etc/tmpfiles-nodeguard.conf so
the label survives reboot. SELinux types govern read here; DAC
ownership remains the integrity boundary either way. This fallback is
recorded here so the operator applies it deliberately, not as a
deploy.sh mutation (deploy.sh pushes files only).

## 2. S2: systemd hardening across all service units

### What each unit actually touches

Derived by reading every script; this table is the source of truth for
the per-unit directives.

| Unit | Executes | Writes (beyond /tmp) | Talks to |
|---|---|---|---|
| nodeguard-maps.service | ngmap.py create-maps/reconcile-allow (bpftool), getaddrinfo DNS resolve (bin/nodeguard-maps:38), tailscale debug derp-map (:47), ip route/addr, ng_log (bin/nodeguard-maps:35-103) | /sys/fs/bpf/nodeguard, /run/nodeguard (GEN file, bin/nodeguard-maps:22), /var/lib/nodeguard (cache truncation, :18) | network (DNS), /run/tailscale socket, dev-log socket (logger) |
| nodeguard-xdp.service | nodeguard-attach / nodeguard-detach: xdp-loader load/unload/status, bpftool identity checks (bin/nodeguard-lib.sh:44-52, :80-127), ng_log | /sys/fs/bpf/nodeguard, /run/nodeguard (prog_id, expected_prog_id) | netlink, dev-log socket (logger) |
| nodeguard-responder.service | tails eve.json, ngmap.py allow-dump and nodeguard-block (bpftool) via subprocess (bin/nodeguard-responder:135-137, :450) | /var/lib/nodeguard (blocks.json), /run/nodeguard (responder.kv, block.lock via ngmap.py:105) | nothing remote |
| nodeguard-feeds.service | https fetches (bin/nodeguard-feeds:150), ngmap.py map writes, systemctl start --no-block nodeguard-sweep (:871) | /var/lib/nodeguard/feeds, /sys/fs/bpf/nodeguard, /run/nodeguard (block.lock) | network, systemd control socket (/run/systemd/private, falling back to the dbus socket) |
| nodeguard-sweep.service | ngmap.py sweep: bpftool dump/delete | /var/lib/nodeguard (mapstat.kv, sweep_hits.json, ngmap.py:43-44), /sys/fs/bpf/nodeguard, /run/nodeguard (block.lock) | nothing remote |
| nodeguard-geo.service | bpftool map dump read-only (bin/nodeguard-geo:54-56) | /run/nodeguard (geo.kv, post move), /var/lib/nodeguard (attack-map.svg) | nothing remote |
| nodeguard-watchdog.service | nodeguard-status (bpftool, xdp-loader status), ping probes (bin/nodeguard-watchdog:240, :273), tailscale status (:262), ss (bin/nodeguard-lib.sh:57-60), systemctl stop/start nodeguard-xdp (:222, :372), logger (bin/nodeguard-lib.sh:16) | /run/nodeguard (counters, kv export post move), /var/lib/nodeguard (wd_baseline.json, wd_anomaly.kv, bin/nodeguard-watchdog:28-29) | ICMP/UDP/TCP probes, /run/tailscale socket, systemd control socket, dev-log socket (logger) |
| suricata-update.service | /usr/bin/suricata-update, suricatasc (units/suricata-update.service) | /var/lib/suricata; /var/lib/nodeguard once close-nodeguard-alerting-gaps adds its update stamp (see the table note below) | network, /run/suricata command socket |

### Directives

Common block on all eight units:

```
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
```

ProtectSystem=strict mounts the entire hierarchy read-only except
/dev, /proc, and /sys, so /sys/fs/bpf stays writable without an
exception; it is still listed in ReadWritePaths where used, as
documentation and as robustness against a future ProtectSystem
semantic change. Because /dev, /proc, and /sys stay writable, the
declared-paths guarantee is scoped to the persistent filesystem; the
spec says so explicitly, and tightening the API filesystems further
(ProtectKernelTunables, ProtectControlGroups, PrivateDevices) is
deferred to the same post-rollout trimming pass as the capability
sets, because their interaction with the required /sys/fs/bpf writes
must be observed, not assumed.

Unix socket connects need no ReadWritePaths entry. The kernel's
read-only-filesystem check (sb_permission in fs/namei.c, verified
against v6.10 on 2026-09-06) returns EROFS only for regular files,
directories, and symlinks; S_ISSOCK is exempt, and connect() goes
through inode_permission, not mnt_want_write, so read-only bind
mounts do not block it either. This is why journald logging over
/dev/log works inside ProtectSystem=strict units with no exception.
Consequently the table lists no socket paths: systemctl callers
(bin/nodeguard-watchdog:222, :372; bin/nodeguard-feeds:871) reach
/run/systemd/private or the dbus socket, the tailscale CLI reaches
/run/tailscale/tailscaled.sock, ng_log's logger
(bin/nodeguard-lib.sh:16; called by maps, the xdp attach/detach pair,
and the watchdog) reaches /dev/log, and suricatasc reaches the
/run/suricata command socket, all through connects a read-only mount
permits. The rollout observation proves this behaviorally: one
hardened cycle must show a tagged ng_log line landing in the journal
at its stated priority, a completed watchdog soft-off systemctl
cycle, and a successful suricatasc reload, alongside the
EPERM/EROFS/avc grep.

Per-unit ReadWritePaths:

| Unit | ReadWritePaths |
|---|---|
| nodeguard-maps | /run/nodeguard /var/lib/nodeguard /sys/fs/bpf/nodeguard |
| nodeguard-xdp | /run/nodeguard /sys/fs/bpf/nodeguard |
| nodeguard-responder | /run/nodeguard /var/lib/nodeguard /sys/fs/bpf/nodeguard |
| nodeguard-feeds | /run/nodeguard /var/lib/nodeguard /sys/fs/bpf/nodeguard |
| nodeguard-sweep | /run/nodeguard /var/lib/nodeguard /sys/fs/bpf/nodeguard |
| nodeguard-geo | /run/nodeguard /var/lib/nodeguard /sys/fs/bpf/nodeguard |
| nodeguard-watchdog | /run/nodeguard /var/lib/nodeguard /sys/fs/bpf/nodeguard |
| suricata-update | /var/lib/suricata /var/lib/nodeguard |

Table note, cross-change: suricata-update's /var/lib/nodeguard entry
exists for the suricata-update.stamp that close-nodeguard-alerting-gaps
writes via an ExecStartPost line deliberately carrying no "-" prefix
(its design.md section 5). Without the entry, that combination would
fail every successful update on EROFS. The entry is harmless if the
stamp change has not landed and correct once it has, so it is safe in
either landing order. This change records the interaction here and in
its proposal; close-nodeguard-alerting-gaps should mirror the note in
its own cross-change list.

Capabilities. The working assumption, to be confirmed at rollout, is
that bpftool operations require CAP_SYS_ADMIN on this kernel (Fedora
44): since the CAP_BPF split (kernel 5.8) some bpf(2) commands accept
CAP_BPF alone, but pinned-map access through bpffs commonly still
demands CAP_SYS_ADMIN, so the initial sets keep it and trimming waits
for the rollout observations. The evaluation report prescribes only
"trimmed to what bpftool needs"; no empirical capability measurement
exists yet, which is exactly why the sets start permissive. Initial
CapabilityBoundingSet per unit:

| Unit | CapabilityBoundingSet |
|---|---|
| nodeguard-maps | CAP_SYS_ADMIN CAP_BPF CAP_NET_ADMIN |
| nodeguard-xdp | CAP_SYS_ADMIN CAP_BPF CAP_NET_ADMIN CAP_PERFMON |
| nodeguard-responder | CAP_SYS_ADMIN CAP_BPF |
| nodeguard-feeds | CAP_SYS_ADMIN CAP_BPF |
| nodeguard-sweep | CAP_SYS_ADMIN CAP_BPF |
| nodeguard-geo | CAP_SYS_ADMIN CAP_BPF |
| nodeguard-watchdog | CAP_SYS_ADMIN CAP_BPF CAP_NET_ADMIN CAP_NET_RAW |
| suricata-update | CAP_DAC_OVERRIDE |

Rationale for the outliers: nodeguard-xdp carries CAP_PERFMON because
program load under the split-capability model can require it alongside
CAP_BPF and CAP_NET_ADMIN; the watchdog carries CAP_NET_RAW so its ping
probes work even where the ping_group_range sysctl is not permissive;
suricata-update starts with CAP_DAC_OVERRIDE rather than the empty set
its plain file-and-network work suggests, because on Fedora
/var/lib/suricata and the /run/suricata command socket are
suricata-owned, and root stripped of CAP_DAC_OVERRIDE cannot write a
0755 directory it does not own or connect to a group-restricted
socket. The ownership is verified on the hosts at rollout and the set
is trimmed to empty only if an observed full cycle survives it.
CAP_SYS_ADMIN dominating each set is acknowledged:
these sets mainly document intent and cut the incidental capabilities
(CAP_SYS_MODULE, CAP_SYS_RAWIO, CAP_MKNOD, CAP_SYS_BOOT, and the rest
of root's default set), which is where most of the defense-in-depth
value is; NoNewPrivileges plus the syscall filter carry the remainder.

SystemCallFilter: @system-service on every unit; units whose commands
call bpf(2) (all except suricata-update) add bpf explicitly, and
nodeguard-xdp also adds perf_event_open. bpf is in systemd's
@privileged group and not in @system-service, hence the explicit
allowance. The exact group membership on the deployed systemd version
is confirmed at rollout with systemd-analyze syscall-filter; the spec
requirement is written against behavior (units complete their cycle,
escapes are denied), not against a hard-coded syscall list, so a
systemd regrouping cannot silently invalidate it.

### Why over-tightening is a safe failure

A directive that turns out too tight makes the unit fail: a oneshot
exits nonzero (timer units already alarm through the kv staleness and
unit-state triggers) and the responder restarts and alarms through its
unit state. One exception is stated honestly: suricata-update has no
failure telemetry today (evaluation finding O5, owned by
close-nodeguard-alerting-gaps), so an over-tight directive on that one
unit fails visibly in the journal and unit state but raises no alarm
until that change lands; its rollout observation is therefore a
deliberate manual check, not trigger-backed. Fail-open means none of
this can tighten enforcement; the watchdog's soft-off path
(bin/nodeguard-watchdog:216-224) is itself one of the hardened cycles
verified at rollout. The dangerous direction would be a hardening
denial that succeeds partially and silently; the per-unit rollout
observation (one full cycle, journal grepped for EPERM, EROFS, avc) is
aimed exactly there.

Local verification is a unit-file conformance test (stdlib unittest)
that parses every units/*.service file present and asserts the common
hardening block on all of them, whatever their number, then asserts
the two tables above for the eight units this change names. Asserting
the common block globally rather than against a frozen list matters
across changes: fix-nodeguard-state-lifecycle adds
nodeguard-allow-refresh.service and explicitly defers its hardening
here, so with a frozen list that unit would silently escape the
requirement; with the global assertion it fails the test until it
carries the block, and it gains a ReadWritePaths row when both
changes have landed. systemd-analyze security scoring and live cycles
are host-side (proposal Impact).

## 3. S5: https-only feed bodies, checked after redirects

fetch() builds the request at bin/nodeguard-feeds:143 and opens it at
:150 with urllib.request.urlopen, whose default handler chain follows
redirects across schemes; nothing checks where the body actually came
from. All three configured URLs are https (bin/nodeguard-feeds:59-68),
so only the post-redirect landing point can currently be non-https.

Edits, both inside fetch() so every caller inherits them:

1. Before opening: refuse a FEED_DEFS url that does not start with
   https:// with status "failed:non-https feed url" (belt against a
   future config edit).
2. After opening, before reading the body: if not
   r.geturl().startswith("https://"), return
   ("failed:redirect to non-https url <final-url>", None, {}).

Both failures return through the existing failed:* contract
(bin/nodeguard-feeds:153-160), so the per-feed FAILED machinery applies
unchanged: zero withdrawals for that feed (invariant W1), conditional
GET state untouched (a failed body never persists etag state, per the
module docstring), and the existing staleness alerting eventually fires
if the condition persists. Rejected alternative: an opener that refuses
redirects outright would break legitimate same-scheme redirects (CDN
hosts move) for no security gain over checking the final scheme.

## 4. S6: debounced journal saves, capped record creation

### The amplification, located

Journal.save() (bin/nodeguard-responder:193-199) serializes the whole
journal and renames it. It runs on every sighting
(bin/nodeguard-responder:207-214) and every offense (:216-227). The
rate-capped path calls journal.sighting at :432, and sighting's
_rec/setdefault (:201-205) creates a record for a previously unseen
source, so during exactly the storm the caps exist for, every
gate-passing alert costs a full O(journal) rewrite and possibly a new
record. The in-window refresh path at :410-414 saves per alert line
too. Growth is bounded by the 30-day prune (:186-191); churn is the
defect. The precedent for the fix is already in the file: flush_sec
(:299-313) debounces responder.kv to one write per 15 seconds, driven
from the idle sentinel (:318-321) and the per-event path.

### Edits

1. Journal gains a dirty flag and a flush(now) method writing at most
   once per JOURNAL_FLUSH_S (15, matching flush_sec; a named constant
   beside it). sighting() and shadow offenses (dry-run,
   bin/nodeguard-responder:443) mark dirty instead of saving.
2. A real enforced offense (:453, after a successful nodeguard-block)
   still saves immediately: it drives TTL escalation and there is at
   most one per accepted block, already capped at RATE_MIN per minute,
   so immediacy is cheap and escalation state survives a crash.
3. flush points: alongside flush_sec in the idle-sentinel branch and
   the per-event path, plus a finally around the event loop that
   flushes pending state on the way out. The finally alone does not
   cover a real stop: units/nodeguard-responder.service sets no
   KillSignal, so systemctl stop delivers SIGTERM, and Python's
   default SIGTERM disposition terminates the process without
   unwinding; only Ctrl-C reaches the existing KeyboardInterrupt
   handler (:469-473). main() therefore installs a SIGTERM handler
   via signal.signal that raises SystemExit, so both SIGINT and a
   systemd stop unwind through the finally and the flush runs.
   prune() keeps its unconditional save (daily, plus startup).
4. Record-creation cap: in the rate-capped branch (:424-433),
   journal.sighting runs only when src is already in journal.data; a
   previously unseen source increments a suppressed-records counter
   that is included in the capped-episode log line (:427-430) and
   reset when the episode ends. The in-window path (:410-414) always
   has an existing record and is unaffected.

Durability tradeoff, stated: a crash loses at most JOURNAL_FLUSH_S of
sightings and shadow-offense updates (last_seen refreshes and
shadow_hits, never a real offense count, never an enforced block).
Suppressed record creation loses first-seen timestamps for sources
observed only during a capped episode; those sources were by definition
not blocked, and the alternative is letting an attacker inflate the
journal during the storm. Both losses are strictly smaller than what
the existing prune already discards on its 30-day horizon.

## 5. Test surface added by this change

Scoped to the behaviors introduced here (the full suite is T1's
change):

- test_units.py: parses every units/*.service file present and asserts
  the common hardening block on all of them, then asserts the per-unit
  ReadWritePaths and CapabilityBoundingSet tables from section 2 for
  the eight named units, so the design tables and the shipped units
  cannot drift and a unit added by another change cannot ship
  unhardened.
- test_feeds_fetch.py: fetch() against a stub handler; a redirect
  landing on http:// yields a failed:* status and no body; a non-https
  configured URL is refused before any request.
- test_responder_journal.py: a burst of sightings produces at most one
  save per flush interval; an enforced offense saves immediately; with
  the rate cap engaged an unseen source creates no record and the
  suppressed counter increments; the SIGTERM handler is installed and
  raises SystemExit; flush-on-exit persists dirty state on both the
  SystemExit path (the systemd stop route) and the KeyboardInterrupt
  path.
- test_geo_write.py: write_atomic with a symlink pre-placed at the
  temp path never follows it (the link is removed, the write lands in
  a fresh regular file, and the symlink's target is never opened,
  truncated, or renamed over), produces mode 0644 under a 077 umask,
  and still renames atomically.

All stdlib unittest, no network, runnable on the workstation.
