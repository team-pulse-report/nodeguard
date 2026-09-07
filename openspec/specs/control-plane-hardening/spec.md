# control-plane-hardening Specification

## Purpose

The containment around the userspace daemons that run as root and parse
input an attacker influences (Suricata's eve.json, downloaded
threat-intel bodies). It covers where root-written files may live, what
each unit is allowed to do beyond its job, how far a hostile transport
or feed body can reach, and the disk cost the responder is allowed to
impose during an event storm. A parser bug here must not equal host
compromise.

## Requirements

### Requirement: Root-written monitoring files SHALL live only in root-owned directories
Every file a nodeguard component writes as root SHALL be created inside
a directory owned by root and writable only by root; no component SHALL
create, write, or rename a file inside a directory owned by a less
privileged user. Files consumed by the monitoring agent SHALL be made
world-readable by explicit file mode, never by relying on the process
umask.

#### Scenario: symlink pre-placement gains nothing
- WHEN an unprivileged account attempts to pre-place a symlink at any
  predictable temporary or final path used by a root kv writer
- THEN the account cannot create the link at all, because the directory
  is root-owned; and should a symlink nevertheless pre-exist at the
  Python kv writer's temporary path, that writer removes the link and
  creates a fresh regular file opened without following symlinks, so
  the link's target is never opened, truncated, or renamed over and no
  root write is ever redirected

#### Scenario: the agent reads the relocated snapshot
- WHEN the monitoring agent polls its master and per-key items after
  the relocation
- THEN it reads the snapshot and the geo kv from the root-owned runtime
  directory and every dependent item parses a value

#### Scenario: a restrictive umask cannot blind monitoring
- WHEN a kv writer runs under a umask more restrictive than 022
- THEN the published files still carry mode 0644 and the agent's read
  succeeds

### Requirement: Control-plane services SHALL be unable to escalate privilege
Every nodeguard service unit and the ruleset update unit SHALL run with
privilege escalation disabled, a capability bounding set reduced to
what the unit's commands require, and a system-call filter denying
syscalls outside the service's needs; a unit whose work requires
bpf(2) SHALL carry that syscall as an explicit allowance rather than
running unfiltered.

#### Scenario: a parser compromise is contained
- WHEN code execution inside a daemon that parses untrusted input
  attempts to acquire a capability outside the unit's bounding set,
  gain privilege through a setuid execution, or invoke a filtered
  syscall
- THEN the kernel denies the attempt: a filtered syscall terminates
  the process and the kill is recorded in the journal, while a denied
  capability acquisition or setuid escalation fails with a permission
  error to the caller, surfacing through the unit's failure state when
  it is fatal to the service

#### Scenario: confinement does not break the map path
- WHEN each hardened unit runs one full normal cycle under its bounding
  set and syscall filter
- THEN every bpftool and loader operation the cycle performs succeeds
  and the journal for the cycle contains no permission, read-only
  filesystem, or access-control denial

### Requirement: Control-plane services SHALL write only their declared state paths
Every hardened unit SHALL run with the persistent filesystem read-only
except an explicit per-unit list of writable paths covering exactly
the runtime directory, state directory, and map pin directory that
unit demonstrably uses, SHALL have no access to home directories, and
SHALL have a private /tmp. The kernel API filesystems (/dev, /proc,
/sys) remain governed by the confinement mechanism's own semantics and
are outside the declared-list guarantee.

#### Scenario: a write outside the declared set fails
- WHEN a process inside a hardened unit attempts to write a persistent
  filesystem path outside the unit's declared writable list
- THEN the write fails on a read-only filesystem, so outside the
  kernel API filesystems and the unit's private /tmp the declared
  writes are the only file mutations the unit can make

#### Scenario: declared paths keep every cycle working
- WHEN each unit performs its normal writes (kv exports, journals,
  state files, map pins) and its socket connects (journal, systemd
  control, tailscaled, suricatasc) during a full cycle
- THEN every write and connect succeeds because the declared list was
  derived from what the scripts actually touch and socket connects
  require no writable mount, and the shipped units are held to the
  documented per-unit list by an automated conformance check

### Requirement: Responder journal persistence SHALL NOT amplify event storms
The responder SHALL debounce journal serialization so sustained
gate-passing alert traffic produces at most one journal write per flush
interval, SHALL persist a real enforced offense immediately, SHALL
flush pending journal state on shutdown, and SHALL NOT create a journal
record for a previously unseen source while the rate cap is engaged,
counting and logging suppressed creations instead.

#### Scenario: an alert storm does not rewrite the journal per line
- WHEN gate-passing alerts arrive faster than the flush interval for a
  sustained period
- THEN the journal file is rewritten at most once per flush interval
  while sighting state accumulates in memory, and no alert is lost from
  gate evaluation

#### Scenario: enforced offenses stay durable
- WHEN a block is actually issued to the kernel map
- THEN the offense count that drives TTL escalation is persisted to the
  journal before the next event is processed, so a crash immediately
  after a block never loses escalation state

#### Scenario: a capped storm cannot inflate the journal
- WHEN the rate cap is engaged and alerts arrive from sources with no
  existing journal record
- THEN no new record is created for them, a suppressed-creation count
  is carried in the capped-episode log line, and sources that already
  have records continue to refresh

#### Scenario: shutdown does not discard pending state
- WHEN the responder is stopped while sightings are pending inside the
  flush interval
- THEN the pending journal state is flushed before exit
