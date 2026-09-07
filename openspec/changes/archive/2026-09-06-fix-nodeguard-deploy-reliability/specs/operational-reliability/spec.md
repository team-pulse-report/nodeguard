## ADDED Requirements

### Requirement: Every oneshot unit SHALL bound its runtime
Every Type=oneshot unit SHALL carry an explicit TimeoutStartSec sized
below its own timer period (or a bounded value for boot-path units), so
a hung run lands the unit in the failed state instead of activating
forever, and external tool invocations inside timer-driven scripts
SHALL be individually time-bounded, with each bound sized to fit inside
the budget of the tightest unit that reaches the call rather than the
loosest.

#### Scenario: a hung watchdog cycle cannot halt failure detection
- WHEN a watchdog cycle blocks on a wedged external tool
- THEN systemd kills the run at TimeoutStartSec (55s, inside the
  1-minute timer period), the unit enters failed where existing alarms
  see it, and the next timer fire starts a fresh cycle, so canary,
  lifeline, WG-port refresh, and kv export resume without human action

#### Scenario: timer-driven oneshots recover within one period
- WHEN any timer-driven oneshot (sweep, geo, feeds, suricata-update)
  hangs mid-run
- THEN the run is killed before its next scheduled fire and the timer
  keeps firing on schedule instead of stalling behind an
  activating-forever service

#### Scenario: one wedged tool fails one step, not the whole budget
- WHEN a single external call (tailscale, xdp-loader, bpftool,
  suricatasc) inside a timer-driven script hangs
- THEN its own timeout expires first and the script handles the failure
  on that step, rather than the whole cycle riding the unit timeout

### Requirement: Detach and attach SHALL treat dispatcher-state read failure as unknown, never as detached
nodeguard-detach and nodeguard-attach SHALL check the ng_prog_ids
return code at every call site, including the piped unload recheck; on
a nonzero return they SHALL log that the attach state is unknown and
they refuse to report a clean result, exit nonzero, and SHALL NOT
delete prog_id or expected_prog_id.

#### Scenario: broken loader at detach start is not a clean detach
- WHEN ng_prog_ids fails at nodeguard-detach's initial listing while
  the program may still be attached and dropping
- THEN detach logs "attach state UNKNOWN, refusing to report clean
  detach" and exits nonzero, so nodeguard-xdp lands in the failed
  state where the existing unit alarms and systemctl status surface
  it (the stop job itself still completes; the failed unit state, not
  the stop command's return code, is the visible signal), and the run
  files survive so ng.prog_match evidence is preserved

#### Scenario: unload recheck does not absorb a loader failure
- WHEN an unload attempt fails and the confirming ng_prog_ids recheck
  itself returns nonzero
- THEN the recheck's return code is evaluated separately from the grep
  over its output, the detach is reported failed, and no run file is
  deleted

#### Scenario: attach refuses to bless an unknown dispatcher state
- WHEN ng_prog_ids fails during nodeguard-attach's pre-existing member
  scan
- THEN attach fails loudly in the existing host-runs-OPEN style instead
  of proceeding as if no member exists
