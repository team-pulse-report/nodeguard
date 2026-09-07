# Proposal: close-nodeguard-alerting-gaps

## Why

The 2026-09-06 evaluation confirmed eight observability gaps that all
share one shape: machinery can die while its telemetry keeps reading
healthy. A wedged responder serves its last responder.kv values forever
with no heartbeat, no age, and no divergence signal (O1). The template
generator still emits the static per-feed items the LLD prototypes
superseded, the sanction file is empty, and the discovered staleness
triggers sit at Information severity, so the next generate-and-import
resurrects retired objects while check_template.py passes (O2).
feeds_journal_reset (a lost CAS journal) and feeds_map_errors (per-key
map-write failures) have dashboard tiles but no triggers (O3). The
alert-to-block graph plots cumulative resp_blocks_issued and
resp_dryrun_would_block against per-second rates, flattening the lines
the graph exists to compare; the archived telemetry change mandated
rate twins for graphed resp_* items and both shipped without them (O4).
Nothing watches the suricata-update path, so a chronically failing
ruleset update is invisible while all automated blocking depends on
those rules (O5). geo.kv carries no timestamp and nodeguard-geo's
top-level handler swallows every exception and exits 0, so dead geo
serves stale data indefinitely (O6). A dead kv export chain pages one
HIGH plus three or more overlapping nodata WARNINGs that all mean the
same thing (O7). And pass_expired has a rate item but no trigger, so
the expired-more-specific-LPM-shadowing window found in the kernel
review (K2) has no alarm on its sustained symptom.

## What Changes

- nodeguard-responder writes ng.resp_kv_ts on every kv flush and gains
  an idle heartbeat: the kv is rewritten at least once per minute while
  the event loop is alive, even with zero new alerts. It also exports
  ng.resp_lag_s, the alert-to-decision lag measured against the EVE
  record's own timestamp.
- nodeguard-status derives ng.resp_kv_age and ng.geo_age the same way
  it already derives ng.sweep_age, and exports the Suricata ruleset
  freshness pair (ng.suricata_update_ts from a stamp written by the
  update unit on success only; ng.suricata_rules_mtime from the live
  rules file). Absent sources omit the keys: visible unknown, never
  zero.
- nodeguard-geo appends ng.geo_ts to geo.kv on successful runs only, so
  a persistently failing run (which exits 0 by design) ages out
  visibly instead of serving stale data forever.
- units/suricata-update.service gains an ExecStartPost stamp writer
  that records the last successful update epoch; the existing
  spec-mandated nonblocking reload line (with its "-" prefix) is kept.
- zbx/gen-template.py: the static per-feed item rows and their nine
  triggers are deleted from build_rows(); the removals are recorded in
  zbx/removed-objects.txt with reason and date in the same commit; the
  discovered per-feed staleness triggers are promoted from INFO to
  operational severities (stale WARNING, failed-open AVERAGE, frozen
  WARNING). New triggers: feeds_journal_reset WARNING,
  feeds_map_errors WARNING, sustained pass_expired WARNING, responder
  kv age WARNING, alerts-rising-while-consumption-flat divergence
  WARNING, geo age WARNING, and suricata-update staleness WARNING.
  New items: the resp_blocks_issued and resp_dryrun_would_block rate
  twins, resp_kv_age, resp_lag_s, geo_age, suricata_update_ts, and
  suricata_rules_mtime. Trigger dependencies (Zabbix name-referenced,
  rendered through the single render_trigger change point) make the
  nodata-based warnings depend on the frozen-kv HIGH trigger so a dead
  telemetry chain pages once; that HIGH gains a nodata half so it is
  recalculated on a timer and can fire at all once values stop, the
  stats-unreadable trigger is split so its value half is never
  suppressed, and the responder heartbeat and not-consuming warnings
  depend on the pre-existing unit-down trigger for the same page-once
  reason.
- zbx/dashboards.py points the alert-to-block graph at the new rate
  twins instead of the cumulative counters.
- zbx/check_template.py's documented kv surface and
  zbx/sample-nodeguard.kv gain the new keys; the preview and the
  committed templates/zabbix-nodeguard-template.json are regenerated in
  the same commit so generator, checker, and committed artifact stay
  consistent.

## Impact

- Affected specs: telemetry-observability (one MODIFIED requirement,
  four ADDED requirements).
- Affected code: bin/nodeguard-responder (heartbeat, lag),
  bin/nodeguard-status (age derivations, ruleset freshness export),
  bin/nodeguard-geo (geo_ts on success only),
  units/suricata-update.service (ExecStartPost stamp),
  zbx/gen-template.py (item and trigger set, severities, dependencies),
  zbx/dashboards.py (graph datasets), zbx/removed-objects.txt (sanction
  entries), zbx/check_template.py (kv surface, plus a stale-sanction
  guard judged against what the generator emits so it survives the
  baseline being regenerated), zbx/sample-nodeguard.kv,
  zbx/preview-template-v2.json,
  templates/zabbix-nodeguard-template.json (regenerated), and
  docs/design.md, whose statement that the committed template is the v1
  baseline until the phase 2 import this change makes false in the same
  commit.
- Rollout (human follow-up, not gated by this change): deploy the
  changed binaries and unit to devops-hive-node-2 and node-3, run
  systemctl daemon-reload, restart nodeguard-responder, and import the
  regenerated template into the live Zabbix server following the
  established scratch-rehearsal-then-import procedure. The static
  per-feed items were already removed from the live server as the
  archived telemetry change's completed task 2.15; because the
  generator and the sanction file were never moved past that step, the
  next generate-and-import would silently resurrect them, so this
  change (the generator-side sanctioning plus regeneration) must land
  before any further template import.
- Cross-change coordination: units/suricata-update.service is also
  edited by fix-nodeguard-deploy-reliability (TimeoutStartSec) and
  harden-nodeguard-control-plane (hardening block); bin/nodeguard-geo
  and the nodeguard-status geo read are also edited by
  harden-nodeguard-control-plane, which moves GEO_KV to
  /run/nodeguard; and bin/nodeguard-responder is also edited by
  fix-nodeguard-state-lifecycle and harden-nodeguard-control-plane.
  The behaviors are disjoint (fix-nodeguard-state-lifecycle explicitly
  defers the pass_expired trigger to this change); whichever change
  lands second rebases on the shared lines, and this change's geo_ts
  and geo_age edits apply at whichever GEO_KV path is current when it
  lands.

## Out of scope

- The kernel-side K2 fix (deleting contained expired LPM entries at
  insert time) and its ADR documentation; this change ships only the
  telemetry half, the sustained expired-pass trigger.
- Moving geo.kv out of zabbix-owned /run/zabbix (finding S1) and any
  systemd unit hardening (S2); those are security changes with their
  own scope. This change keeps the existing paths.
- The responder heartbeat does not add a watchdog or restart logic; a
  wedged responder becomes visible, it is not auto-remediated.
- Any test-suite buildout beyond focused unit tests for the logic this
  change adds (the full suite is finding T1, a separate change).
- Any enforcement change of any kind.
