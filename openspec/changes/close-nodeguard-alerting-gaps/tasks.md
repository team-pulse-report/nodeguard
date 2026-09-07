## 1. Responder heartbeat and lag (O1)

- [ ] 1.1 bin/nodeguard-responder: write ng.resp_kv_ts on every flush
      and add the 60s idle-heartbeat clause to flush_sec (write even
      with sec_dirty false once 60s have passed; keep the 15s dirty
      debounce unchanged); yield the idle sentinel from follow()'s
      FileNotFoundError wait branch after its sleep, so the heartbeat
      keeps advancing while eve.json is absent; verify with
      python3 -m py_compile
- [ ] 1.2 bin/nodeguard-responder: compute ng.resp_lag_s per consumed
      alert from the EVE record's own timestamp
      (datetime.fromisoformat, clamp at 0, integer); absent or
      unparseable timestamps keep the previous value and never raise
      past the per-event guard; py_compile again
- [ ] 1.3 Focused stdlib unittests for the new pure logic: heartbeat
      cadence decision (dirty vs idle vs under-60s, including the
      missing-eve.json wait path yielding the sentinel), lag parse
      against
      hostile timestamp inputs (missing, garbage, future-dated); run
      them with python3 -m unittest; coordinate file layout with the
      T1 suite change if it has landed first

## 2. Freshness producers and exporter derivations (O5, O6)

- [ ] 2.1 bin/nodeguard-geo: append ng.geo_ts=<epoch> to the kv lines
      in main() before write_atomic, so the timestamp advances on
      successful runs only; python3 -m py_compile
- [ ] 2.2 units/suricata-update.service: add an ExecStartPost (no "-"
      prefix, success-gated) writing the epoch to
      /var/lib/nodeguard/suricata-update.stamp; keep the existing "-"
      prefixed nonblocking reload line untouched
- [ ] 2.3 bin/nodeguard-status: derive ng.resp_kv_age from resp_kv_ts
      and ng.geo_age from geo_ts (sweep_age pattern, emitted only when
      the source key is present); export ng.suricata_update_ts from
      the stamp file and ng.suricata_rules_mtime from the rules file
      mtime, both omitted when the source is absent or unreadable;
      bash -n and shellcheck clean

## 3. Template generator: retirement, triggers, twins, dependencies

- [ ] 3.1 zbx/gen-template.py: delete the static per-feed FEEDS loop
      rows and the feed_triggers/feed_frozen_trigger static builders
      from build_rows(); add the 15 sanction entries (6 items by key,
      9 triggers by name, reason, date 2026-09-06) to
      zbx/removed-objects.txt in the same commit (O2)
- [ ] 3.2 zbx/gen-template.py: promote the three LLD prototype trigger
      severities to WARNING / AVERAGE / WARNING and drop the parity
      window wording from their descriptions, keeping the nodata
      guards (O2)
- [ ] 3.3 zbx/gen-template.py: add the WARNING triggers
      last(feeds_journal_reset)=1 and min(feeds_map_errors,13h)>0 on
      their existing rows (O3)
- [ ] 3.4 zbx/gen-template.py: add rate twins for resp_blocks_issued
      and resp_dryrun_would_block; zbx/dashboards.py: point the
      alert-to-block graph datasets at the twin display names (O4)
- [ ] 3.5 zbx/gen-template.py: add the K2 trigger, WARNING on
      min(pass_expired,15m)>0, documenting the placeholder threshold
      and the sweep-corpse rationale in its description
- [ ] 3.6 zbx/gen-template.py: add the new freshness items and
      triggers: resp_kv_age (WARNING last()>120), resp_lag_s (no
      trigger), geo_age (WARNING last()>1800), suricata_update_ts
      (WARNING last()>0 and fuzzytime 180000), suricata_rules_mtime;
      add the multi-item divergence trigger (suricata_alerts rising
      while resp_alerts_seen flat, WARNING) to the multi-item set
      (O1, O5, O6)
- [ ] 3.7 zbx/gen-template.py: add depends_on support to trig() and
      render it in render_trigger as a Zabbix dependencies array
      (name plus expression reference); declare the frozen-kv HIGH
      trigger as the dependency of the three nodata-based warnings
      (telemetry stale, stats unreadable, suricata alive but counters
      unreadable); value-based warnings get no dependency (O7)

## 4. Consistency and regeneration

- [ ] 4.1 zbx/check_template.py: add resp_kv_ts, resp_kv_age,
      resp_lag_s, geo_ts, geo_age, suricata_update_ts, and
      suricata_rules_mtime to DOCUMENTED_KV_FIELDS;
      zbx/sample-nodeguard.kv: add one realistic line per new key so
      every new extraction regex is exercised
- [ ] 4.2 Regenerate zbx/preview-template-v2.json and the committed
      templates/zabbix-nodeguard-template.json from the same generator
      run; update the gen-template.py module docstring's
      committed-template contract (the "NOT overwritten during review"
      wording) to the regenerate-in-the-same-commit rule; run
      zbx/check_template.py against the git HEAD baseline and
      confirm it passes with the sanction entries doing exactly the
      work of the deleted objects (no unsanctioned missing, no stale
      sanction, no uuid churn, no rename)

## 5. Local verification gate

- [ ] 5.1 Full local gate: python3 -m py_compile on every touched
      Python file; bash -n and shellcheck on bin/nodeguard-status; the
      unit tests from 1.3 green; gen-template plus check_template
      green with item and trigger counts changed by exactly the
      designed amounts; openspec validate close-nodeguard-alerting-gaps
      --strict passes
