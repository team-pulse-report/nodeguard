# Design: close-nodeguard-alerting-gaps

Closes evaluation findings O1 to O7 plus the K2 expired-pass-rate
trigger (2026-09-06 evaluation). One theme: no piece of the monitoring
chain may be able to die while its exported values keep reading
healthy. Every mechanism below follows the existing visible-unknown
discipline: a value that cannot be produced is omitted, never zeroed.

## 1. Responder heartbeat and lag (O1)

Today flush_sec (bin/nodeguard-responder:299) returns immediately when
nothing is dirty (bin/nodeguard-responder:302), so a responder that
hangs, or one that idles, stops rewriting
/run/nodeguard/responder.kv and nodeguard-status keeps cat-ing the
last values forever (bin/nodeguard-status:180-182). The unit stays
active, so the existing ng.responder trigger never fires. The refuter
confirmed follow() handles rotation (bin/nodeguard-responder:230-266)
and the allow-dump call is timeout-bounded
(bin/nodeguard-responder:137); the remaining untimed path is the
nodeguard-block subprocess.run at bin/nodeguard-responder:450, and the
general no-heartbeat gap covers any future hang equally.

Changes, all in bin/nodeguard-responder:

1. Every kv flush writes ng.resp_kv_ts=<epoch> alongside the existing
   five sec fields (the write loop at bin/nodeguard-responder:306-309).
2. Idle heartbeat: the follow() idle sentinel
   (bin/nodeguard-responder:266) already reaches flush_sec via the
   `line is None` branch (bin/nodeguard-responder:319-321). flush_sec
   gains a heartbeat clause: when 60 seconds have passed since the
   last flush, it writes even with sec_dirty false. The 15-second
   dirty-flush debounce is unchanged, so burst behavior is identical;
   the only new writes are one per minute at idle. One live-loop state
   never reaches that sentinel today: follow()'s FileNotFoundError
   wait branch (bin/nodeguard-responder:248-250) sleeps and continues
   without yielding, so while eve.json is absent (fresh boot before
   Suricata creates it) the heartbeat would freeze and the new age
   trigger would fire on a responder behaving as designed. That branch
   also yields the idle sentinel after its sleep, keeping the
   at-least-once-per-minute promise literally true in every alive
   state; the alive-but-not-consuming divergence trigger still covers
   the case where alerts exist and are not read.
3. ng.resp_lag_s: for every consumed alert, the lag between the EVE
   record's own timestamp field (ISO 8601 with offset, parsed with
   datetime.fromisoformat) and time.time(), clamped at zero and
   rounded to an integer. An unparseable or absent timestamp leaves
   the previous value in place and never raises past the per-event
   guard (bin/nodeguard-responder:460).

nodeguard-status derives ng.resp_kv_age = now - resp_kv_ts exactly the
way it derives ng.sweep_age from ng.sweep_ts
(bin/nodeguard-status:177-178), emitted only when responder.kv exists
and carries resp_kv_ts. Template: a resp_kv_age item with a WARNING
trigger at last()>120 (two missed heartbeats plus poll jitter), and a
resp_lag_s item (no trigger; the point is that the lag is measured at
all). A new multi-item WARNING trigger fires when ng.suricata_alerts
rises across a ten-sample window while ng.resp_alerts_seen stays flat,
catching the alive-but-not-consuming case (wrong file followed, tail
stuck) that the heartbeat alone cannot see; it joins the existing
multi-item set (zbx/gen-template.py:637-679).

Rejected alternative: systemd WatchdogSec on the responder unit. It
would conflate visibility with remediation (an auto-restart hides the
wedge the operators need to diagnose) and this change is
observability-only.

## 2. Static-item retirement done properly (O2)

zbx/gen-template.py still emits the three static per-feed item pairs
via the FEEDS loop (zbx/gen-template.py:315-325, feeds list at
zbx/gen-template.py:47) with their nine triggers (two staleness per
feed from feed_triggers, zbx/gen-template.py:78-93, plus one frozen
per feed, zbx/gen-template.py:96-103), while
zbx/removed-objects.txt has no entries (zbx/removed-objects.txt:24).
The archived telemetry change's task 2.15 is checked and records
removing the static per-feed items and their triggers from the live
server after the 24h parity window
(openspec/changes/archive/2026-09-06-add-nodeguard-telemetry/tasks.md:186-190),
but the generator, the sanction file, and the committed template were
never moved past that step together: build_rows() still emits
everything and the committed template still carries it, so
check_template.py passes while the next generate-and-import would
silently resurrect the retired objects on the live server.

Change, in one commit so no intermediate state exists:

1. Delete the static FEEDS loop rows and their trigger builders from
   build_rows().
2. Record 15 sanction entries in zbx/removed-objects.txt (6 items by
   key, 9 triggers by name, reason "superseded by LLD prototypes
   after the task 2.15 parity window", date 2026-09-06). The loader
   hard-errors on malformed lines (zbx/check_template.py:163-189) and
   the checker fails both an unsanctioned disappearance and a
   stale sanction (zbx/check_template.py:309-361), so the entries and
   the deletion must land together, which is exactly the recorded
   removal step the format was built for.
3. Promote the three LLD prototype trigger severities
   (zbx/gen-template.py:739-763, all INFO today): stale WARNING,
   failed open AVERAGE, upstream frozen WARNING, with the "parity
   window" wording dropped from their descriptions. The nodata guards
   stay.
4. Regenerate zbx/preview-template-v2.json and the committed
   templates/zabbix-nodeguard-template.json from the same generator
   run, and run check_template.py against the git HEAD baseline; the
   run passes only because of the sanction entries, proving they
   cover exactly what was deleted.

The per-feed kv keys themselves are unchanged: the LLD rule and its
prototypes still extract from ng.feeds_last_success_ts_* and
ng.feeds_snapshot_age_*, so the documented kv surface keeps those
fields (zbx/check_template.py:103-108).

## 3. Triggers for feeds_journal_reset and feeds_map_errors (O3)

Both rows exist with tiles but no triggers: feeds_journal_reset at
zbx/gen-template.py:265-266 and feeds_map_errors at
zbx/gen-template.py:326-329. Per the finding: WARNING on
last(feeds_journal_reset)=1 (a lost CAS journal rebuilt insert-only is
incident-relevant the moment it happens) and WARNING on
min(feeds_map_errors,13h)>0 (persisting across two 6-hour feed cycles
plus margin, the same 13h window the config/approval mismatch trigger
already uses at zbx/gen-template.py:255-263).

## 4. Rate twins for the alert-to-block graph (O4)

The security dashboard's alert-to-block graph
(zbx/dashboards.py:247-255) mixes three per-second datasets with the
cumulative "responder dry-run would-block" and "responder blocks
issued" items (rows at zbx/gen-template.py:446-451, no rate flag, no
twins), so the monotonic lines flatten the pps lines within days and
the graph's stated dry-run-divergence purpose fails. The archived
telemetry change mandated rate twins "where graphed"; these two
shipped without them, a direct implemented-spec omission.

Change: add rate_twin rows for resp_blocks_issued and
resp_dryrun_would_block (the rate_twin helper at
zbx/gen-template.py:116-120 already yields the distinct
<field>.rate key, FLOAT, CHANGE_PER_SECOND, 90d trends), and point the
graph's dataset names at the twin display names. The cumulative items
stay for tiles and history.

## 5. Suricata ruleset freshness (O5)

units/suricata-update.service runs suricata-update daily with no
telemetry at all (units/suricata-update.service:8); the nonblocking
reload's "-" prefix (units/suricata-update.service:9) is spec-mandated
and is kept. A chronically failing update (network, CA, URL move) is
invisible while every automated block is driven by et/open severity-1
rules.

Change: an ExecStartPost line writes the epoch to
/var/lib/nodeguard/suricata-update.stamp. Without a "-" prefix,
ExecStartPost runs only when ExecStart succeeded, so the stamp is
precisely "last successful update", and /var/lib persistence keeps the
staleness math honest across reboots the same way feeds.kv placement
does (bin/nodeguard-status:189-191). nodeguard-status exports
ng.suricata_update_ts from the stamp (omitted when absent: the
never-ran state stays unsupported) and ng.suricata_rules_mtime from
the live mtime of /var/lib/suricata/rules/suricata.rules (omitted when
unreadable). Template: both as unixtime items, with a WARNING trigger
beside the feed staleness family: last(suricata_update_ts)>0 and
fuzzytime(suricata_update_ts,180000)=0, two daily cycles plus the
timer's RandomizedDelaySec hour of margin.

Cross-change note: harden-nodeguard-control-plane adds a systemd
hardening block to units/suricata-update.service and already carries
ReadWritePaths=/var/lib/nodeguard for exactly this stamp write; this
change lands after the hardening change, so the ExecStartPost line is
added to the already-hardened unit and needs no ReadWritePaths edit of
its own. If the landing order is ever reversed, the hardening change's
per-unit ReadWritePaths audit must keep /var/lib/nodeguard for
suricata-update.service or the stamp write fails read-only.

## 6. geo.kv timestamp (O6)

nodeguard-geo builds its kv lines (bin/nodeguard-geo:186-201) and
writes them (bin/nodeguard-geo:202) with no timestamp, and the
top-level handler swallows any exception and exits 0
(bin/nodeguard-geo:209-214), so a persistently failing run never even
marks the unit failed and the last geo.kv is served indefinitely.

Change: main() appends ng.geo_ts=<epoch> to the lines list before the
write. Because the failure path exits before write_atomic, the
timestamp advances on success only, which is the point: the swallowed
failure ages out. nodeguard-status derives ng.geo_age when geo.kv is
present and carries geo_ts (same pattern as sweep_age; the geo cat is
at bin/nodeguard-status:185-187). Template: a geo_age item with a
WARNING trigger at last()>1800, six 5-minute timer periods, generous
against timer jitter and mirroring the sweep_age style
(zbx/gen-template.py:530-540). Hosts without the geoip DB still
produce geo.kv (the empty-result path writes it), so the age key
exists wherever the timer runs; a host where geo has never run omits
everything, visibly.

The S1 finding (root writing into zabbix-owned /run/zabbix) is real
and untouched here; the geo.kv path move belongs to the security
change and only the file's content changes in this one.

## 7. Trigger dependencies (O7)

A dead kv export chain (watchdog timer dead, /run/zabbix wiped) fires
the frozen-kv HIGH (fuzzytime on ng.ts, zbx/gen-template.py:337-343)
plus at least three nodata WARNINGs that all mean "kv export stopped":
telemetry stale (zbx/gen-template.py:145-149), stats unreadable
(zbx/gen-template.py:642-647), and suricata-alive-but-counters-
unreadable (zbx/gen-template.py:648-654).

Mechanism, per the refuter's note: Zabbix template exports express a
trigger dependency as a "dependencies" array on the dependent trigger,
each entry referencing the depended-on trigger by name plus
expression; resolution on import is by that name reference, so the
dependency survives regeneration as long as the master trigger's name
is stable, which uuid carry-over already guarantees. Implementation:
trig() (zbx/gen-template.py:71-75) gains an optional depends_on field
and render_trigger (zbx/gen-template.py:822-831) renders it; every
trigger already funnels through render_trigger, so this is the single
change point the finding identified. The three nodata-based warnings
above declare the frozen-kv HIGH as their dependency. Value-based
warnings (stats_read_fail=1 with a fresh kv, resp_kv_age, geo_age) get
no dependency: they represent independent failures and must keep
paging on their own.

## 8. Expired-pass-rate trigger (K2)

The K2 kernel finding (an expired more-specific LPM entry returns
ST_PASS_EXPIRED for its /32 while the surrounding live CIDR drops,
src/nodeguard_kern.c:278-281, until the sweep deletes the corpse) gets
its telemetry half here: ng.pass_expired is already a per-second rate
item (zbx/gen-template.py:359-361) with no trigger. Change: WARNING on
min(pass_expired,15m)>0, strictly positive across every sample for
longer than a full 10-minute sweep period plus margin, which means
corpses are being created faster than the sweep clears them or the
sweep is not clearing them at all. Brief nonzero blips at normal TTL
expiry do not trip a min() over 15 minutes. The insert-time corpse
deletion and the ADR documentation of the shadowing window stay with
the kernel-side change, out of scope here.

## 9. Consistency: generator, checker, sample, committed template

New kv fields enter the documented surface in zbx/check_template.py
(DOCUMENTED_KV_FIELDS, zbx/check_template.py:67-109): resp_kv_ts,
resp_kv_age, resp_lag_s, geo_ts, geo_age, suricata_update_ts,
suricata_rules_mtime. zbx/sample-nodeguard.kv gains one line per new
key so every new extraction regex is executed against a value.
resp_kv_ts and geo_ts stay kv-only source fields (documented,
untemplated; the checker requires template keys to be a subset of the
documented surface, not equality). The gen-template.py module
docstring currently states the opposite contract ("The committed
template is NOT overwritten by this tool during review",
zbx/gen-template.py:25-27), a leftover of the archived change's phased
rollout; it is updated to the new rule so the tool's stated contract
and the spec agree. The preview and the committed
template are regenerated in the same commit as the generator edits;
check_template.py runs against the git HEAD baseline and must pass
with the sanction entries and pass name, uuid, regex, and kv-surface
checks for everything else.

## Verification (all local; deployment is the human follow-up)

- python3 -m py_compile on bin/nodeguard-responder, bin/nodeguard-geo,
  zbx/gen-template.py, zbx/dashboards.py, zbx/check_template.py.
- bash -n and shellcheck on bin/nodeguard-status.
- Focused stdlib unittests for the new pure logic (heartbeat cadence
  decision, EVE timestamp lag parse with hostile inputs, geo_ts
  success-only placement), coordinated with the T1 suite change if it
  lands first.
- gen-template.py then check_template.py green against the committed
  baseline; the trigger and item counts in the summary line change by
  exactly the designed amounts.
- openspec validate close-nodeguard-alerting-gaps --strict.
