# fix-nodeguard-state-lifecycle: design

Four userspace fixes for state that outlives the event that invalidated
it. No change to src/nodeguard_kern.c; every decision below preserves
the fail-open contract (docs/adr/0003) and the per-key block_lock
discipline (bin/ngmap.py:112 to :122).

## 1. S3: responder journal boot scoping

### The defect, in the code

The responder journals every block window with a wall-clock end:
`rec["blocked_until"] = time.time() + ttl` (bin/nodeguard-responder:279),
persisted in /var/lib/nodeguard/blocks.json (default at
bin/nodeguard-responder:77). The per-event window check:

- bin/nodeguard-responder:461 to :465: a gate-passing alert whose source
  has `now < rec["blocked_until"]` is downgraded to a sighting; no block
  is issued, on the assumption the kernel entry is still covering it.

That assumption fails after a reboot: pinned maps live on bpffs and
CLOCK_MONOTONIC restarts, so all blocks are lost at boot (docs/adr/0003,
Consequences, lines 58 to 60), but blocks.json survives with windows up
to TTL_MAX=86400s (bin/nodeguard-responder:80, escalation at :488). The
most persistent attackers carry the longest windows, so they get the
longest post-reboot suppression. docs/design.md:817 ("the journal is
deliberately not re-armed") covers not re-applying old blocks at boot;
it does not cover the journal actively suppressing new evidence-based
blocks, which is what line 461 does.

### Decision

Record the boot id in the journal and treat prior-boot windows as
expired. This is the exact pattern the feeds loader already uses for
its own state: BOOT_ID_PATH and boot_id() (bin/nodeguard-feeds:57,
:130 to :133), stored in state.json and compared at run start
(bin/nodeguard-feeds:784 to :790, which drops journal rows on a boot-id
change for the same reason: lookups would find nothing).

Mechanics, all inside the Journal class
(bin/nodeguard-responder:175 to :285):

1. `save()` (bin/nodeguard-responder:242 to :257) writes a reserved
   top-level key `_meta` = {"boot_id": <current boot id>}. The string
   `_meta` can never collide with a record key because record keys are
   IP address strings (journal.data is keyed by `src`, written at
   :464, :481, :492, :501).
2. `__init__` (bin/nodeguard-responder:189 to :219) pops `_meta` before
   the existing isinstance record filter (:202 to :203), so a legacy
   journal, which has no `_meta`, loads cleanly.
3. When the loaded boot id is absent or differs from the current one,
   every record's `blocked_until` is set to 0. `count`, `shadow_hits`,
   `first_seen`, `last_seen`, and `sid` are retained: the escalation
   exponent (`ttl_base * (2 ** rec.get("count", 0))`,
   bin/nodeguard-responder:488) still applies, so the post-reboot
   re-block of a repeat offender lands with the escalated TTL rather
   than starting over.
4. A journal with no `_meta` is treated as prior-boot (windows
   cleared). That is the safe direction: at worst one redundant block
   of a source the kernel already covers, which the map overwrite
   absorbs harmlessly.

### Residual, recorded deliberately

`nodeguard-flush` (bin/nodeguard-cli:26 to :27, cmd_flush at
bin/ngmap.py:386 to :394) empties both block maps without a boot-id
change, so same-boot journal windows still suppress re-blocking after a
flush, for up to the remaining window. The evaluation's alternative fix
(verify the block exists in the live map before honoring a window)
would close this but adds a bpftool exec per gate-passing alert to the
hot path, during exactly the storms the rate caps exist for. Flush is a
rare operator panic action and the operator holding it can also remove
blocks.json; the residual is accepted, documented here, and recorded in
proposal.md under Out of scope rather than papered over.

### Cross-change note: Journal edits overlap the hardening change

harden-nodeguard-control-plane (finding S6) also rewrites
Journal.save() to debounce it and to cap record creation during a rate
cap; its proposal calls the two edits disjoint (its proposal.md:95
to :96), which is not accurate: mechanics 1 and 2 above edit save()
and __init__, the same save() S6 debounces. The behaviors are
compatible, but whichever change lands second must merge the `_meta`
write into the debounced save path so every flush, immediate or
debounced, carries the boot id. The nodeguard-allow-refresh units
introduced in section 2 below likewise postdate that change's unit
enumeration and need a hardening line item there or in a follow-up,
beyond the TimeoutStartSec this change gives them.

## 2. C1: protected-remote allow entries, retention and refresh

### The defect, in the code

nodeguard-maps builds the generated allow file fresh on every run,
starting from empty (`: > "$GEN"`, bin/nodeguard-maps:76 to :77):

- `resolve` directive (bin/nodeguard-maps:86 to :101): getaddrinfo
  failure is logged as a warning and the entries are simply absent from
  $GEN.
- `derp` directive (bin/nodeguard-maps:102 to :125): a failed
  `tailscale debug derp-map` or parse likewise logs and omits.

reconcile-allow then deletes every live entry not in the desired set
(bin/ngmap.py:649 to :652), so one transient failure at boot or reload
evicts the protection from the live maps. DERP is the management
fallback and runs over TCP/443; the kernel's WireGuard hard pass covers
UDP only (src/nodeguard_kern.c:248 to :263), so an evicted DERP entry
is genuinely blockable, eroding the cannot-sever-management guarantee.

The staleness direction: generation runs only when
nodeguard-maps.service starts or is reloaded
(units/nodeguard-maps.service:7 to :14); there is no timer, so resolved
addresses and the DERP map drift until the next boot or deploy.

### Decision: last-good per directive, the feeds pattern

Each dynamic directive keeps a last-good snapshot under
/var/lib/nodeguard/allow-cache/ (persistent, root-owned; /run is tmpfs
and would defeat boot-time retention, which is exactly when resolution
is most likely to race the network):

- `resolve <host>` writes allow-cache/resolve_<host>.txt on success
  (atomic tmp plus rename, the house pattern); on failure it appends
  the cached file's entries to $GEN, logs "using last-good", and marks
  the run degraded. No cache and a failure keeps today's behavior
  (warning, entries absent) plus the degraded flag.
- `derp` does the same with allow-cache/derp.txt.
- `cidr` lines are static text and need no cache. The WAN_DYNAMIC_ALLOW
  block (bin/nodeguard-maps:135 to :145) reads local kernel state, not
  the network, and already logs its own missing-entry warning; it is
  left as is.

This mirrors the feeds loader's last-good discipline: a 304 serves the
last-good snapshot (bin/nodeguard-feeds:361 to :367); any other fetch
failure fails the feed and leaves its existing map entries untouched by
skipping it (:369 to :371), rather than pretending the feed is empty.

Retention bound: a cached entry is served only on failure and is
replaced wholesale on the next success, so a stale protected address
lingers at most until the next successful refresh (below). Serving a
slightly stale allow entry is fail-open by direction: allow entries can
only pass traffic, never drop it.

### Decision: periodic hitless refresh

New units, shipped by deploy.sh alongside the existing set:

- units/nodeguard-allow-refresh.service: oneshot,
  `ExecStart=/usr/bin/systemctl reload nodeguard-maps.service`,
  `TimeoutStartSec=180` (getaddrinfo and `tailscale debug derp-map`
  are the slow calls; the R1 timeout sweep is a separate change but a
  new unit is not born without one).
- units/nodeguard-allow-refresh.timer: OnBootSec=15min,
  OnUnitActiveSec=1h, RandomizedDelaySec=5min.

Reload is the sanctioned hitless verb: the unit's own comment
(units/nodeguard-maps.service:10 to :13) records that reload jobs do
not propagate through nodeguard-xdp's Requires=, so no detach and no
WAN link blip; restart does propagate and is not used here. The
refresh timer cannot fire the service's start job directly because
nodeguard-maps is RemainAfterExit=yes and already active, which is why
the timer drives a separate reload-invoking oneshot.

The reload re-runs the whole maps script, not just its allow half, and
that is worth stating because the timer changes how often the rest of
it runs. Section 5 rewrites config[0] from ng_live_wg_port and writes
the tailscale default when the ss probe returns empty
(bin/nodeguard-maps:170 to :179), so a transient tailscaled failure
during an hourly reload can substitute a wrong WireGuard port; the
exposure moves from per-deploy to hourly. The bound is unchanged and
already accepted (docs/design.md, "tailscaled restarts and moves its
port"): the one-minute watchdog rewrites config[0] from the live port
(bin/nodeguard-watchdog:234 to :238), so the stale hard pass lasts at
most a minute and WireGuard rides the allowlist meanwhile. Recorded in
the new unit's NOTE rather than fixed here; narrowing section 5's write
is a change to the maps script's own contract and belongs with the
unit-hardening work, not with an allowlist retention fix.

### Decision: visible failure, allow kv

nodeguard-maps writes /run/nodeguard/allow.kv (root-owned NG_RUN,
deliberately not /run/zabbix, which finding S1 established as a
symlink-attack surface for root writers) after reconcile:

- ng.allow_entries: total desired entries, taken from the reconcile
  summary that cmd_reconcile_allow already prints
  (bin/ngmap.py:658 to :659).
- ng.allow_gen_fail: 1 when any directive failed this run, else 0.
- ng.allow_gen_stale: count of directives served from last-good cache.
- ng.allow_reconcile_ts: epoch of the last successful reconcile.

nodeguard-status --kv cats the file next to the responder and geo
fragments (bin/nodeguard-status:181 to :193), preserving the
visible-unknown discipline: a missing file means the keys go
unsupported, never zero. Trigger wiring for these keys is the
observability change's scope.

## 3. K1: cmd_block read-modify-write under block_lock

### The defect, in the code

cmd_block (bin/ngmap.py:289 to :351) packed a fresh value with hits=0
and called update_map inside block_lock without ever reading the
existing entry. Consequences, both confirmed:

- A permanent entry (expiry 0, reserved for manual entries:
  src/nodeguard_kern.c:52, ADR 0003 decision point 3, and the docstring
  at bin/ngmap.py:11) is silently demoted to a TTL block when the
  responder re-blocks the same address via the BLOCK wrapper
  (bin/nodeguard-responder:499). Reachable during a kill-switch latch,
  when the permanently blocked attacker's traffic reaches Suricata
  again.
- The overwrite zeroes hits, removing exactly the re-offending sources
  from the sweep's delta leaderboard (bin/ngmap.py:442 to :458 ranks by
  hits delta; a zeroed counter reads as no new hits).

The feeds loader already implements the correct discipline: lookup
under the lock, compare, carry cur_hits forward on refresh, refuse
foreign entries (bin/nodeguard-feeds:635 to :707, especially :632
to :645).

### Decision

Extend the block_lock hold in cmd_block to cover lookup plus write,
and branch on the current value:

1. Absent, or present but expired (expiry != 0 and mono_ns() >=
   expiry): write fresh with hits=0. An expired corpse enforces
   nothing for anyone (the same rule the feeds insert path applies at
   bin/nodeguard-feeds:678 to :687).
2. Present, permanent (expiry == 0), and --i-mean-it not given:
   die() with a message naming the entry as permanent and the flag
   required to overwrite it. --i-mean-it is reused rather than a new
   flag because it is already the file's deliberate-override marker
   (broad prefixes at bin/ngmap.py:292 to :295, --permanent at :296
   to :297), and because the responder invokes the wrapper without it
   (bin/nodeguard-cli:11 to :18 passes only target and --ttl unless the
   operator appends flags), so automation can never demote a permanent
   block. The responder logs the nonzero exit as "block FAILED"
   (bin/nodeguard-responder:507), which is the correct signal: the
   address is already covered harder than the responder asked for.
   When --i-mean-it is given and the existing entry is permanent (or
   live), the rewrite carries the current hits forward; only an
   expired or absent entry starts at zero.
3. Present and live with a TTL: write the new expiry with cur_hits
   carried forward, preserving the leaderboard and the operator's
   forensic trail.

The refusal is evaluated under the lock, so a concurrent sweep or
feeds run cannot interleave between the read and the write; the lock
is per key by contract (bin/ngmap.py:115 to :122) and this adds one
lookup to its hold time.

## 4. K2: expired contained entries deleted at insert time

### The defect, in the code

One LPM lookup per family, by design: handle_v4 looks up block4 once
(src/nodeguard_kern.c:273) and passes with ST_PASS_EXPIRED when the
best match is expired (:278 to :280); handle_v6 mirrors it (:338,
:343 to :345). LPM returns the longest prefix match, so an expired
/32 inside a live feed CIDR answers for that host: XDP_PASS while the
rest of the CIDR drops, until the sweep deletes the corpse
(bin/ngmap.py:397 to :432; timer cadence 10 minutes,
units/nodeguard-sweep.timer, OnUnitActiveSec=10min). A successful
feeds apply already triggers an immediate sweep
(bin/nodeguard-feeds:960 to :962), but the 6-hourly timer-driven runs
do not, and cmd_block never did. Fail-open direction, single address,
and the ADR 0002 evidence gate makes the ordering uncommon; the
substantive gap is that no document records the interaction.

### Decision: userspace writers clear what they cover

The kernel keeps exactly one lookup (a second per-packet trie walk
for every packet to close a fail-open single-address window is the
wrong trade and would reopen ADR 0007's minute-path arguments). The
writers close the window instead; they already hold block_lock at
insert time.

New helper in bin/ngmap.py (the single map-mutation implementation, by
the file's own invariant, bin/ngmap.py:3 to :8), called with the lock
held: given the map path and the just-inserted network, delete every
entry that is a strict subnet of it (prefixlen greater than the
inserted entry's) whose expiry is nonzero and past, re-verifying each
candidate with lookup_value before delete_key, the same
re-check-under-lock rule the sweep documents (bin/ngmap.py:408 to
:414: "leaving a corpse is harmless, deleting a fresh block is not").
Live entries, permanent entries, and equal-length keys are never
touched.

Call sites:

- cmd_block: after the update_map write, in the same lock hold, and
  only when net.prefixlen < net.max_prefixlen (a host route cannot
  strictly contain anything). One extra map dump per operator or
  responder CIDR block; responder blocks are always host routes
  (bin/nodeguard-responder:499 blocks `src`), so the hot path pays
  nothing.
- feeds reconcile insert path (bin/nodeguard-feeds:657 to :702, both
  the fresh-insert and adopt branches): to avoid one dump per inserted
  CIDR across a feed of about 1,700 entries, the runner snapshots the
  expired-entry set once per run before reconciling, and at insert
  time deletes only snapshot corpses contained in the inserted net,
  re-verified under the lock exactly as above. The snapshot can only
  under-delete (a corpse born mid-run waits for the sweep), never
  over-delete, because the per-key re-verification is what authorizes
  each delete.

The sweep remains the backstop for corpses no writer ever covers;
its semantics do not change (garbage collection only, ADR 0003
decision point 5).

### ADR 0003 amendment

docs/adr/0003 gains an `## Amendment` section, dated on the day it is
written and labelled as an amendment, per the house ADR rules
(amendments correct the record; they do not change the decision). It
records: the single-lookup consequence (an expired more-specific entry
shadows a live broader block for that address until deleted), the
observed worst case of about one sweep period, the fail-open direction,
and that userspace writers now delete contained expired entries at
insert time while the kernel deliberately keeps one lookup. The
existing Status, Context, Decision, and Consequences sections are not
rewritten and the ADR is not renumbered.

## What a wrong implementation looks like

- S3: clearing offense counts along with the windows (loses
  escalation, exactly what the finding says must survive), or writing
  `_meta` in a way the legacy loader treats as an IP record.
- C1: caching into /run (lost at the reboot that motivates the cache),
  restarting instead of reloading nodeguard-maps from the timer (WAN
  blip), or writing the kv into /run/zabbix (finding S1's attack
  surface).
- K1: checking the permanent guard outside the lock (TOCTOU against
  feeds or sweep), or carrying hits forward from an expired corpse.
- K2: deleting live or permanent contained entries, deleting without
  the under-lock re-verification, or adding a second kernel lookup.
