# fix-nodeguard-state-lifecycle: tasks

Repo implementation and local verification only. Deployment to
devops-hive-node-2 and devops-hive-node-3 is a human follow-up recorded
in proposal.md under Impact and is deliberately absent here.

## 1. Responder journal boot scoping (S3)

- [ ] 1.1 bin/nodeguard-responder Journal: write a reserved `_meta`
      top-level key carrying the current boot id in save(); pop and
      interpret it in __init__ before the record filter; on absent or
      differing boot id set every record's blocked_until to 0 while
      retaining count, shadow_hits, first_seen, last_seen, and sid
- [ ] 1.2 Unit tests for the Journal boot logic (stdlib unittest,
      tmpdir journal files): prior-boot journal clears windows and
      keeps counts; same-boot journal preserves windows; legacy journal
      without `_meta` loads and clears; `_meta` never surfaces as a
      record after load or in saved records

## 2. Allow-generation last-good retention and kv (C1)

- [ ] 2.1 bin/nodeguard-maps: per-directive last-good cache under
      /var/lib/nodeguard/allow-cache/ for resolve (one file per name)
      and derp; atomic replace on success; on failure append the cached
      entries to the generated file, log "using last-good", and count
      the directive as degraded
- [ ] 2.2 bin/nodeguard-maps: write /run/nodeguard/allow.kv after
      reconcile with ng.allow_entries (from the reconcile summary),
      ng.allow_gen_fail, ng.allow_gen_stale, ng.allow_reconcile_ts;
      bin/nodeguard-status --kv cats the file when present, keys
      omitted when absent (visible unknown, never zero)

## 3. Periodic hitless allow refresh (C1)

- [ ] 3.1 Add units/nodeguard-allow-refresh.service (oneshot,
      ExecStart=/usr/bin/systemctl reload nodeguard-maps.service,
      TimeoutStartSec=180) and units/nodeguard-allow-refresh.timer
      (OnBootSec=15min, OnUnitActiveSec=1h, RandomizedDelaySec=5min).
      deploy.sh's scp and install globs (deploy/deploy.sh:59, :105)
      pick both files up with no edit; add the two unit names to the
      systemd-analyze verify list at deploy/deploy.sh:149 to :152 only
      if fix-nodeguard-deploy-reliability's glob-derived verify list
      (its task 3.2) has not landed first; that change owns the
      list-divergence proofing and it is not duplicated here

## 4. cmd_block read-modify-write (K1)

- [ ] 4.1 bin/ngmap.py cmd_block: move the lookup inside the
      block_lock hold; refuse to overwrite an expiry-0 entry without
      --i-mean-it (die with a message naming the flag); carry hits
      forward when the existing entry is live; treat a nonzero expired
      entry as absent (fresh write, hits 0)
- [ ] 4.2 Unit tests for the cmd_block value logic with a faked
      lookup/update layer: permanent refused without flag, permanent
      rewritten with flag, live refresh carries hits, expired treated
      as absent, absent inserts fresh

## 5. Contained-corpse deletion at insert (K2)

- [ ] 5.1 bin/ngmap.py: helper deleting expired strict-subnet entries
      of a just-inserted network under the held lock, re-verifying
      each candidate with lookup_value before delete_key (the sweep's
      re-check rule); call it from cmd_block when
      net.prefixlen < net.max_prefixlen
- [ ] 5.2 bin/nodeguard-feeds: snapshot the expired-entry set once per
      run before reconcile; in the insert and adopt branches of
      one_key, delete snapshot corpses contained in the inserted net
      via the ngmap helper's under-lock re-verification
- [ ] 5.3 Unit tests for the containment helper with a faked map
      layer: expired strict subnet deleted, live subnet kept,
      permanent subnet kept, equal-length key untouched, candidate
      revived between snapshot and delete is kept

## 6. ADR 0003 amendment (K2)

- [ ] 6.1 docs/adr/0003: append a dated, labelled `## Amendment`
      section documenting the single-lookup shadowing window (expired
      more-specific entry passes for its address inside a live broader
      block until deleted, worst case about one sweep period), its
      fail-open direction, and the insert-time deletion now performed
      by the userspace writers; do not rewrite or renumber the ADR

## 7. Verification

- [ ] 7.1 bash -n and shellcheck on bin/nodeguard-maps,
      bin/nodeguard-status, and bin/nodeguard-cli; python3 -m
      py_compile on bin/ngmap.py, bin/nodeguard-responder,
      bin/nodeguard-feeds; run the new unit tests; systemd-analyze
      verify on the two new units where available locally
- [ ] 7.2 openspec validate fix-nodeguard-state-lifecycle --strict
      passes; re-read design.md citations against the tree after the
      code lands and correct any drifted line references
