# Tasks

## 1. Loader

- [x] 1.1 Resolve the frozen-upstream threshold per feed in
      `bin/nodeguard-feeds`, defaulting to the global `FEEDS_MAX_STALE_S`,
      following the `FEEDS_MAX_CHURN_PCT_<FEED_ID>` override convention
      already in the loader.
- [x] 1.2 Name the applied threshold in the FAILED message.
- [x] 1.3 Document the override in `hosts/example-gateway/feeds.conf` and in
      the `docs/design.md` configuration table.

## 2. Tests

- [x] 2.1 Cover the frozen-upstream brake, which has no test today: a feed
      past its threshold FAILS, a feed inside it does not.
- [x] 2.2 Cover the override: a per-feed value decides, a feed without one
      keeps the global default, and a tuned feed past its own threshold
      still FAILS.
- [x] 2.3 Cover that a frozen feed does not fail its peers in the same run.

## 3. Verification

- [x] 3.1 `python3 -m py_compile` on the loader.
- [x] 3.2 `python3 -m unittest discover -s tests` from the repository root.
- [x] 3.3 `openspec validate scope-the-frozen-upstream-brake-per-feed --strict`.

## 4. Rollout

- [x] 4.1 Deploy the loader to `gateway-home` and `gateway-office`.
- [x] 4.2 Set `FEEDS_MAX_STALE_S_SPAMHAUS_DROP_V6=7776000` (90 days) in each
      host's `feeds.conf`.
- [x] 4.3 Run the loader once per host and confirm the unit is active and
      `spamhaus_drop_v6` reports a normal summary rather than FAILED.
