# Tasks: scope the churn brake per feed

## 1. Resolve the threshold per feed

- [x] 1.1 Add the per-feed override to the loader's config handling in
      `bin/nodeguard-feeds`: `FEEDS_MAX_CHURN_PCT_<FEED_ID>` with the feed
      id uppercased, falling back to `FEEDS_MAX_CHURN_PCT`. Validate it as
      an integer in the same place and the same way as the other integer
      settings, so a typo fails the run rather than silently defaulting.
- [x] 1.2 Move the threshold read from above the per-feed loop to inside
      it, so each feed resolves its own value. Leave both arms of the
      comparison, the symmetric difference, the coverage sum, the
      `accepted` bypass and the `enforcing` check exactly as they are.
- [x] 1.3 Carry the resolved threshold into the CHURN-HELD line so the log
      states which number was applied to that feed.

## 2. Tests

- [x] 2.1 A feed with an override above its movement is not held, where the
      same movement under the global default would be. Failing first.
- [x] 2.2 A feed with no override is held at exactly the global default,
      proving the default path is untouched.
- [x] 2.3 An override applies only to its own feed: a second feed in the
      same run keeps the global default.
- [x] 2.4 A malformed override value fails the run rather than falling back
      to the default.
- [x] 2.5 The hold record names the applied threshold.

## 3. Configuration and documentation

- [x] 3.1 Document the override in `hosts/example-gateway/feeds.conf` next
      to `FEEDS_MAX_CHURN_PCT`, including that the metric is the symmetric
      difference over the baseline and so ranges to 200 percent, that a
      rotating feed therefore needs an override above 100, and that 200 or
      more disables the brake for that feed.
- [x] 3.2 Note in the same place that the override does not clear a standing
      hold; that remains `apply --feed <id> --confirm`.

## 4. Verification

- [x] 4.1 `python3 -m unittest discover -s tests` passes from the repository
      root.
- [x] 4.2 `bash -n` and `shellcheck` clean on any changed shell, and
      `python3 -m py_compile` clean on `bin/nodeguard-feeds`.
- [x] 4.3 `openspec validate scope-the-churn-brake-per-feed --strict`
      passes.
- [x] 4.4 Runs in CI on the self-hosted runners (the build job):
      `build/build.sh` end to end, which runs the unit suite as its first
      gate and the Zabbix template drift gate as its last.
