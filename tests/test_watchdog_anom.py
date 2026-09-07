#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Unit tests for the volumetric anomaly detector embedded in
bin/nodeguard-watchdog. The detector's source is extracted from the
script's ANOMPY heredoc and run in-process against kv snapshots and state
files in a temporary directory, so successive cycles can be driven
without a host, a timer, or a kv writer."""

import json
import os
import time
import unittest
import warnings

import ngtest

SOURCE = compile(ngtest.watchdog_anomaly_source(),
                 "nodeguard-watchdog:ANOMPY", "exec")

# Tunables chosen so a crafted burst clears the floor with small numbers;
# production defaults live in the bash wrapper.
K = "2"
FLOOR = "10"
TRIP = "3"
ADAPT = "30"
ALPHA = 0.05
STEADY_DELTA = 100
BURST_DELTA = 5000


class DetectorFixture(unittest.TestCase):
    """One detector instance whose three state paths point at a temporary
    directory through the env seam."""

    def setUp(self):
        self.tmp = ngtest.temp_dir(self)
        self.kv_path = os.path.join(self.tmp, "nodeguard.kv")
        self.state_path = os.path.join(self.tmp, "wd_baseline.json")
        self.out_path = os.path.join(self.tmp, "wd_anomaly.kv")
        self.set_mode("shadow")
        ngtest.patch_env(self, WD_ANOM_KV=self.kv_path,
                         WD_ANOM_STATE=self.state_path,
                         WD_ANOM_OUT=self.out_path,
                         WD_ANOM_K=K, WD_ANOM_FLOOR=FLOOR,
                         WD_ANOM_TRIP=TRIP, WD_ANOM_ADAPT=ADAPT)
        self.ts = int(time.time()) - 20
        self.drops = 1000

    def set_mode(self, mode, **tunables):
        """Point the detector at a mode and optional tunable overrides."""
        ngtest.patch_env(self, WD_ANOM_MODE=mode, **tunables)

    def snapshot(self, drops=None, sanity=0, alerts=None, killswitch="0",
                 prog_id="7", ts=None):
        """Build one kv snapshot; None values are omitted from the file."""
        kv = {"ng.drop_v4": self.drops if drops is None else drops,
              "ng.drop_v6": 0,
              "ng.tcp_synfin": sanity, "ng.tcp_synrst": 0,
              "ng.tcp_null": 0, "ng.tcp_xmas": 0,
              "ng.killswitch": killswitch, "ng.attach_state": "attached",
              "ng.feeds_enforce": "0", "ng.prog_id": prog_id,
              "ng.ts": ts if ts is not None else self.ts}
        if alerts is not None:
            kv["ng.suricata_alerts"] = alerts
        return kv

    def run_cycle(self, kv):
        """Write the snapshot and run one detector cycle, returning what
        it printed (the watchdog pipes that into ng_log)."""
        with open(self.kv_path, "w") as f:
            for key, value in kv.items():
                if value is not None:
                    f.write(f"{key}={value}\n")
        with ngtest.captured_log() as log:
            with warnings.catch_warnings():
                # The detector is a short-lived process in production, so
                # interpreter exit closes the files it leaves open; run
                # in-process, that reads as a ResourceWarning per cycle.
                warnings.simplefilter("ignore", ResourceWarning)
                try:
                    exec(SOURCE, {})
                except SystemExit:
                    pass
        return log.getvalue()

    def advance(self, delta=0, **over):
        """Run the next cycle with the drop counter advanced by delta."""
        self.ts += 1
        self.drops += delta
        return self.run_cycle(self.snapshot(**over))

    def state(self):
        """Read the persisted baseline state."""
        with open(self.state_path) as f:
            return json.load(f)

    def out(self):
        """Read the persisted anomaly kv as a dict."""
        values = {}
        with open(self.out_path) as f:
            for line in f:
                key, value = line.strip().split("=", 1)
                values[key] = value
        return values

    def seed(self):
        """Two calm cycles: the first seeds last values, the second grows
        the EWMA entries."""
        self.advance()
        self.advance(STEADY_DELTA)


class SeedingTest(DetectorFixture):
    """The baseline is built only from calm cycles."""

    def test_first_cycle_seeds_last_values_only(self):
        self.advance()
        state = self.state()
        self.assertEqual(state["last"]["drop_total"], self.drops)
        self.assertEqual(state["ewma"], {})
        self.assertEqual(state["consec"], 0)

    def test_second_calm_cycle_grows_the_ewma_entries(self):
        self.seed()
        entry = self.state()["ewma"]["drop_total"]
        self.assertEqual(entry["m"], float(STEADY_DELTA))
        self.assertEqual(entry["d"], float(FLOOR))
        self.assertEqual(entry["skip"], 0)

    def test_steady_deltas_update_mean_and_deviation(self):
        self.seed()
        self.advance(STEADY_DELTA)
        entry = self.state()["ewma"]["drop_total"]
        self.assertAlmostEqual(entry["m"], float(STEADY_DELTA))
        self.assertAlmostEqual(
            entry["d"], float(FLOOR) + ALPHA * (0 - float(FLOOR)))
        self.assertEqual(self.state()["consec"], 0)

    def test_metric_seen_first_during_an_episode_is_not_seeded(self):
        self.seed()
        self.advance(STEADY_DELTA, alerts=10)   # first sighting: no delta
        self.advance(BURST_DELTA, alerts=20)    # anomalous cycle
        self.assertNotIn("suricata_alerts", self.state()["ewma"])
        self.advance(STEADY_DELTA, alerts=30)   # calm cycle
        self.assertIn("suricata_alerts", self.state()["ewma"])


class TripTest(DetectorFixture):
    """A burst trips once per episode, at the configured cycle count."""

    def burst(self):
        """Run one anomalous cycle."""
        return self.advance(BURST_DELTA)

    def test_trip_fires_exactly_once_at_the_threshold(self):
        self.seed()
        self.advance(STEADY_DELTA)
        self.assertEqual(self.burst(), "")
        self.assertEqual(self.state()["consec"], 1)
        self.assertEqual(self.burst(), "")
        self.assertEqual(self.state()["consec"], 2)
        fired = self.burst()
        self.assertIn("VOLUMETRIC ANOMALY (shadow)", fired)
        self.assertIn("drop_total delta=", fired)
        self.assertEqual(self.out()["ng.anomaly_shadow_count"], "1")
        self.assertEqual(self.out()["ng.anomaly_count"], "0")
        self.assertEqual(self.burst(), "")
        self.assertEqual(self.out()["ng.anomaly_shadow_count"], "1")
        self.assertEqual(self.state()["consec"], 4)

    def test_on_mode_increments_the_enforced_counter(self):
        self.set_mode("on")
        self.seed()
        self.advance(STEADY_DELTA)
        self.burst()
        self.burst()
        fired = self.burst()
        self.assertIn("VOLUMETRIC ANOMALY (on)", fired)
        self.assertEqual(self.out()["ng.anomaly_count"], "1")
        self.assertEqual(self.out()["ng.anomaly_shadow_count"], "0")
        self.assertNotEqual(self.out()["ng.anomaly_last_ts"], "0")

    def test_a_calm_cycle_resets_the_streak(self):
        self.seed()
        self.burst()
        self.assertEqual(self.state()["consec"], 1)
        self.advance(STEADY_DELTA)
        self.assertEqual(self.state()["consec"], 0)

    def test_anomalous_cycles_do_not_adapt_until_the_skip_streak_ends(self):
        # TRIP is out of the way so only the adaptation rule is under test.
        self.set_mode("shadow", WD_ANOM_ADAPT="2", WD_ANOM_TRIP="99")
        self.seed()
        self.advance(STEADY_DELTA)
        before = self.state()["ewma"]["drop_total"]["m"]
        self.advance(BURST_DELTA)
        self.assertEqual(self.state()["ewma"]["drop_total"]["m"], before)
        self.assertEqual(self.state()["ewma"]["drop_total"]["skip"], 1)
        self.advance(BURST_DELTA)
        self.assertEqual(self.state()["ewma"]["drop_total"]["m"], before)
        self.assertEqual(self.state()["ewma"]["drop_total"]["skip"], 2)
        self.advance(BURST_DELTA)
        self.assertGreater(self.state()["ewma"]["drop_total"]["m"], before)
        self.assertEqual(self.state()["ewma"]["drop_total"]["skip"], 3)


class DiscardTest(DetectorFixture):
    """Cycles the detector must refuse to learn from."""

    def test_regime_change_reseeds_the_baseline(self):
        self.seed()
        self.assertNotEqual(self.state()["ewma"], {})
        self.advance(STEADY_DELTA, killswitch="1")
        self.assertEqual(self.state()["ewma"], {})
        self.assertEqual(self.state()["consec"], 0)

    def test_prog_id_change_discards_one_cycle_and_keeps_the_baseline(self):
        self.seed()
        before = self.state()["ewma"]
        self.advance(BURST_DELTA, prog_id="8")
        self.assertEqual(self.state()["ewma"], before)
        self.assertEqual(self.state()["consec"], 0)
        self.assertEqual(self.state()["last"]["drop_total"], self.drops)

    def test_negative_delta_discards_one_cycle_and_keeps_the_baseline(self):
        self.seed()
        before = self.state()["ewma"]
        self.advance(-STEADY_DELTA)
        self.assertEqual(self.state()["ewma"], before)
        self.assertEqual(self.state()["consec"], 0)
        self.assertEqual(self.state()["last"]["drop_total"], self.drops)

    def test_stale_snapshot_leaves_the_state_untouched(self):
        self.seed()
        before = self.state()
        self.ts += 1
        out = self.run_cycle(self.snapshot(ts=int(time.time()) - 3600))
        self.assertEqual(out, "")
        self.assertEqual(self.state(), before)

    def test_unchanged_timestamp_leaves_the_state_untouched(self):
        self.seed()
        before = self.state()
        self.drops += BURST_DELTA
        self.run_cycle(self.snapshot())  # same ts as the previous cycle
        self.assertEqual(self.state(), before)

    def test_missing_timestamp_leaves_the_state_untouched(self):
        self.seed()
        before = self.state()
        self.ts += 1
        kv = self.snapshot()
        del kv["ng.ts"]
        self.run_cycle(kv)
        self.assertEqual(self.state(), before)

    def test_the_output_kv_is_written_on_a_discarded_cycle(self):
        self.seed()
        os.remove(self.out_path)
        self.ts += 1
        self.run_cycle(self.snapshot(ts=int(time.time()) - 3600))
        self.assertEqual(self.out()["ng.anomaly_count"], "0")
        self.assertEqual(self.out()["ng.anomaly_shadow_count"], "0")


if __name__ == "__main__":
    unittest.main()
