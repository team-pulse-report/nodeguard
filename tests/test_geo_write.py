#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Unit tests for bin/nodeguard-geo's kv publisher: the temp path is
predictable, so a symlink pre-placed there must be removed rather than
followed (evaluation finding S1), and the published file must carry mode
0644 whatever umask the unit inherits, because the monitoring agent reads
it as an unprivileged identity. Plus the success-only stamp of finding
O6, which is what makes a silently failing run age out."""

import os
import stat
import time
import unittest

import ngtest

geo = ngtest.load_bin("nodeguard_geo", "nodeguard-geo")

KV_BODY = "ng.geo_located=7\n"
VICTIM_BODY = "the file an attacker wants root to truncate\n"
STRICT_UMASK = 0o077


class WriteAtomicTest(unittest.TestCase):
    """The publisher's symlink, mode, and rename guarantees."""

    def setUp(self):
        self.tmp = ngtest.temp_dir(self)
        self.target = os.path.join(self.tmp, "geo.kv")
        self.temp_path = self.target + ".tmp"

    def set_umask(self, value):
        """Run the rest of the test under one umask, restoring the
        process-wide value afterwards."""
        previous = os.umask(value)
        self.addCleanup(os.umask, previous)

    def victim(self):
        """A file outside the kv path that a pre-placed symlink points at;
        it stands for whatever the attacker chose to have root destroy."""
        path = os.path.join(self.tmp, "victim")
        with open(path, "w") as f:
            f.write(VICTIM_BODY)
        return path

    def test_symlink_at_the_temp_path_is_never_followed(self):
        victim = self.victim()
        os.symlink(victim, self.temp_path)

        geo.write_atomic(self.target, KV_BODY)

        with open(victim) as f:
            self.assertEqual(f.read(), VICTIM_BODY)
        with open(self.target) as f:
            self.assertEqual(f.read(), KV_BODY)
        # The link was unlinked, not renamed over the destination: the
        # published file is a regular file of its own.
        self.assertFalse(os.path.islink(self.target))
        self.assertTrue(stat.S_ISREG(os.lstat(self.target).st_mode))
        self.assertFalse(os.path.lexists(self.temp_path))

    def test_dangling_symlink_at_the_temp_path_creates_nothing(self):
        # O_CREAT through a dangling link would create the target instead
        # of failing, which is how the original open() turned an absent
        # path into a root-owned file of the attacker's choosing.
        absent = os.path.join(self.tmp, "absent")
        os.symlink(absent, self.temp_path)

        geo.write_atomic(self.target, KV_BODY)

        self.assertFalse(os.path.lexists(absent))
        with open(self.target) as f:
            self.assertEqual(f.read(), KV_BODY)

    def test_published_file_is_0644_under_a_restrictive_umask(self):
        self.set_umask(STRICT_UMASK)

        geo.write_atomic(self.target, KV_BODY)

        self.assertEqual(stat.S_IMODE(os.stat(self.target).st_mode), 0o644)

    def test_rewrite_replaces_the_file_by_rename(self):
        geo.write_atomic(self.target, KV_BODY)
        first = os.stat(self.target).st_ino

        geo.write_atomic(self.target, "ng.geo_located=9\n")

        self.assertNotEqual(os.stat(self.target).st_ino, first)
        with open(self.target) as f:
            self.assertEqual(f.read(), "ng.geo_located=9\n")
        self.assertFalse(os.path.lexists(self.temp_path))

    def test_missing_parent_directory_is_created(self):
        nested = os.path.join(self.tmp, "run", "nodeguard", "geo.kv")

        geo.write_atomic(nested, KV_BODY)

        with open(nested) as f:
            self.assertEqual(f.read(), KV_BODY)


class SuccessStampTest(unittest.TestCase):
    """Finding O6: the top-level handler swallows every failure and exits
    zero, so nothing but a success-only stamp can tell a working run from
    one that has been failing for a week."""

    def setUp(self):
        self.tmp = ngtest.temp_dir(self)
        self.kv_path = os.path.join(self.tmp, "geo.kv")
        ngtest.patch_attrs(self, geo,
                           GEO_KV=self.kv_path,
                           MAP_SVG=os.path.join(self.tmp, "attack-map.svg"),
                           block_hits=lambda: {},
                           load_dbip=lambda: (None, None))

    def kv_fields(self):
        """The published kv file as {key: value}."""
        with open(self.kv_path) as f:
            return dict(line.strip().split("=", 1)
                        for line in f if line.strip())

    def test_a_successful_run_stamps_the_kv(self):
        with ngtest.captured_log():
            geo.main()

        stamped = int(self.kv_fields()["ng.geo_ts"])
        self.assertLessEqual(abs(stamped - time.time()), 5)

    def test_an_empty_result_still_stamps(self):
        # A host with no geoip index still publishes geo.kv, so the age
        # exists wherever the timer runs; only a host where geo has never
        # completed omits the key.
        with ngtest.captured_log():
            geo.main()

        self.assertEqual(self.kv_fields()["ng.geo_located"], "0")
        self.assertIn("ng.geo_ts", self.kv_fields())

    def published(self):
        """The published kv file verbatim."""
        with open(self.kv_path) as f:
            return f.read()

    def test_a_failing_run_leaves_the_previous_stamp_untouched(self):
        with ngtest.captured_log():
            geo.main()
        before = self.published()

        def explode():
            raise RuntimeError("block4 dump wedged")

        ngtest.patch_attrs(self, geo, block_hits=explode)
        with self.assertRaises(RuntimeError):
            geo.main()

        self.assertEqual(self.published(), before)

    def test_a_failing_map_render_leaves_the_previous_stamp_untouched(self):
        # The map is the last artifact the run produces, so the stamp has
        # to be written after it; otherwise a run that fails only in the
        # render keeps the freshness signal green over a frozen map.
        with ngtest.captured_log():
            geo.main()
        before = self.published()

        def explode(points):
            raise RuntimeError("svg render wedged")

        ngtest.patch_attrs(self, geo, render_svg=explode)
        with self.assertRaises(RuntimeError):
            geo.main()

        self.assertEqual(self.published(), before)


if __name__ == "__main__":
    unittest.main()
