#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Unit tests for bin/nodeguard-geo's kv publisher: the temp path is
predictable, so a symlink pre-placed there must be removed rather than
followed (evaluation finding S1), and the published file must carry mode
0644 whatever umask the unit inherits, because the monitoring agent reads
it as an unprivileged identity."""

import os
import stat
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


if __name__ == "__main__":
    unittest.main()
