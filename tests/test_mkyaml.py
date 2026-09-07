#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Unit tests for build/mkyaml.py's stock-version sidecar (evaluation
finding B5).

The generated suricata.yaml header used to carry a hardcoded RPM version,
so a stock refresh that forgot to edit mkyaml.py shipped a header naming
the wrong source. The version now comes from a committed sidecar beside
the stock yaml, and a missing one fails the build instead.

Only mkyaml's pure helpers are exercised; the generator itself needs
PyYAML, which the build container installs and this stdlib-only suite
does not have to.
"""

import os
import unittest

import ngtest

mkyaml = ngtest.load_build("mkyaml", "mkyaml.py")

STOCK_YAML_BODY = "%YAML 1.1\n---\nsuricata-version: '8.0'\n"
PARAMS_PATH = "hosts/example-gateway/suricata-params.json"
COMMITTED_SIDECAR = os.path.join(ngtest.BUILD_DIR, "suricata-stock.version")


class StockVersionTest(unittest.TestCase):
    """Reading the sidecar, including the two ways it can be unusable."""

    def setUp(self):
        self.tmp = ngtest.temp_dir(self)
        self.stock = os.path.join(self.tmp, "suricata-stock.yaml")
        with open(self.stock, "w") as f:
            f.write(STOCK_YAML_BODY)
        self.sidecar = os.path.join(self.tmp, "suricata-stock.version")

    def write_sidecar(self, body):
        with open(self.sidecar, "w") as f:
            f.write(body)

    def test_version_comes_from_the_sidecar_beside_the_stock_yaml(self):
        self.write_sidecar("suricata-9.1.2-3.fc45\n")

        self.assertEqual(mkyaml.stock_version(self.stock),
                         "suricata-9.1.2-3.fc45")

    def test_surrounding_whitespace_is_trimmed(self):
        # A sidecar edited by hand picks up a trailing newline or an
        # indent; the header must name the version, not the whitespace.
        self.write_sidecar("  suricata-9.1.2-3.fc45  \n\n")

        self.assertEqual(mkyaml.stock_version(self.stock),
                         "suricata-9.1.2-3.fc45")

    def test_missing_sidecar_exits_nonzero_naming_the_file(self):
        with self.assertRaises(SystemExit) as raised:
            mkyaml.stock_version(self.stock)

        self.assertNotEqual(raised.exception.code, 0)
        self.assertIn(self.sidecar, str(raised.exception.code))

    def test_empty_sidecar_exits_nonzero_naming_the_file(self):
        # An empty file is not a version; rendering "the stock  yaml"
        # would be a header that says nothing while looking generated.
        self.write_sidecar("\n")

        with self.assertRaises(SystemExit) as raised:
            mkyaml.stock_version(self.stock)

        self.assertNotEqual(raised.exception.code, 0)
        self.assertIn(self.sidecar, str(raised.exception.code))


class HeaderTest(unittest.TestCase):
    """The header the generator writes above the YAML."""

    def test_header_names_the_sidecar_version_and_the_params_file(self):
        lines = mkyaml.header_lines(PARAMS_PATH, "suricata-9.1.2-3.fc45")

        self.assertEqual(lines[:2], ["%YAML 1.1", "---"])
        self.assertIn("# and the stock suricata-9.1.2-3.fc45 suricata.yaml.",
                      lines)
        self.assertTrue(any(PARAMS_PATH in line for line in lines))

    def test_header_carries_no_hardcoded_version(self):
        # The regression: a version that appears whatever the sidecar
        # says is a version nobody can refresh.
        lines = mkyaml.header_lines(PARAMS_PATH, "suricata-9.1.2-3.fc45")

        self.assertFalse(any("8.0.6" in line for line in lines))


class CommittedSidecarTest(unittest.TestCase):
    """The sidecar build.sh requires is actually in the tree."""

    def test_repository_ships_a_readable_stock_version(self):
        stock = os.path.join(ngtest.BUILD_DIR, "suricata-stock.yaml")

        version = mkyaml.stock_version(stock)

        self.assertTrue(os.path.exists(COMMITTED_SIDECAR))
        self.assertTrue(version.startswith("suricata-"))


if __name__ == "__main__":
    unittest.main()
