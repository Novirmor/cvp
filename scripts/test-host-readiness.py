#!/usr/bin/env python3
"""Credential-free tests of the host readiness probe's isolation boundary."""

from contextlib import redirect_stdout
import importlib.util
from io import StringIO
import os
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch


SOURCE = Path(__file__).with_name("host-readiness.py")
spec = importlib.util.spec_from_file_location("host_readiness", SOURCE)
probe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(probe)


class ReadinessTests(unittest.TestCase):
    def test_default_does_not_enter_a_namespace(self):
        with patch.object(probe, "check_readiness", return_value=[
                {"name": "module vxlan", "passed": False, "detail": "not visible"}]), \
                patch.object(probe, "functional_test") as functional, \
                patch("sys.argv", [str(SOURCE)]), redirect_stdout(StringIO()):
            self.assertEqual(probe.main(), 1)
        functional.assert_not_called()

    def test_functional_mode_requires_isolation(self):
        with patch.object(probe, "run", return_value=(1, "", "unshare: Operation not permitted")) as run:
            result, error = probe.functional_test()
        self.assertIsNone(result)
        self.assertIn("Operation not permitted", error)
        self.assertEqual(run.call_args.args[:4],
                         ("unshare", "--user", "--map-root-user", "--net"))

    def test_hidden_br_netfilter_is_informational(self):
        checks = [{"name": "module br_netfilter", "passed": False, "required": False,
                   "detail": "hidden"},
                  {"name": "module vxlan", "passed": True, "required": True,
                   "detail": "visible"}]
        output = StringIO()
        with patch.object(probe, "check_readiness", return_value=checks), \
                patch.object(probe, "functional_test") as functional, \
                patch("sys.argv", [str(SOURCE)]), redirect_stdout(output):
            self.assertEqual(probe.main(), 0)
        self.assertIn("INFO module br_netfilter", output.getvalue())
        self.assertIn("1/1 passed", output.getvalue())
        functional.assert_not_called()

    def test_functional_mode_reports_namespace_results(self):
        result_text = '[{"name":"VXLAN creation","passed":true,"detail":"device created"}]'
        with patch.object(probe, "run", return_value=(0, result_text, "")):
            result, error = probe.functional_test()
        self.assertEqual(error, "")
        self.assertTrue(result[0]["passed"])

    def test_child_refuses_unisolated_execution_before_creating_devices(self):
        user = os.stat("/proc/self/ns/user").st_ino
        net = os.stat("/proc/self/ns/net").st_ino
        result = subprocess.run([sys.executable, "-c", probe.CHILD, str(user), str(net)],
                                capture_output=True, text=True, timeout=5)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("refusing test", result.stderr)


if __name__ == "__main__":
    unittest.main()
