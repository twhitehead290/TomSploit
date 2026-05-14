#!/usr/bin/env python3
"""Tests for TomSploit.py UI/UX changes."""

import io
import json
import os
import sys
import tempfile
import time
import unittest
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import TomSploit
from TomSploit import (
    NxcAutomator,
    _configure_colors,
    _COLOR_DEFAULTS,
    ALL_PROTOCOLS,
    LOCAL_AUTH_PROTOCOLS,
)


def _make_automator(**kwargs) -> NxcAutomator:
    """Construct a minimal NxcAutomator without hitting the filesystem."""
    defaults = dict(target="192.168.1.1", user="admin", password="pass")
    defaults.update(kwargs)
    return NxcAutomator(**defaults)


class TestConfigureColors(unittest.TestCase):
    def setUp(self):
        self._saved = {name: getattr(TomSploit, name) for name in _COLOR_DEFAULTS}

    def tearDown(self):
        for name, val in self._saved.items():
            setattr(TomSploit, name, val)

    def test_no_color_flag_strips_all_codes(self):
        _configure_colors(no_color=True)
        for name in _COLOR_DEFAULTS:
            self.assertEqual(getattr(TomSploit, name), "", f"{name} should be empty")

    def test_non_tty_strips_codes(self):
        with patch.object(sys.stdout, "isatty", return_value=False):
            _configure_colors(no_color=False)
        self.assertEqual(TomSploit.GREEN, "")
        self.assertEqual(TomSploit.RESET, "")

    def test_tty_preserves_codes(self):
        with patch.object(sys.stdout, "isatty", return_value=True):
            _configure_colors(no_color=False)
        self.assertEqual(TomSploit.GREEN, _COLOR_DEFAULTS["GREEN"])
        self.assertEqual(TomSploit.RESET, _COLOR_DEFAULTS["RESET"])

    def test_no_color_overrides_tty(self):
        with patch.object(sys.stdout, "isatty", return_value=True):
            _configure_colors(no_color=True)
        self.assertEqual(TomSploit.RED, "")

    def test_restore_after_strip(self):
        _configure_colors(no_color=True)
        self.assertEqual(TomSploit.GREEN, "")
        with patch.object(sys.stdout, "isatty", return_value=True):
            _configure_colors(no_color=False)
        self.assertEqual(TomSploit.GREEN, _COLOR_DEFAULTS["GREEN"])


# ── Log file naming ─────────────────────────────────────────────────────────

class TestLogFileNaming(unittest.TestCase):
    def test_default_log_includes_date(self):
        a = _make_automator()
        # Must start with YYYY-MM-DD (10 chars)
        self.assertRegex(a.log_file, r"^\d{4}-\d{2}-\d{2}_\d{2}-\d{2}-\d{2}\.txt$")

    def test_custom_log_path_respected(self):
        a = _make_automator(output="my_scan.log")
        self.assertEqual(a.log_file, "my_scan.log")

    def test_default_log_does_not_use_old_format(self):
        """Old format was HH-MM-SS-mmm.txt (no date). Must not match that pattern."""
        a = _make_automator()
        # Old format: digits only before first dash, no YYYY prefix
        self.assertNotRegex(a.log_file, r"^\d{2}-\d{2}-\d{2}-\d{3}\.txt$")


# ── Credential pairing ──────────────────────────────────────────────────────

class TestCredentialPairing(unittest.TestCase):
    def test_combination_cartesian_product(self):
        a = _make_automator(user="u1", password="p1")
        a.users = ["u1", "u2"]
        a.passwords = ["p1", "p2"]
        pairs = a._build_credential_pairs()
        self.assertEqual(pairs, [("u1", "p1"), ("u1", "p2"), ("u2", "p1"), ("u2", "p2")])

    def test_linear_zip(self):
        a = _make_automator(mode="linear")
        a.users = ["u1", "u2"]
        a.passwords = ["p1", "p2"]
        pairs = a._build_credential_pairs()
        self.assertEqual(pairs, [("u1", "p1"), ("u2", "p2")])

    def test_linear_length_mismatch_raises(self):
        a = _make_automator(mode="linear")
        a.users = ["u1", "u2"]
        a.passwords = ["p1"]
        with self.assertRaises(ValueError):
            a._build_credential_pairs()

    def test_single_credential_pair(self):
        a = _make_automator()
        self.assertEqual(a.credential_pairs, [("admin", "pass")])


# ── Progress bar ETA ────────────────────────────────────────────────────────

class TestProgressBarETA(unittest.TestCase):
    def _capture_progress(self, automator: NxcAutomator) -> str:
        buf = io.StringIO()
        with patch("sys.stderr", buf):
            automator._redraw_progress()
        return buf.getvalue()

    def test_eta_shown_when_scan_running(self):
        a = _make_automator()
        a.total_tasks = 10
        a.completed = 5
        a.scan_start_time = time.time() - 10  # 10s elapsed, ~10s remaining
        out = self._capture_progress(a)
        self.assertIn("ETA", out)
        self.assertIn("s", out)

    def test_no_eta_when_no_start_time(self):
        a = _make_automator()
        a.total_tasks = 10
        a.completed = 5
        a.scan_start_time = 0.0
        out = self._capture_progress(a)
        self.assertNotIn("ETA", out)

    def test_no_eta_when_no_progress(self):
        a = _make_automator()
        a.total_tasks = 10
        a.completed = 0
        a.scan_start_time = time.time() - 5
        out = self._capture_progress(a)
        self.assertNotIn("ETA", out)

    def test_progress_bar_format(self):
        a = _make_automator()
        a.total_tasks = 10
        a.completed = 5
        a.scan_start_time = time.time() - 10
        out = self._capture_progress(a)
        self.assertIn("50%", out)
        self.assertIn("5/10", out)


# ── _parse_nxc_line ──────────────────────────────────────────────────────────

class TestParseNxcLine(unittest.TestCase):
    def test_parses_success_marker(self):
        line = "SMB  10.10.10.10  445  DC01  [+] CORP\\admin:Password123"
        marker, msg = NxcAutomator._parse_nxc_line(line)
        self.assertEqual(marker, "[+]")
        self.assertEqual(msg, "CORP\\admin:Password123")

    def test_parses_failure_marker(self):
        line = "SMB  10.10.10.10  445  DC01  [-] CORP\\admin:wrongpass STATUS_LOGON_FAILURE"
        marker, msg = NxcAutomator._parse_nxc_line(line)
        self.assertEqual(marker, "[-]")

    def test_parses_info_marker(self):
        line = "SMB  10.10.10.10  445  DC01  [*] Windows Server 2019 name:DC01"
        marker, msg = NxcAutomator._parse_nxc_line(line)
        self.assertEqual(marker, "[*]")
        self.assertIn("DC01", msg)

    def test_no_marker_returns_none(self):
        line = "some random line without a marker"
        marker, msg = NxcAutomator._parse_nxc_line(line)
        self.assertIsNone(marker)
        self.assertEqual(msg, line)

    def test_empty_line(self):
        marker, msg = NxcAutomator._parse_nxc_line("")
        self.assertIsNone(marker)
        self.assertEqual(msg, "")


# ── _classify_attempt_output ─────────────────────────────────────────────────

class TestClassifyAttemptOutput(unittest.TestCase):
    def setUp(self):
        self.a = _make_automator()

    def test_auth_failure_pattern(self):
        result = self.a._classify_attempt_output("STATUS_LOGON_FAILURE", "")
        self.assertEqual(result, "credential_response")

    def test_connectivity_timeout_pattern(self):
        result = self.a._classify_attempt_output("", "Connection timed out")
        self.assertEqual(result, "connectivity_timeout")

    def test_nxc_marker_is_credential_response(self):
        result = self.a._classify_attempt_output("SMB 10.0.0.1 445 DC01 [-] bad", "")
        self.assertEqual(result, "credential_response")

    def test_empty_output_is_ambiguous(self):
        result = self.a._classify_attempt_output("", "")
        self.assertEqual(result, "ambiguous")

    def test_connection_refused_is_timeout(self):
        result = self.a._classify_attempt_output("connection refused", "")
        self.assertEqual(result, "connectivity_timeout")

    def test_success_marker_is_credential_response(self):
        result = self.a._classify_attempt_output("SMB 10.0.0.1 445 DC01 [+] win\\admin:pass", "")
        self.assertEqual(result, "credential_response")


# ── _is_domain_controller ────────────────────────────────────────────────────

class TestIsDomainController(unittest.TestCase):
    def test_dc_prefix_name(self):
        self.assertTrue(NxcAutomator._is_domain_controller("Windows Server 2019 name:DC01 domain:corp.local"))

    def test_pdc_name(self):
        self.assertTrue(NxcAutomator._is_domain_controller("Windows Server 2019 name:PDC01 domain:corp.local"))

    def test_addc_name(self):
        self.assertTrue(NxcAutomator._is_domain_controller("Windows Server 2022 name:ADDC01"))

    def test_regular_server_not_dc(self):
        self.assertFalse(NxcAutomator._is_domain_controller("Windows Server 2019 name:FILESERVER01"))

    def test_none_input(self):
        self.assertFalse(NxcAutomator._is_domain_controller(None))

    def test_empty_string(self):
        self.assertFalse(NxcAutomator._is_domain_controller(""))


# ── _parse_credentials ───────────────────────────────────────────────────────

class TestParseCredentials(unittest.TestCase):
    def setUp(self):
        self.a = _make_automator()

    def test_domain_user_password(self):
        domain, user, password = self.a._parse_credentials("CORP\\admin:Password123 (Pwn3d!)")
        self.assertEqual(domain, "CORP")
        self.assertEqual(user, "admin")
        self.assertEqual(password, "Password123")

    def test_user_password_no_domain(self):
        domain, user, password = self.a._parse_credentials("admin:Password123")
        self.assertEqual(user, "admin")
        self.assertEqual(password, "Password123")
        self.assertEqual(domain, "")

    def test_malformed_returns_empty_strings(self):
        domain, user, password = self.a._parse_credentials("notavalidcredstring")
        self.assertEqual(domain, "")
        self.assertEqual(user, "")
        self.assertEqual(password, "")


# ── Quiet mode ───────────────────────────────────────────────────────────────

class TestQuietMode(unittest.TestCase):
    def _run_print_target_results(self, automator, tasks, results, anon_results):
        buf = io.StringIO()
        with patch("sys.stdout", buf):
            ret = automator._print_target_results(
                "192.168.1.1", results, tasks, anon_results, elapsed=1.0
            )
        return buf.getvalue(), ret

    def _empty_results(self, tasks):
        return {key: ["[-] auth_failed STATUS_LOGON_FAILURE"] for key in tasks}

    def test_banner_suppressed_in_quiet_mode(self):
        a = _make_automator(quiet=True)
        buf = io.StringIO()
        with patch("sys.stdout", buf):
            a._print_scan_banner(100)
        self.assertEqual(buf.getvalue(), "")

    def test_banner_shown_in_normal_mode(self):
        a = _make_automator(quiet=False)
        buf = io.StringIO()
        with patch("sys.stdout", buf):
            a._print_scan_banner(100)
        self.assertIn("NetExec Automator", buf.getvalue())

    def test_no_valid_creds_message_suppressed(self):
        a = _make_automator(quiet=True)
        tasks = NxcAutomator._build_protocol_tasks()
        results = self._empty_results(tasks)
        out, _ = self._run_print_target_results(a, tasks, results, [])
        self.assertNotIn("No valid credentials found", out)

    def test_no_valid_creds_message_shown_in_normal_mode(self):
        a = _make_automator(quiet=False)
        tasks = NxcAutomator._build_protocol_tasks()
        results = self._empty_results(tasks)
        out, _ = self._run_print_target_results(a, tasks, results, [])
        self.assertIn("No valid credentials found", out)

    def test_failure_lines_suppressed_in_quiet_mode(self):
        a = _make_automator(quiet=True)
        tasks = NxcAutomator._build_protocol_tasks()
        results = self._empty_results(tasks)
        out, _ = self._run_print_target_results(a, tasks, results, [])
        self.assertNotIn("auth_failed", out)

    def test_success_lines_still_shown_in_quiet_mode(self):
        a = _make_automator(quiet=True)
        tasks = NxcAutomator._build_protocol_tasks()
        results = {key: [] for key in tasks}
        results[("smb", False)] = ["SMB 192.168.1.1 445 SRV01 [+] CORP\\admin:pass"]
        out, (successes, _, _, _) = self._run_print_target_results(a, tasks, results, [])
        self.assertTrue(len(successes) > 0)
        self.assertIn("VALID CREDENTIALS", out)

    def test_no_response_line_suppressed_in_quiet_mode(self):
        a = _make_automator(quiet=True)
        tasks = NxcAutomator._build_protocol_tasks()
        results = {}  # all empty = no output protos
        out, _ = self._run_print_target_results(a, tasks, results, [])
        self.assertNotIn("No response", out)


# ── Multi-target summary table ───────────────────────────────────────────────

class TestSummaryTable(unittest.TestCase):
    def _capture_summary(self, summary):
        a = _make_automator()
        buf = io.StringIO()
        with patch("sys.stdout", buf):
            a._print_summary_table(summary)
        return buf.getvalue()

    def test_summary_shows_target_count(self):
        summary = [
            {"target": "10.0.0.1", "hostname": "", "is_dc": False, "elapsed": 5.0, "successes": []},
            {"target": "10.0.0.2", "hostname": "DC01", "is_dc": True, "elapsed": 3.0, "successes": [("SMB (domain)", "CORP\\admin:pass")]},
        ]
        out = self._capture_summary(summary)
        self.assertIn("2 targets", out)
        self.assertIn("Scan Summary", out)

    def test_summary_shows_dc_tag(self):
        summary = [
            {"target": "10.0.0.2", "hostname": "DC01", "is_dc": True, "elapsed": 3.0, "successes": []},
        ]
        out = self._capture_summary(summary)
        self.assertIn("DC", out)

    def test_summary_total_count(self):
        summary = [
            {"target": "10.0.0.1", "hostname": "", "is_dc": False, "elapsed": 5.0, "successes": [("SMB (domain)", "user:pass")]},
            {"target": "10.0.0.2", "hostname": "", "is_dc": False, "elapsed": 4.0, "successes": []},
            {"target": "10.0.0.3", "hostname": "", "is_dc": False, "elapsed": 3.0, "successes": [("WMI (domain)", "user:pass")]},
        ]
        out = self._capture_summary(summary)
        self.assertIn("2/3", out)

    def test_run_calls_summary_only_for_multiple_targets(self):
        a = _make_automator()
        a._print_scan_banner = MagicMock()
        a._print_summary_table = MagicMock()
        a._run_anon_smb = MagicMock(return_value=[])
        a._collect_target_results = MagicMock(return_value={})
        a._print_target_results = MagicMock(return_value=([], False, "", "192.168.1.1"))

        with patch("sys.stderr"), patch("sys.stdout"):
            a.run()

        a._print_summary_table.assert_not_called()

    def test_run_calls_summary_for_multiple_targets(self):
        a = _make_automator()
        a.targets = ["10.0.0.1", "10.0.0.2"]
        a._print_scan_banner = MagicMock()
        a._print_summary_table = MagicMock()
        a._run_anon_smb = MagicMock(return_value=[])
        a._collect_target_results = MagicMock(return_value={})
        a._print_target_results = MagicMock(return_value=([], False, "", "10.0.0.1"))

        with patch("sys.stderr"), patch("sys.stdout"):
            a.run()

        a._print_summary_table.assert_called_once()


# ── Per-target timing ────────────────────────────────────────────────────────

class TestPerTargetTiming(unittest.TestCase):
    def test_elapsed_label_in_results_header(self):
        a = _make_automator()
        tasks = NxcAutomator._build_protocol_tasks()
        buf = io.StringIO()
        with patch("sys.stdout", buf):
            a._print_target_results("192.168.1.1", {}, tasks, [], elapsed=12.5)
        self.assertIn("12.5s", buf.getvalue())

    def test_no_elapsed_label_when_zero(self):
        a = _make_automator()
        tasks = NxcAutomator._build_protocol_tasks()
        buf = io.StringIO()
        with patch("sys.stdout", buf):
            a._print_target_results("192.168.1.1", {}, tasks, [], elapsed=0.0)
        self.assertNotIn("0.0s", buf.getvalue())


# ── JSON output ──────────────────────────────────────────────────────────────

class TestJsonOutput(unittest.TestCase):
    def test_json_file_created_with_correct_structure(self):
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False, mode="w") as f:
            json_path = f.name
        try:
            a = _make_automator(json_output=json_path)
            summary = [
                {
                    "target": "10.0.0.1",
                    "real_ip": "10.0.0.1",
                    "hostname": "SRV01",
                    "is_dc": False,
                    "elapsed": 5.23,
                    "successes": [("SMB (domain)", "CORP\\admin:pass")],
                }
            ]
            with patch("sys.stdout"):
                a._write_json_output(summary)

            with open(json_path) as f:
                data = json.load(f)

            self.assertIn("scan_time", data)
            self.assertIn("targets", data)
            self.assertEqual(len(data["targets"]), 1)
            t = data["targets"][0]
            self.assertEqual(t["target"], "10.0.0.1")
            self.assertEqual(t["hostname"], "SRV01")
            self.assertFalse(t["is_dc"])
            self.assertEqual(t["elapsed_seconds"], 5.23)
            self.assertEqual(len(t["successes"]), 1)
            self.assertEqual(t["successes"][0]["protocol"], "SMB (domain)")
            self.assertEqual(t["successes"][0]["credential"], "CORP\\admin:pass")
        finally:
            os.unlink(json_path)

    def test_json_output_with_empty_successes(self):
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False, mode="w") as f:
            json_path = f.name
        try:
            a = _make_automator(json_output=json_path)
            summary = [
                {
                    "target": "10.0.0.2",
                    "real_ip": "10.0.0.2",
                    "hostname": "",
                    "is_dc": False,
                    "elapsed": 2.0,
                    "successes": [],
                }
            ]
            with patch("sys.stdout"):
                a._write_json_output(summary)

            with open(json_path) as f:
                data = json.load(f)

            self.assertEqual(data["targets"][0]["successes"], [])
        finally:
            os.unlink(json_path)

    def test_json_not_written_when_not_configured(self):
        a = _make_automator()
        a._print_scan_banner = MagicMock()
        a._run_anon_smb = MagicMock(return_value=[])
        a._collect_target_results = MagicMock(return_value={})
        a._print_target_results = MagicMock(return_value=([], False, "", "192.168.1.1"))
        a._write_json_output = MagicMock()

        with patch("sys.stderr"), patch("sys.stdout"):
            a.run()

        a._write_json_output.assert_not_called()


# ── Argument parsing ─────────────────────────────────────────────────────────

class TestArgParsing(unittest.TestCase):
    def _parse(self, args_list):
        with patch("sys.argv", ["prog"] + args_list):
            return TomSploit.parse_args()

    def test_quiet_flag(self):
        args = self._parse(["-t", "10.0.0.1", "-u", "admin", "-p", "pass", "-q"])
        self.assertTrue(args.quiet)

    def test_no_color_flag(self):
        args = self._parse(["-t", "10.0.0.1", "-u", "admin", "-p", "pass", "--no-color"])
        self.assertTrue(args.no_color)

    def test_json_output_flag(self):
        args = self._parse(["-t", "10.0.0.1", "-u", "admin", "-p", "pass", "--json-output", "out.json"])
        self.assertEqual(args.json_output, "out.json")

    def test_defaults(self):
        args = self._parse(["-t", "10.0.0.1", "-u", "admin", "-p", "pass"])
        self.assertFalse(args.quiet)
        self.assertFalse(args.no_color)
        self.assertIsNone(args.json_output)
        self.assertEqual(args.mode, "combination")

    def test_linear_mode(self):
        args = self._parse(["-t", "10.0.0.1", "-u", "admin", "-p", "pass", "-m", "linear"])
        self.assertEqual(args.mode, "linear")

    def test_invalid_mode_exits(self):
        with self.assertRaises(SystemExit):
            self._parse(["-t", "10.0.0.1", "-u", "admin", "-p", "pass", "-m", "badmode"])


# ── _build_protocol_tasks ────────────────────────────────────────────────────

class TestBuildProtocolTasks(unittest.TestCase):
    def test_task_count(self):
        tasks = NxcAutomator._build_protocol_tasks()
        expected = len(ALL_PROTOCOLS) + len(LOCAL_AUTH_PROTOCOLS)
        self.assertEqual(len(tasks), expected)

    def test_local_auth_only_for_supported_protocols(self):
        tasks = NxcAutomator._build_protocol_tasks()
        local_auth_protos = {proto for proto, local in tasks if local}
        self.assertEqual(local_auth_protos, LOCAL_AUTH_PROTOCOLS)

    def test_all_protocols_have_domain_task(self):
        tasks = NxcAutomator._build_protocol_tasks()
        domain_protos = {proto for proto, local in tasks if not local}
        self.assertEqual(domain_protos, set(ALL_PROTOCOLS))


# ── _extract_ip_from_nxc_line ────────────────────────────────────────────────

class TestExtractIpFromNxcLine(unittest.TestCase):
    def test_extracts_valid_ip(self):
        line = "SMB  192.168.1.55  445  DC01  [+] CORP\\admin:pass"
        ip = NxcAutomator._extract_ip_from_nxc_line(line)
        self.assertEqual(ip, "192.168.1.55")

    def test_returns_none_for_hostname(self):
        line = "SMB  DC01.corp.local  445  DC01  [+] CORP\\admin:pass"
        ip = NxcAutomator._extract_ip_from_nxc_line(line)
        self.assertIsNone(ip)

    def test_returns_none_for_short_line(self):
        ip = NxcAutomator._extract_ip_from_nxc_line("SMB")
        self.assertIsNone(ip)


# ── _format_stderr_block ─────────────────────────────────────────────────────

class TestFormatStderrBlock(unittest.TestCase):
    def setUp(self):
        self.a = _make_automator()

    def test_returns_none_for_empty_stderr(self):
        self.assertIsNone(self.a._format_stderr_block("", "[-]"))

    def test_uses_fallback_marker_for_plain_lines(self):
        result = self.a._format_stderr_block("some error text", "[!]")
        self.assertIn("[!]", result)

    def test_preserves_existing_markers(self):
        result = self.a._format_stderr_block("[-] logon failure", "[!]")
        self.assertIn("[-]", result)

    def test_skips_blank_lines(self):
        result = self.a._format_stderr_block("\n\n", "[-]")
        self.assertIsNone(result)


# ── _print_target_results return value ──────────────────────────────────────

class TestPrintTargetResultsReturn(unittest.TestCase):
    def test_returns_four_tuple(self):
        a = _make_automator()
        tasks = NxcAutomator._build_protocol_tasks()
        buf = io.StringIO()
        with patch("sys.stdout", buf):
            result = a._print_target_results("192.168.1.1", {}, tasks, [], elapsed=0.0)
        self.assertIsInstance(result, tuple)
        self.assertEqual(len(result), 4)
        successes, is_dc, hostname, real_ip = result
        self.assertIsInstance(successes, list)
        self.assertIsInstance(is_dc, bool)
        self.assertIsInstance(hostname, str)
        self.assertIsInstance(real_ip, str)

    def test_success_line_collected(self):
        a = _make_automator()
        tasks = NxcAutomator._build_protocol_tasks()
        results = {("smb", False): ["SMB 192.168.1.1 445 SRV01 [+] CORP\\admin:Password1"]}
        buf = io.StringIO()
        with patch("sys.stdout", buf):
            successes, _, _, _ = a._print_target_results("192.168.1.1", results, tasks, [], elapsed=0.0)
        self.assertEqual(len(successes), 1)
        self.assertIn("SMB", successes[0][0])


if __name__ == "__main__":
    unittest.main(verbosity=2)
