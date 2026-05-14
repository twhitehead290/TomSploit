#!/usr/bin/env python3
# MIT License
# Copyright (c) 2026 Kazgangap
# Modifications Copyright (c) 2026 twhitehead290
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

import argparse
import ipaddress
import json
import os
import re
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from threading import Lock
from typing import Literal

RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
BLUE = "\033[94m"
CYAN = "\033[96m"
BOLD = "\033[1m"
DIM = "\033[2m"
RESET = "\033[0m"

# Original ANSI values kept so _configure_colors can restore them if needed
_COLOR_DEFAULTS = {
    "RED": "\033[91m", "GREEN": "\033[92m", "YELLOW": "\033[93m",
    "BLUE": "\033[94m", "CYAN": "\033[96m", "BOLD": "\033[1m",
    "DIM": "\033[2m", "RESET": "\033[0m",
}


def _configure_colors(no_color: bool) -> None:
    """Strip ANSI codes when stdout is not a TTY or --no-color is set."""
    global RED, GREEN, YELLOW, BLUE, CYAN, BOLD, DIM, RESET
    if no_color or not sys.stdout.isatty():
        RED = GREEN = YELLOW = BLUE = CYAN = BOLD = DIM = RESET = ""
    else:
        for name, val in _COLOR_DEFAULTS.items():
            globals()[name] = val


ALL_PROTOCOLS = ["smb", "ssh", "ldap", "ftp", "wmi", "winrm", "rdp", "vnc", "mssql", "nfs"]
LOCAL_AUTH_PROTOCOLS = {"smb", "wmi", "winrm", "rdp", "mssql"}

DEFAULT_WORKERS = len(ALL_PROTOCOLS) + len(LOCAL_AUTH_PROTOCOLS)
MAX_RETRY = 3
SUBPROCESS_TIMEOUT = 45
NETEXEC_TIMEOUT = 30
BANNER_WIDTH = 60
PROGRESS_CLEAR_WIDTH = 70

# Standard credential-based command templates
COMMAND_TEMPLATES = {
    "winrm": "evil-winrm -i {ip} -u {user} -p '{password}'",
    "smb":   "impacket-psexec {domain}/{user}:'{password}'@{ip}",
    "rdp":   "xfreerdp3 /u:{user} /p:'{password}' /d:{domain} /v:{ip} /dynamic-resolution /drive:share,/home/kali",
    "wmi":   "impacket-wmiexec {domain}/{user}:'{password}'@{ip}",
    "ssh":   "ssh {user}@{ip}",
    "mssql": "impacket-mssqlclient {domain}/{user}:'{password}'@{ip} -windows-auth",
    "ldap":  "ldapdomaindump -u '{domain}\\{user}' -p '{password}' {ip}",
}

# Pass-the-hash command templates (triggered with -H flag)
HASH_TEMPLATES = {
    "winrm": "evil-winrm -i {ip} -u {user} -H {hash}",
    "smb":   "impacket-psexec {domain}/{user}@{ip} -hashes :{hash}",
    "rdp":   "xfreerdp3 /u:{user} /pth:{hash} /d:{domain} /v:{ip} /dynamic-resolution /drive:share,/home/kali",
    "wmi":   "impacket-wmiexec {domain}/{user}@{ip} -hashes :{hash}",
    "mssql": "impacket-mssqlclient {domain}/{user}@{ip} -hashes :{hash} -windows-auth",
}

# DC-specific commands (replaces generic templates when target is identified as a DC)
DC_COMMAND_TEMPLATES = {
    "ldap": [
        ("BloodHound",     "bloodhound-python -u {user} -p '{password}' -d {domain} -dc {hostname}.{domain} -ns {ip} -c All --zip"),
        ("getTGT",         "impacket-getTGT {domain}/{user}:'{password}'"),
        ("ldapdomaindump", "ldapdomaindump -u '{domain}\\{user}' -p '{password}' {ip}"),
    ],
    "smb": [
        ("psexec",         "impacket-psexec {domain}/{user}:'{password}'@{ip}"),
        ("smbexec",        "impacket-smbexec {domain}/{user}:'{password}'@{ip}"),
        ("smbclient",      "smbclient -U '{domain}\\{user}%{password}' //{ip}/SYSVOL"),
    ],
}

DC_HASH_TEMPLATES = {
    "ldap": [
        ("secretsdump",    "impacket-secretsdump {domain}/{user}@{ip} -hashes :{hash}"),
        ("getTGT",         "impacket-getTGT {domain}/{user} -hashes :{hash}"),
    ],
    "smb": [
        ("psexec",         "impacket-psexec {domain}/{user}@{ip} -hashes :{hash}"),
        ("secretsdump",    "impacket-secretsdump {domain}/{user}@{ip} -hashes :{hash}"),
    ],
}

TaskKey = tuple[str, bool]
ParsedStatus = tuple[str, str]
AttemptClassification = Literal["credential_response", "connectivity_timeout", "ambiguous"]

AUTH_RESPONSE_PATTERNS = (
    "status_logon_failure",
    "status_access_denied",
    "rpc_s_access_denied",
    "access denied",
    "authentication failed",
    "invalid credentials",
    "bad credentials",
    "permission denied",
    "login failed",
    "logon failure",
)

CONNECTIVITY_TIMEOUT_PATTERNS = (
    "timed out",
    "connection timeout",
    "connection refused",
    "connection reset",
    "reset by peer",
    "could not connect",
    "connection error",
    "host is unreachable",
    "no route to host",
    "network is unreachable",
    "netbios connection",
    "name or service not known",
    "temporary failure in name resolution",
    "broken pipe",
    "errno 110",
    "errno 111",
    "errno 113",
)


class NxcAutomator:
    """Run nxc across all protocols with combination or linear credential pairing."""

    def __init__(
        self,
        target: str,
        user: str,
        password: str,
        hash_val: str | None = None,
        output: str | None = None,
        workers: int = DEFAULT_WORKERS,
        mode: str = "combination",
        quiet: bool = False,
        json_output: str | None = None,
    ):
        self.targets = self._read_value_or_file(target)
        self.users = self._read_value_or_file(user)
        self.passwords = self._read_value_or_file(password)
        self.hash_val = hash_val
        self.mode = mode.lower()
        self.credential_pairs = self._build_credential_pairs()
        self.workers = workers
        self.quiet = quiet
        self.json_output = json_output
        self.lock = Lock()
        self.completed = 0
        self.total_tasks = 0
        self.scan_start_time: float = 0.0
        self.log_file = output if output else datetime.now().strftime("%Y-%m-%d_%H-%M-%S") + ".txt"

    @staticmethod
    def _read_lines(path: str) -> list[str]:
        with open(path) as f:
            return [line.strip() for line in f if line.strip()]

    @classmethod
    def _read_value_or_file(cls, source: str) -> list[str]:
        """Return direct value as one-item list, or load non-empty lines from file."""
        return cls._read_lines(source) if os.path.isfile(source) else [source]

    @staticmethod
    def _auth_scope(local_auth: bool) -> str:
        return "local" if local_auth else "domain"

    def _task_label(self, protocol: str, local_auth: bool) -> str:
        """Return standardized display label for protocol/auth scope."""
        return f"{protocol.upper()} ({self._auth_scope(local_auth)})"

    @staticmethod
    def _build_protocol_tasks() -> list[TaskKey]:
        tasks: list[TaskKey] = []
        for protocol in ALL_PROTOCOLS:
            tasks.append((protocol, False))
            if protocol in LOCAL_AUTH_PROTOCOLS:
                tasks.append((protocol, True))
        return tasks

    def _build_credential_pairs(self) -> list[tuple[str, str]]:
        if self.mode == "combination":
            return [(user, password) for user in self.users for password in self.passwords]
        if self.mode == "linear":
            if len(self.users) != len(self.passwords):
                raise ValueError(
                    "Linear mode requires user and password lists to have the same length."
                )
            return list(zip(self.users, self.passwords))
        raise ValueError(f"Unsupported mode: {self.mode}")

    def _redraw_progress(self):
        if self.total_tasks > 0:
            bar_len = 20
            filled = int(bar_len * self.completed / self.total_tasks)
            bar = f"{'█' * filled}{'░' * (bar_len - filled)}"
            pct = int(100 * self.completed / self.total_tasks)

            elapsed = time.time() - self.scan_start_time if self.scan_start_time else 0
            if elapsed > 0 and self.completed > 0:
                rate = self.completed / elapsed
                remaining = self.total_tasks - self.completed
                eta_secs = int(remaining / rate)
                eta_str = f" ETA {eta_secs}s" if eta_secs < 9999 else " ETA --"
            else:
                eta_str = ""

            sys.stderr.write(
                f"\r  {DIM}{bar} {pct:3d}% ({self.completed}/{self.total_tasks}){eta_str}{RESET}"
            )
            sys.stderr.flush()

    def _update_progress(self):
        with self.lock:
            self.completed += 1
            self._redraw_progress()

    def _skip_progress(self, count: int):
        with self.lock:
            self.completed += count
            self._redraw_progress()

    def _print_live(self, msg: str):
        """Print a finding in real-time, temporarily clearing the progress bar."""
        with self.lock:
            sys.stderr.write("\r" + " " * PROGRESS_CLEAR_WIDTH + "\r")
            sys.stderr.flush()
            print(msg, flush=True)
            self._redraw_progress()

    def _build_nxc_command(
        self, protocol: str, target: str, user: str, password: str, local_auth: bool
    ) -> list[str]:
        cmd = ["nxc", protocol, target, "-u", user, "-p", password]
        if local_auth:
            cmd.append("--local-auth")
        cmd.extend(["--timeout", str(NETEXEC_TIMEOUT), "--log", self.log_file])
        return cmd

    def _report_success_lines(self, stdout: str, protocol: str, local_auth: bool):
        for raw_line in stdout.split("\n"):
            marker, msg = self._parse_nxc_line(raw_line.strip())
            if marker == "[+]":
                label = self._task_label(protocol, local_auth)
                self._print_live(
                    f"  {GREEN}{BOLD}⚡ {label}{RESET} {GREEN}{msg}{RESET}"
                )

    @staticmethod
    def _parse_status_blocks(blocks: list[str]) -> list[ParsedStatus]:
        parsed: list[ParsedStatus] = []
        for block in blocks:
            for line in block.split("\n"):
                line = line.strip()
                if not line:
                    continue
                marker, msg = NxcAutomator._parse_nxc_line(line)
                if marker in ("[+]", "[-]", "[!]"):
                    parsed.append((marker, msg))
        return parsed

    @staticmethod
    def _status_icon(parsed: list[ParsedStatus]) -> str:
        has_success = any(marker == "[+]" for marker, _ in parsed)
        has_skip = any(marker == "[!]" for marker, _ in parsed)
        if has_success:
            return f"{GREEN}✔{RESET}"
        if has_skip:
            return f"{YELLOW}⏱{RESET}"
        return f"{RED}✘{RESET}"

    @staticmethod
    def _contains_any_pattern(text: str, patterns: tuple[str, ...]) -> bool:
        return any(pattern in text for pattern in patterns)

    def _classify_attempt_output(self, stdout: str, stderr: str) -> AttemptClassification:
        """Classify one nxc run to decide timeout skip behavior."""
        combined = "\n".join(part for part in (stdout, stderr) if part).lower()
        if not combined:
            return "ambiguous"

        if self._contains_any_pattern(combined, AUTH_RESPONSE_PATTERNS):
            return "credential_response"

        if self._contains_any_pattern(combined, CONNECTIVITY_TIMEOUT_PATTERNS):
            return "connectivity_timeout"

        for raw_line in (stdout + "\n" + stderr).split("\n"):
            marker, _ = self._parse_nxc_line(raw_line.strip())
            if marker in ("[+]", "[-]", "[*]", "[!]"):
                return "credential_response"

        return "ambiguous"

    def _format_stderr_block(self, stderr: str, fallback_marker: str) -> str | None:
        """Convert stderr lines to parseable status lines for result summary."""
        formatted: list[str] = []
        for raw_line in stderr.split("\n"):
            line = raw_line.strip()
            if not line:
                continue
            marker, msg = self._parse_nxc_line(line)
            if marker in ("[+]", "[-]", "[!]"):
                formatted.append(f"{marker} {msg}")
            else:
                formatted.append(f"{fallback_marker} {line}")
        return "\n".join(formatted) if formatted else None

    def _run_protocol_task(self, protocol: str, target: str, local_auth: bool = False) -> list[str]:
        """Run all credential pairs for one protocol/auth-type, return captured output."""
        output_lines: list[str] = []
        timeout_count = 0
        total_per_task = len(self.credential_pairs)
        ran = 0
        for user, password in self.credential_pairs:
            cmd = self._build_nxc_command(protocol, target, user, password, local_auth)
            try:
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=SUBPROCESS_TIMEOUT)
                stdout = (result.stdout or "").strip()
                stderr = (result.stderr or "").strip()
                classification = self._classify_attempt_output(stdout, stderr)

                if stdout:
                    output_lines.append(stdout)
                    self._report_success_lines(stdout, protocol, local_auth)

                if stderr and (not stdout or classification == "connectivity_timeout"):
                    marker = "[!]" if classification == "connectivity_timeout" else "[-]"
                    stderr_block = self._format_stderr_block(stderr, marker)
                    if stderr_block:
                        output_lines.append(stderr_block)

                if classification == "connectivity_timeout":
                    timeout_count += 1
                else:
                    timeout_count = 0
            except subprocess.TimeoutExpired:
                timeout_count += 1

            ran += 1
            self._update_progress()

            if timeout_count >= MAX_RETRY:
                output_lines.append(f"[!] {MAX_RETRY} consecutive timeouts — skipped")
                label = self._task_label(protocol, local_auth)
                self._print_live(
                    f"  {YELLOW}⏱ {label}{RESET} {DIM}{MAX_RETRY} consecutive timeouts — skipping{RESET}"
                )
                remaining = total_per_task - ran
                if remaining > 0:
                    self._skip_progress(remaining)
                break
        return output_lines

    def _run_anon_smb(self, target: str) -> list[str]:
        """Check for anonymous SMB access using empty credentials."""
        output_lines: list[str] = []
        cmd = ["nxc", "smb", target, "-u", "", "-p", "",
               "--timeout", str(NETEXEC_TIMEOUT), "--log", self.log_file]
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=SUBPROCESS_TIMEOUT)
            stdout = (result.stdout or "").strip()
            stderr = (result.stderr or "").strip()
            if stdout:
                output_lines.append(stdout)
                for raw_line in stdout.split("\n"):
                    marker, msg = self._parse_nxc_line(raw_line.strip())
                    if marker == "[+]":
                        self._print_live(
                            f"  {YELLOW}{BOLD}⚡ SMB (anon){RESET} {YELLOW}{msg}{RESET}"
                        )
            if stderr and not stdout:
                stderr_block = self._format_stderr_block(stderr, "[-]")
                if stderr_block:
                    output_lines.append(stderr_block)
        except subprocess.TimeoutExpired:
            output_lines.append("[!] Anonymous SMB check timed out")
        return output_lines

    @staticmethod
    def _parse_nxc_line(line: str) -> tuple[str | None, str]:
        """Extract status marker and message from nxc output.

        'SMB  10.x.x.x  445  DC01  [+] dom\\user:pass' -> ('[+]', 'dom\\user:pass')
        """
        for marker in ("[+]", "[-]", "[*]", "[!]"):
            idx = line.find(marker)
            if idx != -1:
                return marker, line[idx + 4:].strip()
        return None, line.strip()

    @staticmethod
    def _extract_target_info(results: dict) -> str | None:
        """Get first [*] info line to display target OS/host details once."""
        for blocks in results.values():
            for block in blocks:
                for line in block.split("\n"):
                    if "[*]" in line:
                        idx = line.find("[*]")
                        return line[idx + 4:].strip()
        return None

    @staticmethod
    def _extract_ip_from_nxc_line(line: str) -> str | None:
        """Pull the resolved host IP from a raw nxc output line.

        nxc lines look like:
          SMB  192.168.219.55  445  DC01  [+] ...
        The IP is always the second whitespace-separated token.
        """
        parts = line.split()
        if len(parts) >= 2:
            match = re.match(r"^\d{1,3}(\.\d{1,3}){3}$", parts[1])
            if match:
                return parts[1]
        return None

    def _extract_real_ip(self, results: dict, anon_smb_results: list[str]) -> str | None:
        """Return the first real host IP seen across all raw nxc output blocks."""
        all_blocks: list[str] = list(anon_smb_results)
        for blocks in results.values():
            all_blocks.extend(blocks)
        for block in all_blocks:
            for line in block.split("\n"):
                ip = self._extract_ip_from_nxc_line(line.strip())
                if ip:
                    return ip
        return None

    @staticmethod
    def _is_domain_controller(target_info: str | None) -> bool:
        """Detect if the target is a DC from the nxc [*] info line."""
        if not target_info:
            return False
        info_lower = target_info.lower()
        name_match = re.search(r"name:([^\s)]+)", info_lower)
        if name_match:
            hostname = name_match.group(1)
            if re.search(r"\bdc\d*\b|^dc|pdc|addc", hostname):
                return True
        return False

    def _parse_credentials(self, msg: str) -> tuple[str, str, str]:
        """Parse domain, user, password from a nxc success message string."""
        domain, user, password = "", "", ""
        try:
            if "\\" in msg:
                domain_user, rest = msg.split(":", 1)
                password = rest.split()[0]
                domain, user = domain_user.split("\\", 1)
            else:
                user, rest = msg.split(":", 1)
                password = rest.split()[0]
        except ValueError:
            pass
        return domain, user, password

    def _print_suggested_commands(self, target: str, successes: list[tuple[str, str]], is_dc: bool, hostname: str = ""):
        """Print suggested follow-up commands based on successful protocols."""
        seen_protocols: set[str] = set()
        command_blocks: list[tuple[str, list[tuple[str, str]]]] = []

        for label, msg in successes:
            proto = label.split()[0].lower()
            if proto in seen_protocols:
                continue
            seen_protocols.add(proto)

            domain, user, password = self._parse_credentials(msg)
            fmt = dict(ip=target, user=user, password=password, domain=domain,
                       hash=self.hash_val or "<NTLM_HASH>",
                       hostname=hostname or target)

            entries: list[tuple[str, str]] = []

            if is_dc and proto in DC_COMMAND_TEMPLATES:
                for sub_label, template in DC_COMMAND_TEMPLATES[proto]:
                    entries.append((sub_label, template.format(**fmt)))
                if self.hash_val and proto in DC_HASH_TEMPLATES:
                    for sub_label, template in DC_HASH_TEMPLATES[proto]:
                        entries.append((f"{sub_label} [hash]", template.format(**fmt)))
            else:
                if proto in COMMAND_TEMPLATES:
                    entries.append(("", COMMAND_TEMPLATES[proto].format(**fmt)))
                if proto in HASH_TEMPLATES:
                    hash_cmd = HASH_TEMPLATES[proto].format(**fmt)
                    entries.append(("[hash]", hash_cmd))

            if entries:
                command_blocks.append((label.split()[0], entries))

        if not command_blocks:
            return

        dc_tag = f" {YELLOW}[DC]{RESET}" if is_dc else ""
        print(f"\n  {CYAN}{BOLD}💡 Suggested Commands{RESET}{dc_tag}")
        print(f"  {'─' * (BANNER_WIDTH - 2)}")

        for proto_label, entries in command_blocks:
            if len(entries) == 1:
                sub_label, cmd = entries[0]
                tag = f" {DIM}({sub_label}){RESET}" if sub_label else ""
                print(f"    {GREEN}►{RESET} {BOLD}[{proto_label}]{RESET}{tag} {cmd}")
            else:
                print(f"    {GREEN}►{RESET} {BOLD}[{proto_label}]{RESET}")
                for sub_label, cmd in entries:
                    tag = f"{DIM}({sub_label}){RESET} " if sub_label else ""
                    print(f"        {DIM}│{RESET} {tag}{cmd}")
        print()

    def _print_scan_banner(self, total_attempts: int):
        print(f"\n{BOLD}{'═' * BANNER_WIDTH}{RESET}")
        print(f"  {CYAN}{BOLD}⚡ NetExec Automator{RESET}")
        print(f"{'═' * BANNER_WIDTH}")
        print(f"  Targets Count   {DIM}│{RESET} {BOLD}{len(self.targets):<11}{RESET} Protocols {DIM}│{RESET} {BOLD}{len(ALL_PROTOCOLS)}{RESET} (+ local auth)")
        print(f"  Users Count     {DIM}│{RESET} {BOLD}{len(self.users):<11}{RESET} Workers   {DIM}│{RESET} {BOLD}{self.workers}{RESET}")
        print(f"  Passwords Count {DIM}│{RESET} {BOLD}{len(self.passwords):<11}{RESET} Timeout   {DIM}│{RESET} {BOLD}30s{RESET}/attempt")
        print(f"  Pairing Mode    {DIM}│{RESET} {BOLD}{self.mode.upper():<11}{RESET} Log File  {DIM}│{RESET} {BOLD}{self.log_file}{RESET}")
        if self.hash_val:
            print(f"  Hash (PtH)      {DIM}│{RESET} {BOLD}{self.hash_val}{RESET}")
        print(f"  Total Tasks     {DIM}│{RESET} {BOLD}{total_attempts}{RESET}")
        print(f"{'═' * BANNER_WIDTH}\n")

    def _collect_target_results(self, target: str, tasks: list[TaskKey], pair_count: int) -> dict[TaskKey, list[str]]:
        self.completed = 0
        self.total_tasks = len(tasks) * pair_count
        self.scan_start_time = time.time()
        results: dict[TaskKey, list[str]] = {}

        with ThreadPoolExecutor(max_workers=self.workers) as pool:
            futures: dict = {}
            for protocol, local_auth in tasks:
                fut = pool.submit(self._run_protocol_task, protocol, target, local_auth)
                futures[fut] = (protocol, local_auth)

            for future in as_completed(futures):
                key = futures[future]
                try:
                    results[key] = future.result()
                except Exception as exc:
                    results[key] = [f"[!] Error: {exc}"]
        return results

    def _print_target_results(
        self,
        target: str,
        results: dict[TaskKey, list[str]],
        tasks: list[TaskKey],
        anon_smb_results: list[str],
        elapsed: float = 0.0,
    ) -> tuple[list[tuple[str, str]], bool, str, str]:
        """Print per-target results. Returns (successes, is_dc, hostname, real_ip)."""
        target_info = self._extract_target_info(results)
        is_dc = self._is_domain_controller(target_info)
        real_ip = self._extract_real_ip(results, anon_smb_results) or target
        hostname = ""
        if target_info:
            m = re.search(r"name:([^\s)]+)", target_info, re.IGNORECASE)
            if m:
                hostname = m.group(1).upper()

        print(f"\n{'─' * BANNER_WIDTH}")
        dc_label = f" {YELLOW}{BOLD}[Domain Controller]{RESET}" if is_dc else ""
        ip_label = f" {DIM}({real_ip}){RESET}" if real_ip != target else ""
        elapsed_label = f" {DIM}[{elapsed:.1f}s]{RESET}" if elapsed > 0 else ""
        print(f"  {CYAN}{BOLD}📋 NetExec Automator Results{RESET}{ip_label}{dc_label}{elapsed_label}")
        print(f"{'─' * BANNER_WIDTH}")

        if target_info and not self.quiet:
            print(f"    {DIM}{target_info}{RESET}")
        print()

        successes: list[tuple[str, str]] = []
        no_output_protos: set[str] = set()

        # ── Anonymous SMB block ──────────────────────────────────────
        if anon_smb_results:
            anon_parsed = self._parse_status_blocks(anon_smb_results)
            if anon_parsed:
                anon_icon = self._status_icon(anon_parsed)
                label = "SMB (anon)"
                for i, (marker, msg) in enumerate(anon_parsed):
                    prefix = (
                        f"  {anon_icon} {BOLD}{label:<20}{RESET}" if i == 0
                        else f"      {'':<20}"
                    )
                    if marker == "[+]":
                        print(f"{prefix} {YELLOW}{msg}{RESET}")
                        successes.append((label, msg))
                    elif marker == "[-]" and not self.quiet:
                        print(f"{prefix} {DIM}{msg}{RESET}")
                    elif marker == "[!]":
                        print(f"{prefix} {YELLOW}{msg}{RESET}")

        # ── Credentialled results ────────────────────────────────────
        for protocol, local_auth in tasks:
            key = (protocol, local_auth)
            label = self._task_label(protocol, local_auth)
            blocks = results.get(key, [])

            if not blocks:
                no_output_protos.add(protocol.upper())
                continue

            parsed = self._parse_status_blocks(blocks)

            if not parsed:
                no_output_protos.add(protocol.upper())
                continue

            icon = self._status_icon(parsed)

            for i, (marker, msg) in enumerate(parsed):
                if i == 0:
                    prefix = f"  {icon} {BOLD}{label:<20}{RESET}"
                else:
                    prefix = f"      {'':<20}"

                if marker == "[+]":
                    print(f"{prefix} {GREEN}{msg}{RESET}")
                    successes.append((label, msg))
                elif marker == "[-]" and not self.quiet:
                    print(f"{prefix} {DIM}{msg}{RESET}")
                elif marker == "[!]":
                    print(f"{prefix} {YELLOW}{msg}{RESET}")

        if no_output_protos and not self.quiet:
            ordered = [p for p in ALL_PROTOCOLS if p.upper() in no_output_protos]
            names = ", ".join(p.upper() for p in ordered)
            print(f"\n  {DIM}── No response: {names}{RESET}")

        print(f"\n{'─' * BANNER_WIDTH}")

        if successes:
            print(f"\n  {GREEN}{BOLD}✓ VALID CREDENTIALS{RESET}\n")
            for label, msg in successes:
                color = YELLOW if "(anon)" in label else GREEN
                print(f"    {color}►{RESET} {BOLD}{label:<20}{RESET} {DIM}│{RESET} {msg}")
            print()
            # Only suggest commands for credentialled successes (not anon)
            cred_successes = [(l, m) for l, m in successes if "(anon)" not in l]
            if cred_successes:
                self._print_suggested_commands(real_ip, cred_successes, is_dc, hostname)
        elif not self.quiet:
            print(f"\n  {RED}{BOLD}✗ No valid credentials found.{RESET}\n")

        print(f"{'═' * BANNER_WIDTH}\n")
        return successes, is_dc, hostname, real_ip

    def _print_summary_table(self, summary: list[dict]):
        """Print a rollup table after scanning multiple targets."""
        total_success = sum(1 for s in summary if s["successes"])
        print(f"\n{BOLD}{'═' * BANNER_WIDTH}{RESET}")
        print(f"  {CYAN}{BOLD}📊 Scan Summary{RESET}  {DIM}({len(summary)} targets){RESET}")
        print(f"{'═' * BANNER_WIDTH}")
        for entry in summary:
            has_creds = bool(entry["successes"])
            icon = f"{GREEN}✔{RESET}" if has_creds else f"{RED}✘{RESET}"
            host_label = entry["target"]
            if entry["hostname"]:
                host_label += f" {DIM}({entry['hostname']}){RESET}"
            if entry["is_dc"]:
                host_label += f" {YELLOW}[DC]{RESET}"
            time_label = f" {DIM}[{entry['elapsed']:.1f}s]{RESET}"
            cred_count = len(entry["successes"])
            cred_label = f" {GREEN}{cred_count} cred{'s' if cred_count != 1 else ''}{RESET}" if has_creds else ""
            print(f"  {icon} {host_label}{cred_label}{time_label}")
        print(f"\n  Total: {GREEN}{BOLD}{total_success}{RESET}/{len(summary)} targets with valid credentials")
        print(f"{'═' * BANNER_WIDTH}\n")

    def _write_json_output(self, summary: list[dict]):
        """Write scan findings to a JSON file."""
        output = {
            "scan_time": datetime.now().isoformat(),
            "log_file": self.log_file,
            "targets": [
                {
                    "target": entry["target"],
                    "real_ip": entry["real_ip"],
                    "hostname": entry["hostname"],
                    "is_dc": entry["is_dc"],
                    "elapsed_seconds": round(entry["elapsed"], 2),
                    "successes": [
                        {"protocol": label, "credential": msg}
                        for label, msg in entry["successes"]
                    ],
                }
                for entry in summary
            ],
        }
        with open(self.json_output, "w") as f:
            json.dump(output, f, indent=2)
        print(f"  {DIM}JSON output written to {self.json_output}{RESET}\n")

    def run(self):
        task_count = len(ALL_PROTOCOLS) + len(LOCAL_AUTH_PROTOCOLS)
        pair_count = len(self.credential_pairs)
        total_attempts = len(self.targets) * pair_count * task_count

        if not self.quiet:
            self._print_scan_banner(total_attempts)

        summary: list[dict] = []

        for target in self.targets:
            print(f"  {GREEN}{BOLD}► {target}{RESET}\n")

            tasks = self._build_protocol_tasks()
            target_start = time.time()

            # Run anonymous SMB check and credentialled scans concurrently
            anon_smb_results: list[str] = []
            with ThreadPoolExecutor(max_workers=2) as outer:
                anon_future = outer.submit(self._run_anon_smb, target)
                cred_future = outer.submit(self._collect_target_results, target, tasks, pair_count)
                anon_smb_results = anon_future.result()
                results = cred_future.result()

            elapsed = time.time() - target_start

            sys.stderr.write("\r" + " " * PROGRESS_CLEAR_WIDTH + "\r")
            sys.stderr.flush()

            successes, is_dc, hostname, real_ip = self._print_target_results(
                target, results, tasks, anon_smb_results, elapsed
            )

            summary.append({
                "target": target,
                "real_ip": real_ip,
                "hostname": hostname,
                "is_dc": is_dc,
                "elapsed": elapsed,
                "successes": successes,
            })

        if len(self.targets) > 1:
            self._print_summary_table(summary)

        if self.json_output:
            self._write_json_output(summary)


def parse_mode(value: str) -> str:
    """Validate accepted mode values."""
    mode = value.lower()
    if mode in ("combination", "linear"):
        return mode
    raise argparse.ArgumentTypeError("Mode must be one of: combination, linear")


def parse_args():
    parser = argparse.ArgumentParser(
        description="Run nxc across all protocols with combination or linear credential pairing.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
examples:
  # Basic usage with credentials
  netexec-automator -t 192.168.1.10 -u admin -p 'Password123'

  # Spray credentials across a target list
  netexec-automator -t targets.txt -u users.txt -p passwords.txt

  # Supply an NTLM hash for pass-the-hash command suggestions
  netexec-automator -t 192.168.1.10 -u administrator -p '' -H aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0

  # Linear mode (pairs users[0]:passwords[0], users[1]:passwords[1], ...)
  netexec-automator -t targets.txt -u users.txt -p passwords.txt -m linear

  # Quiet mode — suppress banner and negative results, show findings only
  netexec-automator -t 192.168.1.10 -u admin -p 'Password123' -q

  # Disable color for piped/logged output
  netexec-automator -t 192.168.1.10 -u admin -p 'Password123' --no-color | tee scan.txt

  # Write findings to a JSON file
  netexec-automator -t targets.txt -u users.txt -p passwords.txt --json-output results.json
        """
    )
    parser.add_argument("-t", "--target",   required=True,
                        help="Target IP/hostname or path to targets file")
    parser.add_argument("-u", "--user",     required=True,
                        help="Username or path to users file")
    parser.add_argument("-p", "--password", required=True,
                        help="Password or path to passwords file")
    parser.add_argument("-H", "--hash",
                        help="NTLM hash (LM:NT or :NT) — used to populate pass-the-hash "
                             "command suggestions in output (e.g. -H aad3b...:31d6c...)")
    parser.add_argument("-o", "--output",
                        help="Custom log file path (default: YYYY-MM-DD_HH-MM-SS.txt)")
    parser.add_argument("-w", "--workers",  type=int, default=DEFAULT_WORKERS,
                        help=f"Number of parallel threads (default: {DEFAULT_WORKERS})")
    parser.add_argument(
        "-m", "--mode",
        type=parse_mode,
        default="combination",
        metavar="{combination,linear}",
        help="Credential pairing mode: combination (cartesian product, default) "
             "or linear (index-matched pairs)",
    )
    parser.add_argument("-q", "--quiet",    action="store_true",
                        help="Suppress banner and negative results; show findings only")
    parser.add_argument("--no-color",       action="store_true",
                        help="Disable ANSI color codes (auto-detected for non-TTY output)")
    parser.add_argument("--json-output",    metavar="FILE",
                        help="Write findings to a JSON file at the given path")
    return parser.parse_args()


def main():
    args = parse_args()
    _configure_colors(args.no_color)
    try:
        runner = NxcAutomator(
            target=args.target,
            user=args.user,
            password=args.password,
            hash_val=args.hash,
            output=args.output,
            workers=args.workers,
            mode=args.mode,
            quiet=args.quiet,
            json_output=args.json_output,
        )
        runner.run()
    except ValueError as exc:
        print(f"{RED}{BOLD}Error:{RESET} {exc}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
