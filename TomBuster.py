#!/usr/bin/env python3
"""tombuster — minimal nmap automation for single-host recon (OSCP).

Three scans, run exactly as you would by hand, output left clean:

    1. nmap -p- <target>                     full TCP port sweep
    2. nmap -A [--script vuln] -p<ports>      service/version + vuln on open ports
    3. nmap -sU --top-ports N <target>        UDP, in parallel with 1 & 2

UDP runs in the background captured to a file, then its report is printed
after the TCP scans so the three outputs never interleave. Afterwards
tombuster prints OSCP follow-ups: credential-attackable services point at
`tomsploit`; everything else gets concrete commands. Detected version banners
are surfaced with ready `searchsploit` queries so the version→exploit check
isn't buried in the -A output.

Run it with sudo (UDP and the SYN sweep both want root).
"""

import argparse
import atexit
import ipaddress
import os
import re
import shutil
import signal
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

# ─── Colors ────────────────────────────────────────────────────────────
RED = GREEN = YELLOW = BLUE = CYAN = MAGENTA = BOLD = DIM = RESET = ""
_CODES = {"RED": "\033[91m", "GREEN": "\033[92m", "YELLOW": "\033[93m",
          "BLUE": "\033[94m", "CYAN": "\033[96m", "MAGENTA": "\033[95m",
          "BOLD": "\033[1m", "DIM": "\033[2m", "RESET": "\033[0m"}


def configure_colors(no_color: bool) -> None:
    if no_color or not sys.stdout.isatty():
        return
    for name, code in _CODES.items():
        globals()[name] = code


W = 60  # banner width


# ─── Data ──────────────────────────────────────────────────────────────

@dataclass
class OpenPort:
    proto: str          # "tcp" or "udp"
    port: int
    service: str = "unknown"
    state: str = "open"


@dataclass
class Results:
    target: str
    outdir: Path
    tcp: list[OpenPort] = field(default_factory=list)
    udp: list[OpenPort] = field(default_factory=list)


# ─── nmap runners ──────────────────────────────────────────────────────

def run_live(args: list[str]) -> int:
    """Run nmap with stdout/stderr inheriting the terminal — output looks
    exactly like running nmap by hand."""
    return subprocess.run(args).returncode


def start_background(args: list[str]) -> subprocess.Popen | None:
    """Kick off a scan whose output we DON'T want interleaved (UDP). It
    writes its files via -oA; terminal streams are discarded and the saved
    report is printed later."""
    try:
        return subprocess.Popen(args, stdout=subprocess.DEVNULL,
                                stderr=subprocess.DEVNULL)
    except OSError:
        return None


# ─── gnmap parsing ─────────────────────────────────────────────────────

def parse_gnmap(path: Path) -> list[OpenPort]:
    """Pull open/open|filtered ports out of an nmap .gnmap file."""
    if not path.exists():
        return []
    out: list[OpenPort] = []
    seen: set[tuple[str, int]] = set()
    for line in path.read_text(errors="replace").splitlines():
        if "Ports:" not in line:
            continue
        for m in re.finditer(r"(\d+)/(open(?:\|filtered)?)/(\w+)//([^/]*)/", line):
            port, state, proto, svc = (int(m.group(1)), m.group(2),
                                       m.group(3), m.group(4) or "unknown")
            if (proto, port) in seen:
                continue
            seen.add((proto, port))
            out.append(OpenPort(proto=proto, port=port, service=svc, state=state))
    return sorted(out, key=lambda p: p.port)


def merge_services(base: list[OpenPort], detail: list[OpenPort]) -> list[OpenPort]:
    """Prefer the richer service names from the -A pass where available."""
    by_port = {p.port: p.service for p in detail if p.service not in ("", "unknown")}
    for p in base:
        if p.port in by_port:
            p.service = by_port[p.port]
    return base


# ─── subnet sweep (discovery → live hosts) ─────────────────────────────

# Common OSCP-relevant TCP ports for discovery + the stage-2 scan. Windows
# hosts usually block ICMP but answer 445/135/3389, so TCP-SYN discovery on
# these beats a plain ping sweep.
SWEEP_PORTS = ("21,22,25,53,80,110,111,135,139,143,389,443,445,"
               "1433,3306,3389,5985,8080")


def _ip_key(host: str):
    """Numeric IP sort (so .100 sorts after .14, not before)."""
    try:
        return (0, int(ipaddress.ip_address(host)))
    except ValueError:
        return (1, host)


def parse_live_hosts(path: Path) -> list[str]:
    """Hosts that answered discovery ('Status: Up') in an nmap -sn .gnmap,
    numerically sorted and de-duplicated."""
    if not path.exists():
        return []
    hosts: set[str] = set()
    for line in path.read_text(errors="replace").splitlines():
        m = re.match(r"Host:\s+(\S+).*Status:\s+Up", line)
        if m:
            hosts.add(m.group(1))
    return sorted(hosts, key=_ip_key)


def parse_hosts_ports(path: Path) -> dict[str, list[OpenPort]]:
    """Map each host → its open TCP ports from an nmap -oG .gnmap (stage 2)."""
    result: dict[str, list[OpenPort]] = {}
    if not path.exists():
        return result
    for line in path.read_text(errors="replace").splitlines():
        if "Ports:" not in line:
            continue
        hm = re.match(r"Host:\s+(\S+)", line)
        if not hm:
            continue
        ports: list[OpenPort] = []
        for m in re.finditer(r"(\d+)/(open(?:\|filtered)?)/(\w+)//([^/]*)/", line):
            ports.append(OpenPort(proto=m.group(3), port=int(m.group(1)),
                                  service=m.group(4) or "unknown", state=m.group(2)))
        if ports:
            result[hm.group(1)] = sorted(ports, key=lambda p: p.port)
    return result


def run_sweep(cidr: str, outdir: Path) -> None:
    """Reliable subnet discovery: stage 1 finds live hosts with -sn (TCP-SYN to
    common ports + ICMP, NO --min-rate — that drops SYN-ACKs on laggy VPNs and
    gives inconsistent host counts); stage 2 port-scans ONLY the live hosts.
    Writes ./live_hosts.txt so `tomsploit -t live_hosts.txt` can consume it."""
    if os.geteuid() != 0:
        print(f"{YELLOW}⚠ Not root — -sn SYN/ICMP discovery needs raw sockets. "
              f"Re-run with sudo for accurate results.{RESET}\n")

    print(f"{GREEN}{BOLD}[*] Stage 1 — host discovery: "
          f"nmap -sn -PS{SWEEP_PORTS} {cidr}{RESET}\n")
    disc = outdir / "sweep-discovery.gnmap"
    run_live(["nmap", "-sn", "-PS" + SWEEP_PORTS, "-n", "-T4",
              "--max-retries", "2", "-oG", str(disc), cidr])
    live = parse_live_hosts(disc)

    lh = Path.cwd() / "live_hosts.txt"
    if not live:
        print(f"\n{RED}[-] No live hosts in {cidr}. On a laggy VPN, re-run "
              f"(packet loss varies) or widen the -PS port list.{RESET}\n")
        return
    lh.write_text("\n".join(live) + "\n")
    print(f"\n{GREEN}[+] {len(live)} live host(s) → {lh}{RESET}")
    for h in live:
        print(f"    {h}")
    print()

    print(f"{BLUE}{BOLD}[*] Stage 2 — ports on live hosts only: "
          f"nmap -p {SWEEP_PORTS} --open -iL {lh}{RESET}\n")
    pscan = outdir / "sweep-ports"
    run_live(["nmap", "-p", SWEEP_PORTS, "--open", "-T4", "-iL", str(lh),
              "-oG", f"{pscan}.gnmap", "-oN", f"{pscan}.nmap"])
    hp = parse_hosts_ports(Path(f"{pscan}.gnmap"))

    print(f"\n{CYAN}{'─' * W}{RESET}")
    print(f"{CYAN}{BOLD}  Sweep results — {cidr}{RESET}")
    print(f"{CYAN}{'─' * W}{RESET}")
    for h in live:
        ports = hp.get(h, [])
        if ports:
            summary = ", ".join(f"{p.port}/{p.service}" for p in ports)
            print(f"  {GREEN}{h:<16}{RESET} {summary}")
        else:
            print(f"  {DIM}{h:<16} (up — no open ports in the scanned set){RESET}")
    print()
    print(f"{DIM}Next:  deep-scan a host →  sudo tombuster -t <ip>{RESET}")
    print(f"{DIM}       triage creds     →  tomsploit -t {lh} --combo creds.txt{RESET}\n")


# ─── hostname hints (for web vhosts / /etc/hosts) ──────────────────────

def extract_hostnames(nmap_report: Path, target: str) -> list[str]:
    try:
        text = nmap_report.read_text(errors="replace")
    except OSError:
        return []
    names: set[str] = set()

    # High-confidence host/computer names — accept even SINGLE-LABEL ones (e.g.
    # the RDP cert CN 'nickel', or the NetBIOS/DNS computer name) so the box name
    # still reaches /etc/hosts when nmap never resolved a dotted FQDN.
    for pat in (
        r"Nmap scan report for ([A-Za-z0-9_.\-]+) \(",            # resolved PTR
        r"commonName=([A-Za-z0-9_.\-]+)",                         # TLS cert CN
        r"(?:DNS|NetBIOS)_Computer_Name:\s*([A-Za-z0-9_.\-]+)",   # rdp/smb ntlm-info
        r"Target_Name:\s*([A-Za-z0-9_.\-]+)",                     # rdp-ntlm-info
        r"NetBIOS computer name:\s*([A-Za-z0-9_.\-]+)",           # smb-os-discovery
    ):
        for m in re.finditer(pat, text, re.IGNORECASE):
            names.add(m.group(1).rstrip("."))

    # Lower-confidence sources that could otherwise grab junk: require a dot.
    for pat in (r"redirect to https?://([A-Za-z0-9_.\-]+)",       # http redirects
                r"DNS:([A-Za-z0-9_.\-]+)"):                       # TLS SAN
        for m in re.finditer(pat, text):
            n = m.group(1).rstrip(".")
            if "." in n:
                names.add(n)

    # Drop the target itself, bare IPs, and localhost (never put it in hosts).
    keep: set[str] = set()
    for n in names:
        nl = n.lower()
        if (not nl or nl == target.lower() or nl == "localhost"
                or re.fullmatch(r"\d+\.\d+\.\d+\.\d+", nl)):
            continue
        keep.add(nl)
    return sorted(keep)


def extract_domain(nmap_report: Path) -> str | None:
    """Pull the AD/DNS domain from nmap output if any script leaked it.

    nmap surfaces the domain several ways depending on which services were
    scanned: rdp-ntlm-info ('Target_Domain'/'DNS_Domain_Name'), the smb OS
    discovery line, ldap rootDSE ('defaultNamingContext: DC=dante,DC=local'),
    or a resolved DC hostname like 'dc01.dante.local'. Try each, most
    explicit first; return None if nothing is found so callers can fall back
    to a visible placeholder."""
    try:
        text = nmap_report.read_text(errors="replace")
    except OSError:
        return None

    # 1) Explicit NTLM-info / SMB fields (rdp-ntlm-info, smb2-*, smb-os-disc).
    for pat in (
        r"DNS_Domain_Name:\s*([A-Za-z0-9.\-]+)",
        r"Target_Domain:\s*([A-Za-z0-9.\-]+)",
        r"(?:Domain|Domain name):\s*([A-Za-z0-9.\-]+\.[A-Za-z0-9.\-]+)",
        r"FQDN:\s*[A-Za-z0-9\-]+\.([A-Za-z0-9.\-]+)",
    ):
        m = re.search(pat, text, re.IGNORECASE)
        if m:
            d = m.group(1).strip().rstrip(".")
            if "." in d and not re.fullmatch(r"\d+\.\d+\.\d+\.\d+", d):
                return d.lower()

    # 2) LDAP rootDSE naming context: DC=dante,DC=local -> dante.local
    m = re.search(r"(?:defaultNamingContext|rootDomainNamingContext)[^A-Za-z]*"
                  r"((?:DC=[A-Za-z0-9\-]+,?)+)", text, re.IGNORECASE)
    if not m:
        m = re.search(r"((?:DC=[A-Za-z0-9\-]+,){1,}DC=[A-Za-z0-9\-]+)", text,
                      re.IGNORECASE)
    if m:
        parts = re.findall(r"DC=([A-Za-z0-9\-]+)", m.group(1), re.IGNORECASE)
        if len(parts) >= 2:
            return ".".join(parts).lower()

    return None


def extract_versions(nmap_report: Path) -> list[tuple[int, str, str]]:
    """From the -A scan's .nmap output, pull (port, service, version banner)
    for each open TCP port that actually reported a version. nmap only prints
    a version column when it fingerprinted something, so ports with no banner
    (e.g. 'microsoft-ds?') are naturally skipped. Returns [] if the file is
    missing or nothing had a banner."""
    out: list[tuple[int, str, str]] = []
    try:
        text = nmap_report.read_text(errors="replace")
    except OSError:
        return out
    for line in text.splitlines():
        # e.g.  "80/tcp   open  http        Apache httpd 2.4.49 ((Unix))"
        m = re.match(r"^(\d+)/tcp\s+open\s+(\S+)\s+(.+?)\s*$", line)
        if not m:
            continue
        port, svc, ver = int(m.group(1)), m.group(2), m.group(3).strip()
        if ver and ver.lower() != "tcpwrapped":
            out.append((port, svc, ver))
    return sorted(out, key=lambda t: t[0])


def searchsploit_terms(version: str) -> str:
    """Best-effort search terms from a version banner: product name + first
    dotted version number, parentheticals and noise words dropped. It's a
    starting point you tweak by hand, not a guaranteed-good query."""
    v = re.sub(r"\([^)]*\)", " ", version)          # drop (...) / ((...))
    v = re.sub(r"\b(?:protocol|httpd|server|version|ver)\b", " ", v, flags=re.I)
    terms: list[str] = []
    for tok in v.split():
        terms.append(tok)
        if re.match(r"^\d+(?:\.\d+)+", tok):         # stop after first dotted version
            break
    return " ".join(terms[:4])


def render_versions(versions: list[tuple[int, str, str]]) -> None:
    print(f"\n  {BOLD}Versions → public exploits{RESET} "
          f"{DIM}(read the banner, then searchsploit){RESET}")
    print(f"  {DIM}{'─' * 40}{RESET}")
    for i, (port, svc, ver) in enumerate(versions):
        if i:
            print()
        print(f"        {BOLD}[{port}] {svc}{RESET}  {DIM}{ver}{RESET}")
        terms = searchsploit_terms(ver)
        if terms:
            print(f"        searchsploit {terms}")
    print(f"\n        {DIM}# tip: searchsploit -w <terms> for links · confirm the "
          f"exact build before trusting a match{RESET}")


def sync_etc_hosts(ip: str, names: list[str]) -> tuple[list[str], list[str]]:
    """Append 'ip name' lines to /etc/hosts for names not already present.
    Idempotent — re-runs add nothing. Returns (added, pending); `pending` is
    non-empty only when we lack root or the write failed, so the caller can
    print a manual command instead. Never raises."""
    names = list(dict.fromkeys(n for n in names if n))  # dedupe, keep order
    if not names:
        return [], []
    try:
        existing = Path("/etc/hosts").read_text(errors="replace")
    except OSError:
        return [], names
    present: set[str] = set()
    for ln in existing.splitlines():
        for tok in ln.split("#", 1)[0].split()[1:]:   # skip the IP, keep names
            present.add(tok.lower())
    to_add = [n for n in names if n.lower() not in present]
    if not to_add:
        return [], []
    if os.geteuid() != 0:
        return [], to_add
    try:
        with open("/etc/hosts", "a") as f:
            f.write(f"{ip}\t{' '.join(to_add)}\n")
        return to_add, []
    except OSError:
        return [], to_add


# ─── Suggestion engine ─────────────────────────────────────────────────
# Division of labour: anything credential-attackable is tomsploit's job, so
# tombuster only points there (one line, no duplication — tomsploit already
# does anonymous SMB/LDAP, cred spray, kerbrute, AS-REP, BloodHound, etc.).
# tombuster owns the services tomsploit doesn't touch.

# Ports tomsploit covers (nxc protocols) + the AD-infra ports that simply
# mean "this is a DC, go run tomsploit". These get NO standalone recipe.
TOMSPLOIT_PORTS: dict[int, str] = {
    88: "Kerberos", 135: "RPC/WMI", 139: "SMB", 389: "LDAP", 445: "SMB",
    464: "kpasswd", 636: "LDAPS", 1433: "MSSQL", 1434: "MSSQL-browser",
    3268: "GC", 3269: "GC-SSL", 3389: "RDP", 5900: "VNC",
    5985: "WinRM", 5986: "WinRM-SSL",
}

HTTPS_PORTS = {443, 8443, 4443, 9443, 10443}
HTTP_PORTS = {80, 8080, 8000, 8888, 8081, 8082, 5000, 3000, 9090}
HTTP_HINTS = ("http", "www", "web", "apache", "nginx", "iis", "tomcat",
              "jetty", "lighttpd", "gunicorn", "werkzeug", "node")


def web_scheme(port: int, service: str) -> str | None:
    """Return 'http'/'https' if the port looks like a web server, else None."""
    svc = service.lower()
    looks_web = (port in HTTPS_PORTS or port in HTTP_PORTS
                 or any(h in svc for h in HTTP_HINTS))
    if not looks_web:
        return None
    if port in HTTPS_PORTS or "https" in svc or ("ssl" in svc and "http" in svc):
        return "https"
    return "http"


# port -> (label, ((comment, command-or-note), ...))
# A command may contain newlines; a line beginning with '#' renders as a
# dim note rather than a command.
SERVICE_RECIPES: dict[int, tuple[str, tuple[tuple[str, str], ...]]] = {
    21: ("FTP", (
        ("anonymous login (classic quick win)",
            "ftp -A {ip}\n# user 'anonymous', any password"),
        ("mirror everything if anon works",
            "wget -m --no-passive ftp://anonymous:anonymous@{ip}/"),
        ("note",
            "# writable + served by a web root? upload a webshell"),
    )),
    22: ("SSH", (
        ("audit version & algos (look for a CVE)",
            "ssh-audit {ip}"),
        ("note",
            "# OpenSSH < 7.7 -> user enum CVE-2018-15473\n"
            "# have creds? run tomsploit (it sprays SSH too)"),
    )),
    23: ("Telnet", (
        ("connect / grab banner",
            "telnet {ip}\n# try device defaults (admin:admin, root:root) and any creds you already have"),
        ("encryption support + NTLM info",
            "nmap -p23 --script telnet-encryption,telnet-ntlm-info {ip}"),
        ("brute (with a user list)",
            "hydra -L users.txt -P /usr/share/wordlists/rockyou.txt {ip} telnet"),
    )),
    25: ("SMTP", (
        ("username enumeration (build a user list)",
            "smtp-user-enum -M RCPT -U /usr/share/seclists/Usernames/Names/names.txt "
            "-D {domain} -t {ip}"),
        ("commands / open-relay / NTLM info",
            "nmap -p25 --script smtp-commands,smtp-open-relay,smtp-ntlm-info {ip}"),
    )),
    53: ("DNS", (
        ("zone transfer (use the domain you discover)",
            "dig axfr {domain} @{ip}"),
        ("brute records / subdomains",
            "dnsenum --dnsserver {ip} {domain}"),
    )),
    110: ("POP3", (
        ("banner + manual login",
            "nc -nv {ip} 110\n# then:  USER <name>   PASS <password>   LIST   RETR 1"),
        ("capabilities + NTLM info",
            "nmap -p110 --script pop3-capabilities,pop3-ntlm-info {ip}"),
        ("brute (with a user list)",
            "hydra -L users.txt -P /usr/share/wordlists/rockyou.txt {ip} pop3"),
    )),
    143: ("IMAP", (
        ("banner + manual login",
            "nc -nv {ip} 143\n# then:  a LOGIN <name> <password>   a LIST \"\" *   a SELECT INBOX"),
        ("capabilities + NTLM info",
            "nmap -p143 --script imap-capabilities,imap-ntlm-info {ip}"),
        ("brute (with a user list)",
            "hydra -L users.txt -P /usr/share/wordlists/rockyou.txt {ip} imap"),
    )),
    993: ("IMAPS", (
        ("banner + manual login over TLS",
            "openssl s_client -connect {ip}:993 -quiet\n# then:  a LOGIN <name> <password>   a LIST \"\" *   a SELECT INBOX"),
        ("capabilities + NTLM info",
            "nmap -p993 --script imap-capabilities,imap-ntlm-info {ip}"),
        ("brute (with a user list)",
            "hydra -L users.txt -P /usr/share/wordlists/rockyou.txt {ip} imaps"),
    )),
    995: ("POP3S", (
        ("banner + manual login over TLS",
            "openssl s_client -connect {ip}:995 -quiet\n# then:  USER <name>   PASS <password>   LIST   RETR 1"),
        ("capabilities + NTLM info",
            "nmap -p995 --script pop3-capabilities,pop3-ntlm-info {ip}"),
        ("brute (with a user list)",
            "hydra -L users.txt -P /usr/share/wordlists/rockyou.txt {ip} pop3s"),
    )),
    161: ("SNMP (UDP)", (
        ("walk with the 'public' string",
            "snmpwalk -v2c -c public {ip}"),
        ("faster bulk walk",
            "snmpbulkwalk -v2c -c public {ip}"),
        ("structured summary",
            "snmp-check {ip}"),
        ("brute community strings",
            "onesixtyone -c /usr/share/seclists/Discovery/SNMP/common-snmp-community-strings.txt {ip}"),
        ("extended objects — commands SNMP runs (often as root → RCE)",
            "snmpwalk -v2c -c public {ip} NET-SNMP-EXTEND-MIB::nsExtendObjects"),
        ("note",
            "# juicy OIDs: users 1.3.6.1.4.1.77.1.2.25 · procs .25.4.2.1.2 · "
            "software .25.6.3.1.2"),
    )),
    3306: ("MySQL", (
        ("try blank / default root",
            "mysql -h {ip} -u root -p"),
        ("nmap info + empty-password check",
            "nmap -p3306 --script mysql-info,mysql-empty-password,mysql-databases {ip}"),
    )),
    5432: ("PostgreSQL", (
        ("try postgres:postgres",
            "psql 'host={ip} user=postgres password=postgres'"),
        ("note",
            "# inside: \\l (dbs) · \\du (roles) · COPY ... TO PROGRAM = RCE if superuser"),
    )),
    6379: ("Redis", (
        ("connect (often unauthenticated)",
            "redis-cli -h {ip}\n# then: INFO · CONFIG GET dir · KEYS *"),
        ("note",
            "# unauth -> write SSH key / webshell, or MODULE LOAD for RCE"),
    )),
    69: ("TFTP (UDP)", (
        ("enumerate filenames",
            "sudo nmap -sU -p69 --script tftp-enum {ip}"),
    )),
    111: ("rpcbind", (
        ("list RPC services",
            "rpcinfo -p {ip}"),
        ("note",
            "# NFS behind it? see the NFS block below for showmount / mount"),
    )),
    123: ("NTP (UDP)", (
        ("read variables / monlist",
            "ntpq -c readlist {ip}"),
    )),
    137: ("NetBIOS (UDP)", (
        ("name table",
            "nmblookup -A {ip}"),
    )),
    500: ("IKE / IPsec (UDP)", (
        ("fingerprint the VPN",
            "sudo ike-scan {ip}"),
        ("aggressive mode (may leak a PSK hash)",
            "sudo ike-scan -M -A {ip}"),
    )),
    623: ("IPMI (UDP)", (
        ("version + cipher-0 auth bypass",
            "sudo nmap -sU -p623 --script ipmi-version,ipmi-cipher-zero {ip}"),
        ("dump BMC password hashes",
            "msfconsole -q -x 'use auxiliary/scanner/ipmi/ipmi_dumphashes; "
            "set RHOSTS {ip}; run; exit'"),
    )),
    2049: ("NFS", (
        ("list exports",
            "showmount -e {ip}"),
        ("mount one read-only",
            "sudo mkdir -p /mnt/nfs && sudo mount -t nfs -o nolock,vers=3 "
            "{ip}:<EXPORT> /mnt/nfs"),
        ("note",
            "# no_root_squash? drop a SUID-root binary on the export and run it"),
    )),
    873: ("rsync", (
        ("list modules (often anonymous)",
            "rsync -av --list-only rsync://{ip}/"),
        ("pull a module's contents",
            "rsync -av rsync://{ip}/<module>/ ./loot/"),
        ("note",
            "# writable module -> drop into a served path / cron dir / authorized_keys"),
    )),
    1521: ("Oracle TNS", (
        ("enumerate SIDs",
            "nmap -p1521 --script oracle-sid-brute {ip}"),
        ("brute creds once you have a SID (odat)",
            "odat all -s {ip} -p 1521"),
        ("note",
            "# defaults: scott/tiger, system/manager, sys/change_on_install"),
    )),
    2375: ("Docker API", (
        ("instant root — mount the host fs in a container",
            "docker -H tcp://{ip}:2375 run -v /:/mnt -it alpine chroot /mnt sh"),
        ("look around first (confirm the API answers)",
            "docker -H tcp://{ip}:2375 ps\ndocker -H tcp://{ip}:2375 images"),
    )),
    11211: ("Memcached", (
        ("dump stats then items (unauth)",
            "memcstat --servers={ip}\n# or:  nc -nv {ip} 11211   then: stats / stats items"),
        ("note",
            "# walk keys -> 'get <key>' can leak sessions / creds"),
    )),
    27017: ("MongoDB", (
        ("connect (often no auth)",
            "mongosh mongodb://{ip}:27017\n"
            "# then: show dbs · use <db> · show collections · db.<c>.find()"),
        ("nmap info + database list",
            "nmap -p27017 --script mongodb-info,mongodb-databases {ip}"),
    )),
}


# ─── Rendering ─────────────────────────────────────────────────────────

def _print_entries(entries: tuple[tuple[str, str], ...], ip: str,
                   domain: str | None = None) -> None:
    # If a template references {domain} but none was discovered, show a clear
    # placeholder so the command is obviously "fill this in" rather than blank.
    dom = domain or "<domain>"
    first = True
    starred = False
    for comment, body in entries:
        body = body.format(ip=ip, domain=dom) if body else ""
        if not first:
            print()
        first = False
        if comment != "note":
            if not starred:
                print(f"        {YELLOW}# ★ {comment}{RESET}")
                starred = True
            else:
                print(f"        {DIM}# {comment}{RESET}")
        for ln in body.split("\n"):
            ln = ln.rstrip()
            if not ln:
                continue
            if ln.lstrip().startswith("#"):
                print(f"        {DIM}{ln}{RESET}")
            else:
                print(f"        {ln}")


def render_tomsploit_block(target: str, ports: list[int],
                           domain: str | None = None) -> None:
    labels = sorted({TOMSPLOIT_PORTS[p] for p in ports})
    print(f"\n  {BOLD}Credential / AD services{RESET} "
          f"{DIM}({', '.join(labels)}){RESET}")
    print(f"  {DIM}{'─' * 40}{RESET}")
    print(f"        {DIM}# tomsploit handles these end-to-end — anonymous SMB/LDAP,{RESET}")
    print(f"        {DIM}# credential spray, and the per-service follow-ups (incl.{RESET}")
    print(f"        {DIM}# kerbrute / AS-REP / BloodHound once it flags a DC).{RESET}")
    print(f"        {DIM}# Don't manually enumerate or spray these here.{RESET}")
    print()
    print(f"        tomsploit -t {target} -u users.txt -p passwords.txt")
    if domain:
        print(f"        {DIM}# domain {domain} detected — once you have a cred, "
              f"e.g. AS-REP roast with no password:{RESET}")
        print(f"        impacket-GetNPUsers {domain}/ -dc-ip {target} "
              f"-request -format hashcat -outputfile asrep.hash")


_WL_VARIATIONS = ("{b}", "{b}-admin", "{b}-dev", "{b}-test", "{b}-api",
                  "{b}-portal", "{b}-backup", "{b}_backup", "dev-{b}")
_WL_GENERIC = ("dev", "backup", "backups", "uploads", "private",
               "internal", "old", "api", "portal", "app")


def _wordlist_bases(target: str, hostnames: list[str],
                    domain: str | None) -> list[str]:
    """Short base names (box/app names) from discovered hostnames + AD domain.
    'lezram.lab' and 'lezram.local' both reduce to 'lezram'."""
    bases: list[str] = []
    seen: set[str] = set()
    sources = list(hostnames) + ([domain] if domain else [])
    for name in sources:
        name = (name or "").strip().lower().rstrip(".")
        if not name:
            continue
        for cand in (name.split(".")[0], name):
            if not cand or cand.replace(".", "").isdigit():
                continue          # skip IPs / pure numbers
            if cand not in seen:
                seen.add(cand)
                bases.append(cand)
    return bases


def build_custom_wordlist(target: str, hostnames: list[str],
                          domain: str | None) -> list[str]:
    """Box/app-name directory guesses raft won't contain: each base name plus
    common variations, then a few generic dirs as a floor."""
    words: list[str] = []
    seen: set[str] = set()

    def add(w: str) -> None:
        if w and w not in seen:
            seen.add(w)
            words.append(w)

    for b in _wordlist_bases(target, hostnames, domain):
        for pat in _WL_VARIATIONS:
            add(pat.format(b=b))
    for g in _WL_GENERIC:
        add(g)
    return words


def write_custom_wordlist(words: list[str], path: Path) -> "Path | None":
    """Write guesses to `path`. If it already exists, MERGE (keep the user's
    own additions) instead of clobbering, so re-running tombuster is additive."""
    try:
        existing: list[str] = []
        if path.exists():
            existing = [ln.strip() for ln
                        in path.read_text(errors="replace").splitlines()
                        if ln.strip()]
        merged: list[str] = []
        seen: set[str] = set()
        for w in existing + words:
            if w not in seen:
                seen.add(w)
                merged.append(w)
        path.write_text("\n".join(merged) + "\n")
        return path
    except OSError:
        return None


def infer_web_extensions(service: str) -> str:
    """Pick feroxbuster -x extensions from the server banner. IIS → asp/aspx,
    Tomcat/Java → jsp, Apache/nginx → php; framework servers (Python/Node/.NET
    Core) get no server-side extension. Unknown → PHP, the most common default."""
    s = (service or "").lower()
    static = "html,txt"
    if "iis" in s or "asp.net" in s:
        return f"asp,aspx,{static}"
    if any(j in s for j in ("tomcat", "coyote", "jetty", "jboss", "jsp")):
        return f"jsp,{static}"
    if "php" in s:
        return f"php,{static}"
    if any(fw in s for fw in ("werkzeug", "gunicorn", "flask", "django",
                              "python", "node", "express", "kestrel")):
        return static                       # routes, not files
    if any(w in s for w in ("apache", "nginx", "lighttpd", "httpd")):
        return f"php,{static}"              # usual LAMP/LEMP pairing
    return f"php,{static}"                  # unknown → PHP is the safe bet


def is_http_api(service: str) -> bool:
    """True for a raw HTTP API listener (Microsoft-HTTPAPI / http.sys) rather
    than a normal website — content discovery rarely helps; verb/endpoint
    probing does."""
    s = (service or "").lower()
    return "httpapi" in s or "http.sys" in s


def render_web_block(target: str, web: list[OpenPort], hostnames: list[str],
                     domain: str | None = None) -> None:
    ports = ", ".join(str(p.port) for p in web)
    print(f"\n  {BOLD}Web{RESET} {DIM}(ports: {ports}){RESET}")
    print(f"  {DIM}{'─' * 40}{RESET}")

    # Seed a small per-box wordlist of box/app-name guesses (raft lacks these)
    # and drop it in the CWD so the recipe can reference '-w custom.txt' and
    # feroxbuster, run from here, finds it. Merges on re-run (keeps your adds).
    words = build_custom_wordlist(target, hostnames, domain)
    wl_path = write_custom_wordlist(words, Path.cwd() / "custom.txt")
    wl_flag = "-w custom.txt " if wl_path else ""

    for p in web:
        scheme = web_scheme(p.port, p.service) or "http"
        url = (f"{scheme}://{target}" if p.port in (80, 443)
               else f"{scheme}://{target}:{p.port}")
        k = " -k" if scheme == "https" else ""
        exts = infer_web_extensions(p.service)
        ferox = (f"feroxbuster -u {url} "
                 f"-w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt "
                 f"{wl_flag}-x {exts}{k}")
        print(f"        {DIM}# [{p.port}] fingerprint{RESET}")
        print(f"        whatweb -a3 {url}")
        print()
        if is_http_api(p.service):
            # Microsoft-HTTPAPI / http.sys is a raw API, not a website. Dir-busting
            # is usually empty (it was on Nickel); the win is reading another app's
            # source for endpoint names, then probing verbs/headers.
            print(f"        {YELLOW}# ★ [{p.port}] Microsoft-HTTPAPI = a raw HTTP API "
                  f"(http.sys), not a website{RESET}")
            print(f"        {DIM}#   dir-busting usually finds nothing here. Read another "
                  f"web app's source for{RESET}")
            print(f"        {DIM}#   endpoint names, then probe each — swap the verb and add "
                  f"headers it rejects:{RESET}")
            print(f"        curl -i {url}/<endpoint>                        # GET (often: use POST)")
            print(f"        curl -i {url}/<endpoint> -X POST -H 'Content-Length: 0'   # 411? add length")
            print(f"        {DIM}#   200 / 411 / 400 back = right path; the right verb+header "
                  f"dumps the data{RESET}")
            print(f"        {DIM}# dir-bust anyway (low odds on httpapi):{RESET}")
            print(f"        {ferox}")
        else:
            print(f"        {YELLOW}# ★ [{p.port}] content discovery{RESET}")
            print(f"        {ferox}")
            print()
            print(f"        {DIM}# [{p.port}] known-issue scan{RESET}")
            print(f"        nikto -h {url}{k}")
        print()
    if len(web) >= 2:
        print(f"        {YELLOW}# ★ 2+ web services — check whether one references "
              f"the other{RESET}")
        print(f"        {DIM}#   read each app's source for a hardcoded host/port; an "
              f"APIPA 169.254.x.x (or a{RESET}")
        print(f"        {DIM}#   wrong IP) means broken DHCP — swap in the target IP / "
              f"127.0.0.1 and re-request{RESET}")
    if wl_path:
        bases = _wordlist_bases(target, hostnames, domain)
        if bases:
            print(f"        {GREEN}# + wrote ./custom.txt (box-name guesses from "
                  f"'{bases[0]}') — add any names you learn & re-run{RESET}")
        else:
            print(f"        {DIM}# wrote ./custom.txt (no hostname in scan; generic "
                  f"dirs only — add the box name to it & re-run){RESET}")
    print(f"        {DIM}# always do first: / , view-source, robots.txt, "
          f"/sitemap.xml, login pages (default creds){RESET}")
    print(f"        {DIM}# vhost fuzz: ffuf -u {('https' if any(web_scheme(p.port,p.service)=='https' for p in web) else 'http')}://{target} "
          f"-H 'Host: FUZZ.{domain or '<domain>'}' \\{RESET}")
    print(f"        {DIM}#   -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -fs <baseline-size>{RESET}")


def render_recipe(p: OpenPort, ip: str, domain: str | None = None) -> None:
    label, entries = SERVICE_RECIPES[p.port]
    state = f" {DIM}({p.state}){RESET}" if p.state != "open" else ""
    tag = f"/{p.proto}" if p.proto == "udp" else ""
    print(f"\n  {BOLD}[{p.port}{tag}] {label}{RESET}{state}")
    print(f"  {DIM}{'─' * 40}{RESET}")
    _print_entries(entries, ip, domain)


def print_next_steps(results: Results) -> None:
    target = results.target
    all_ports = results.tcp + results.udp
    if not all_ports:
        return

    tomsploit_open = [p.port for p in all_ports if p.port in TOMSPLOIT_PORTS]
    web = [p for p in results.tcp
           if p.port not in TOMSPLOIT_PORTS and web_scheme(p.port, p.service)]
    web_ports = {p.port for p in web}
    recipe_ports = [p for p in all_ports
                    if p.port not in TOMSPLOIT_PORTS
                    and p.port not in web_ports
                    and p.port in SERVICE_RECIPES]
    leftover = [p for p in all_ports
                if p.port not in TOMSPLOIT_PORTS
                and p.port not in web_ports
                and p.port not in SERVICE_RECIPES]

    hostnames = extract_hostnames(results.outdir / "tcp-detail.nmap", target)
    # Pull the AD/DNS domain from the detailed scan (and the base scan as a
    # fallback) so the suggested commands come pre-filled instead of leaving
    # <domain> for you to swap in by hand.
    domain = (extract_domain(results.outdir / "tcp-detail.nmap")
              or extract_domain(results.outdir / "tcp-all.nmap")
              or extract_domain(results.outdir / "udp.nmap"))
    versions = extract_versions(results.outdir / "tcp-detail.nmap")

    if not (tomsploit_open or web or recipe_ports or leftover or hostnames
            or versions):
        return

    print(f"\n{'═' * W}")
    print(f"  {CYAN}{BOLD}🎯 Next Steps{RESET}")
    print(f"{'═' * W}")
    if domain:
        print(f"  {DIM}domain detected: {RESET}{BOLD}{domain}{RESET} "
              f"{DIM}(filled into the commands below){RESET}")

    # /etc/hosts: auto-append the names we found (AD domain + any vhost / TLS
    # names) so web vhost routing and AD tooling resolve without a manual step.
    host_names = sorted(set(hostnames) | ({domain} if domain else set()))
    if host_names:
        added, pending = sync_etc_hosts(target, host_names)
        if added or pending:
            print(f"\n  {BOLD}Hosts file{RESET} {DIM}(/etc/hosts){RESET}")
            print(f"  {DIM}{'─' * 40}{RESET}")
            if added:
                print(f"        {GREEN}[+] appended:{RESET} {target}  "
                      f"{' '.join(added)}")
            if pending:
                print(f"        {DIM}# not root (or write failed) — add manually:{RESET}")
                print(f"        echo '{target}  {' '.join(pending)}' "
                      f"| sudo tee -a /etc/hosts")

    if versions:
        render_versions(versions)
    if tomsploit_open:
        render_tomsploit_block(target, tomsploit_open, domain)
    if web:
        render_web_block(target, web, hostnames, domain)
    for p in recipe_ports:
        render_recipe(p, target, domain)
    if leftover:
        names = ", ".join(f"{p.port}/{p.service}" for p in leftover)
        print(f"\n  {BOLD}Other open ports{RESET}")
        print(f"  {DIM}{'─' * 40}{RESET}")
        print(f"        {DIM}# no canned recipe — read the -A output: {names}{RESET}")

    print(f"\n  {BOLD}Output{RESET}")
    print(f"  {DIM}{'─' * 40}{RESET}")
    print(f"        {DIM}Scan files:{RESET}  {results.outdir}")
    print(f"\n{'═' * W}\n")


# ─── CLI / main ────────────────────────────────────────────────────────

def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="tombuster",
        description="Minimal nmap automation: TCP -p- → -A --script vuln, "
                    "UDP in parallel. Run with sudo.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""examples:
  sudo tombuster -t 10.10.10.50
  sudo tombuster -t target.htb --skip-udp
  sudo tombuster -t 10.10.10.50 --udp-top 50
  sudo tombuster -t 10.10.10.50 --skip-vuln -o ./recon/box1
  sudo tombuster --sweep 10.10.196.0/24
""",
    )
    p.add_argument("-t", "--target", help="Single IP or hostname (deep scan).")
    p.add_argument("--sweep", metavar="CIDR",
                   help="Subnet discovery: find live hosts in a CIDR (two-stage, "
                        "no --min-rate) and write ./live_hosts.txt. "
                        "e.g. --sweep 10.10.196.0/24")
    p.add_argument("--keep", action="store_true",
                   help="Keep the nmap output dir (named after the target). "
                        "Default: scan in a temp dir and delete it on exit.")
    p.add_argument("-o", "--output-dir",
                   help="Output directory (default: ./<target>/).")
    p.add_argument("--udp-top", type=int, default=200, metavar="N",
                   help="UDP --top-ports (default: 200).")
    p.add_argument("--udp-min-rate", type=int, default=1000, metavar="N",
                   help="UDP --min-rate (default: 1000).")
    p.add_argument("--skip-udp", action="store_true", help="Skip the UDP scan.")
    p.add_argument("--skip-vuln", action="store_true",
                   help="Drop '--script vuln' from phase 2 (keeps -A).")
    p.add_argument("--no-color", action="store_true", help="Disable colors.")
    return p.parse_args()


def main() -> int:
    args = parse_args()
    configure_colors(args.no_color)

    if not shutil.which("nmap"):
        print(f"{RED}{BOLD}Error:{RESET} nmap not on PATH.", file=sys.stderr)
        return 1

    # ── Sweep mode: subnet discovery → live_hosts.txt, then exit ──
    if args.sweep:
        if args.target:
            print(f"{YELLOW}Note: --sweep given; ignoring -t {args.target}.{RESET}\n")
        sweep_dir = Path(args.output_dir) if args.output_dir else \
            Path(tempfile.mkdtemp(prefix="tombuster-sweep-"))
        sweep_dir.mkdir(parents=True, exist_ok=True)
        if not args.output_dir and not args.keep:
            atexit.register(shutil.rmtree, sweep_dir, ignore_errors=True)
        run_sweep(args.sweep.strip(), sweep_dir)
        return 0

    if not args.target:
        print(f"{RED}{BOLD}Error:{RESET} give -t <target> for a deep scan, "
              f"or --sweep <cidr> for subnet discovery.", file=sys.stderr)
        return 1
    target = args.target.strip()
    if args.output_dir:
        outdir = Path(args.output_dir)          # explicit location -> kept
    elif args.keep:
        outdir = Path(target)                   # --keep -> kept, named after the IP
    else:
        outdir = Path(tempfile.mkdtemp(prefix=f"tombuster-{target}-"))
        cleanup_dir = outdir                    # default -> temp dir, removed on exit
    outdir.mkdir(parents=True, exist_ok=True)
    if cleanup_dir is not None:
        atexit.register(shutil.rmtree, cleanup_dir, ignore_errors=True)

    results = Results(target=target, outdir=outdir)

    if os.geteuid() != 0:
        print(f"{YELLOW}⚠ Not root — the SYN sweep and UDP scan want sudo. "
              f"Re-run with sudo (or --skip-udp).{RESET}\n")

    udp_proc: subprocess.Popen | None = None

    def _cleanup(*_):
        if udp_proc and udp_proc.poll() is None:
            udp_proc.terminate()

    def _sigint(_sig, _frame):
        _cleanup()
        print(f"\n{YELLOW}Interrupted.{RESET}")
        sys.exit(130)
    signal.signal(signal.SIGINT, _sigint)

    try:
        # ── UDP in the background (captured; printed cleanly at the end) ──
        if not args.skip_udp:
            udp_base = outdir / "udp"
            udp_args = ["nmap", "-sU", "--open", "--top-ports", str(args.udp_top),
                        "--min-rate", str(args.udp_min_rate),
                        "-oA", str(udp_base), target]
            print(f"{DIM}[*] UDP scan running in background "
                  f"(top {args.udp_top}); its output appears after the TCP scans.{RESET}\n")
            udp_proc = start_background(udp_args)

        # ── Phase 1: full TCP sweep (live) ──
        print(f"{GREEN}{BOLD}[*] Phase 1 — nmap -p- {target}{RESET}\n")
        tcp_base = outdir / "tcp-all"
        run_live(["nmap", "-p-", "--open", "-oA", str(tcp_base), target])
        results.tcp = [p for p in parse_gnmap(tcp_base.with_suffix(".gnmap"))
                       if p.proto == "tcp"]

        if results.tcp:
            summary = ", ".join(f"{p.port}/{p.service}" for p in results.tcp)
            print(f"\n{GREEN}[+] Open TCP: {summary}{RESET}\n")
        else:
            print(f"\n{RED}[-] No open TCP ports.{RESET}\n")

        # ── Phase 2: -A (+ vuln) on the open ports (live) ──
        if results.tcp:
            spec = ",".join(str(p.port) for p in results.tcp)
            script = [] if args.skip_vuln else ["--script", "vuln"]
            shown = "-A" + ("" if args.skip_vuln else " --script vuln")
            print(f"{BLUE}{BOLD}[*] Phase 2 — nmap {shown} -p {spec} {target}{RESET}\n")
            detail_base = outdir / "tcp-detail"
            run_live(["nmap", "-A", *script, "-p", spec,
                      "-oA", str(detail_base), target])
            detail = parse_gnmap(detail_base.with_suffix(".gnmap"))
            results.tcp = merge_services(results.tcp, detail)

        # ── Join UDP and print its report as one clean block ──
        if udp_proc is not None:
            print(f"\n{MAGENTA}{BOLD}[*] Waiting for UDP scan…{RESET}\n")
            udp_proc.wait()
            udp_report = outdir / "udp.nmap"
            udp_gnmap = outdir / "udp.gnmap"
            results.udp = [p for p in parse_gnmap(udp_gnmap) if p.proto == "udp"]
            if udp_report.exists():
                body = udp_report.read_text(errors="replace").strip()
                print(f"{MAGENTA}{'─' * W}{RESET}")
                print(f"{MAGENTA}{BOLD}  UDP scan (nmap -sU --top-ports "
                      f"{args.udp_top}){RESET}")
                print(f"{MAGENTA}{'─' * W}{RESET}")
                print(body + "\n")
            if results.udp:
                summary = ", ".join(f"{p.port}/{p.service}" for p in results.udp)
                print(f"{MAGENTA}[+] Open UDP: {summary}{RESET}\n")
            else:
                print(f"{DIM}[-] No open UDP ports (or scan needs root).{RESET}\n")

    except KeyboardInterrupt:
        _cleanup()
        print(f"\n{YELLOW}Interrupted.{RESET}")
        return 130

    # ── OSCP follow-ups ──
    print_next_steps(results)

    print(f"{BOLD}Done.{RESET} TCP: {len(results.tcp)} open  ·  "
          f"UDP: {len(results.udp)} open  ·  {outdir}\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
