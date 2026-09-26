#!/usr/bin/env python3
"""
axios-rat-check.py
==================
Wieloplatformowy skrypt do wykrywania śladów ataku supply-chain na axios (2026-03-31).

Zainfekowane wersje: axios@1.14.1, axios@0.30.4
Złośliwa zależność:  plain-crypto-js@4.2.1
C2 domain:           sfrclak[.]com / 142.11.206.73
GHSA:                GHSA-fw8c-xr5c-95f9 / MAL-2026-2306

Co sprawdza:
  1. Lokalne node_modules (rekursywnie) — package.json axios + plain-crypto-js
  2. Globalne node_modules npm/yarn/pnpm
  3. Artefakty RAT specyficzne dla platformy (Windows registry, persistence .bat, Python RAT)
  4. Logi sieciowe / hosts — obecność C2 domain/IP
  5. Procesy — orphaned python3 z /tmp/ld.py (Linux/macOS)
  6. Ślady w plikach tymczasowych
  7. package-lock.json / yarn.lock / pnpm-lock.yaml w bieżącym katalogu

Autor: Quaerendir
Licencja: MIT
"""

# list[str] etc. in annotations need Python 3.9; with postponed evaluation
# they are never evaluated, so the script runs on 3.8 as documented.
from __future__ import annotations

import os
import sys
import json
import platform
import subprocess
import re
import glob
import argparse
from pathlib import Path
from datetime import datetime, timezone
from typing import Optional


def _run(cmd: list[str], timeout: int = 10) -> Optional[str]:
    """
    Uruchom polecenie i zwróć stdout jako str lub None przy błędzie.
    Wymusza UTF-8 z fallback errors='replace' — odporna na cp1250/cp852
    i inne locale Windows które sypią UnicodeDecodeError w _readerthread.
    capture_output=True + encoding=None → bytes, dekodujemy sami.
    """
    try:
        r = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
        )
        raw = r.stdout or b""
        # Próbuj UTF-8, potem cp1250 (Windows PL), potem latin-1 (nigdy nie rzuca)
        for enc in ("utf-8", "cp1250", "latin-1"):
            try:
                return raw.decode(enc)
            except UnicodeDecodeError:
                continue
        return raw.decode("latin-1", errors="replace")
    except FileNotFoundError:
        return None  # polecenie nie istnieje
    except Exception:
        return None

# ─────────────────────────────────────────────
#  IOC / stałe ataku
# ─────────────────────────────────────────────

MALICIOUS_AXIOS   = {"1.14.1", "0.30.4"}
MALICIOUS_DEP     = "plain-crypto-js"
MALICIOUS_DEP_VER = "4.2.1"
C2_DOMAIN         = "sfrclak.com"
C2_IP             = "142.11.206.73"
# Payload artefacts per platform, as reported by StepSecurity, Snyk and Socket.
RAT_SCRIPT_LINUX  = "/tmp/ld.py"
RAT_BINARY_MACOS  = "/Library/Caches/com.apple.act.mond"
RAT_PS_COPY_WIN   = os.path.join(os.environ.get("PROGRAMDATA", "C:\\ProgramData"), "wt.exe")
DROPPER_ID        = "6202033"   # C2 path and temp dropper name: $TMPDIR/6202033, %TEMP%\6202033.vbs/.ps1
ATTACK_WINDOW_UTC = ("2026-03-31T00:21:00Z", "2026-03-31T03:29:00Z")

BOLD  = "\033[1m"
RED   = "\033[91m"
YEL   = "\033[93m"
GRN   = "\033[92m"
CYN   = "\033[96m"
RST   = "\033[0m"

findings: list[dict] = []


def _mentions_bad_axios(text: str) -> Optional[str]:
    """Malicious axios version named as axios@X or axios/X in text, else None.
    Bounded on both sides so e.g. axios@1.14.10 or my-axios@1.14.1 don't match."""
    for bad in sorted(MALICIOUS_AXIOS):
        if re.search(r"(?<![\w.-])axios[@/]" + re.escape(bad) + r"(?![0-9])", text):
            return bad
    return None


def _mentions_bad_dep(text: str) -> bool:
    return re.search(r"(?<![\w.-])" + re.escape(MALICIOUS_DEP) + r"[@/]"
                     + re.escape(MALICIOUS_DEP_VER) + r"(?![0-9])", text) is not None


def _parse_ver(v: str) -> Optional[tuple]:
    m = re.fullmatch(r"v?(\d+)\.(\d+)\.(\d+)", v.strip())
    return tuple(int(x) for x in m.groups()) if m else None


def _spec_admits_bad(spec: str) -> Optional[tuple]:
    """(bad_version, exact) if an npm version spec admits a malicious axios
    version: exact pins and simple ^/~ ranges. Anything more complex (||,
    comparators, x-ranges, tags) returns None; the lockfile shows what was
    actually installed."""
    spec = spec.strip()
    op = spec[:1] if spec[:1] in "^~=" else ""
    base = _parse_ver(spec[len(op):])
    if base is None:
        return None
    for bad in sorted(MALICIOUS_AXIOS):
        b = _parse_ver(bad)
        if op in ("", "="):
            if b == base:
                return bad, True
        elif op == "~":
            if b[:2] == base[:2] and b >= base:
                return bad, False
        elif op == "^":
            same = b[0] == base[0] if base[0] != 0 else b[:2] == base[:2]
            if same and b >= base:
                return bad, False
    return None


def _files(root: Path, name: str, skip_node_modules: bool = False):
    """root.rglob(name) without anything under .git (and node_modules if asked)."""
    for f in root.rglob(name):
        if ".git" in f.parts or (skip_node_modules and "node_modules" in f.parts):
            continue
        yield f


def banner():
    print(f"""
{BOLD}{CYN}╔══════════════════════════════════════════════════════════════╗
║         axios supply-chain RAT checker  —  2026-03-31        ║
║   CVE/GHSA: GHSA-fw8c-xr5c-95f9 / MAL-2026-2306             ║
╚══════════════════════════════════════════════════════════════╝{RST}
  Platforma : {platform.system()} {platform.release()} [{platform.machine()}]
  Python    : {sys.version.split()[0]}
  Czas UTC  : {datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')}
""")


def hit(severity: str, category: str, path: str, detail: str):
    sym = {"CRITICAL": f"{RED}[!!!]{RST}", "WARN": f"{YEL}[ ! ]{RST}", "INFO": f"{CYN}[ i ]{RST}"}
    icon = sym.get(severity, "[ ? ]")
    print(f"  {icon} {BOLD}{category}{RST}")
    print(f"       path   : {path}")
    print(f"       detail : {detail}\n")
    findings.append({"severity": severity, "category": category, "path": path, "detail": detail})


def ok(msg: str):
    print(f"  {GRN}[OK ]{RST} {msg}")


# ─────────────────────────────────────────────
#  1. Szukanie package.json z axios + plain-crypto-js
# ─────────────────────────────────────────────

def check_package_json(root: Path):
    """Rekursywne przeszukiwanie package.json — pomija .git, node_modules/*/node_modules głęboko."""
    found_any = False
    for pj in _files(root, "package.json"):
        # Pomiń własne node_modules zagnieżdżone głębiej niż 2 poziomy
        parts = pj.parts
        nm_count = sum(1 for p in parts if p == "node_modules")
        if nm_count > 2:
            continue
        try:
            data = json.loads(pj.read_text(encoding="utf-8", errors="replace"))
        except Exception:
            continue

        name    = data.get("name", "")
        version = data.get("version", "")

        # Sprawdź czy to sam axios w złej wersji
        if name == "axios" and version in MALICIOUS_AXIOS:
            found_any = True
            deps = data.get("dependencies", {})
            pcj_present = MALICIOUS_DEP in deps
            hit("CRITICAL", "Zainfekowany axios",
                str(pj),
                f"axios@{version} — plain-crypto-js w deps: {pcj_present}")

        # Sprawdź czy to plain-crypto-js@4.2.1
        if name == MALICIOUS_DEP and version == MALICIOUS_DEP_VER:
            found_any = True
            hit("CRITICAL", "plain-crypto-js złośliwy pakiet",
                str(pj),
                f"{MALICIOUS_DEP}@{version} — MALWARE DROPPER")

        # Sprawdź dependencies (transitive przez vendoring)
        for dep_field in ("dependencies", "devDependencies", "optionalDependencies"):
            deps = data.get(dep_field, {})
            if isinstance(deps, dict) and isinstance(deps.get("axios"), str):
                ver_spec = deps["axios"]
                admits = _spec_admits_bad(ver_spec)
                if admits and admits[1]:
                    hit("WARN", "Bezpośrednia zależność od złej wersji axios",
                        str(pj),
                        f"{dep_field}[axios] = {ver_spec!r} — pinned do zainfekowanej wersji")
                elif admits:
                    # ^/~ range mogła rozwiązać się do złej wersji w oknie ataku
                    hit("INFO", "Zakres wersji axios obejmuje złą wersję",
                        str(pj),
                        f"{dep_field}[axios] = {ver_spec!r} dopuszcza axios@{admits[0]} — sprawdź lockfile")

    if not found_any:
        ok(f"Brak złośliwych axios/plain-crypto-js w: {root}")


# ─────────────────────────────────────────────
#  2. Lockfiles — sprawdź rozwiązane wersje
# ─────────────────────────────────────────────

def _npm_lock_entries(data: dict):
    """(path, name, version) for every package in a package-lock.json: the
    flat "packages" map (lockfileVersion 2/3), or the nested "dependencies"
    tree of lockfileVersion 1 (npm <= 6)."""
    packages = data.get("packages")
    if isinstance(packages, dict) and packages:
        for pkg_path, info in packages.items():
            if isinstance(info, dict):
                name = info.get("name") or pkg_path.rsplit("node_modules/", 1)[-1]
                yield pkg_path, name, str(info.get("version", ""))
        return

    def walk(deps, prefix):
        for name, info in (deps or {}).items():
            if isinstance(info, dict):
                path = f"{prefix}node_modules/{name}"
                yield path, name, str(info.get("version", ""))
                yield from walk(info.get("dependencies"), path + "/")
    yield from walk(data.get("dependencies"), "")


def _yarn_lock_entries(content: str):
    """(names, version) for every entry of a yarn.lock, classic v1
    (`version "1.2.3"`) or berry (`version: 1.2.3`)."""
    names: list[str] = []
    for line in content.splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        if not line[0].isspace():
            # Entry header: one or more descriptors, e.g.
            #   axios@^1.14.0, axios@^1.2.0:     "axios@npm:^1.14.0":
            names = []
            header = line.rstrip()
            if header.endswith(":"):
                for desc in header[:-1].split(","):
                    desc = desc.strip().strip('"')
                    at = desc.find("@", 1)   # from 1: skip a scope's leading @
                    if at > 0:
                        names.append(desc[:at])
            continue
        m = re.match(r'\s+version:?\s+"?([^"\s]+)"?\s*$', line)
        if m and names:
            yield names, m.group(1)
            names = []


def _flag_dep(source: str, path: str, version: str):
    if version == MALICIOUS_DEP_VER:
        hit("CRITICAL", f"{source} — plain-crypto-js", path,
            f"{MALICIOUS_DEP}@{version} znaleziony w lockfile — MALWARE DROPPER")
    else:
        hit("WARN", f"{source} — plain-crypto-js", path,
            f"{MALICIOUS_DEP}@{version or '?'} — pakiet atakującego (inna wersja niż dropper)")


def check_lockfile(root: Path):
    # package-lock.json
    for lf in _files(root, "package-lock.json", skip_node_modules=True):
        try:
            data = json.loads(lf.read_text(encoding="utf-8", errors="replace"))
        except Exception:
            continue
        for _path, name, ver in _npm_lock_entries(data):
            if name == "axios" and ver in MALICIOUS_AXIOS:
                hit("CRITICAL", "package-lock.json — zainfekowany axios",
                    str(lf),
                    f"Rozwiązany axios@{ver} — lockfile może odzwierciedlać zainfekowaną instalację")
            if name == MALICIOUS_DEP:
                _flag_dep("package-lock.json", str(lf), ver)

    # yarn.lock (v1 i berry)
    for lf in _files(root, "yarn.lock", skip_node_modules=True):
        try:
            content = lf.read_text(encoding="utf-8", errors="replace")
        except Exception:
            continue
        for names, ver in _yarn_lock_entries(content):
            if "axios" in names and ver in MALICIOUS_AXIOS:
                hit("CRITICAL", "yarn.lock — zainfekowany axios",
                    str(lf), f"Rozwiązany axios@{ver} w yarn.lock")
            if MALICIOUS_DEP in names:
                _flag_dep("yarn.lock", str(lf), ver)

    # pnpm-lock.yaml
    for lf in _files(root, "pnpm-lock.yaml", skip_node_modules=True):
        try:
            content = lf.read_text(encoding="utf-8", errors="replace")
        except Exception:
            continue
        if _mentions_bad_dep(content):
            hit("CRITICAL", "pnpm-lock.yaml — plain-crypto-js",
                str(lf), f"{MALICIOUS_DEP}@{MALICIOUS_DEP_VER} znaleziony w pnpm-lock.yaml")
        elif MALICIOUS_DEP in content:
            hit("WARN", "pnpm-lock.yaml — plain-crypto-js",
                str(lf), f"{MALICIOUS_DEP} (inna wersja) znaleziony w pnpm-lock.yaml")
        bad = _mentions_bad_axios(content)
        if bad:
            hit("CRITICAL", "pnpm-lock.yaml — zainfekowany axios",
                str(lf), f"axios@{bad} w pnpm-lock.yaml")


# ─────────────────────────────────────────────
#  3. Globalne node_modules
# ─────────────────────────────────────────────

def get_global_nm_paths() -> list[Path]:
    candidates = []

    out = _run(["npm", "root", "-g"])
    if out and out.strip():
        candidates.append(Path(out.strip()))

    out = _run(["yarn", "global", "dir"])
    if out and out.strip():
        candidates.append(Path(out.strip()) / "node_modules")

    out = _run(["pnpm", "root", "-g"])
    if out and out.strip():
        candidates.append(Path(out.strip()))

    return [p for p in candidates if p.exists()]


def check_global_nm():
    paths = get_global_nm_paths()
    if not paths:
        ok("Brak dostępnych globalnych node_modules do sprawdzenia")
        return
    for nm in paths:
        check_package_json(nm)


# ─────────────────────────────────────────────
#  4. Artefakty RAT — platforma-specyficzne
# ─────────────────────────────────────────────

def check_rat_artifacts():
    os_name = platform.system()
    tmp = os.environ.get("TMPDIR") or os.environ.get("TEMP") or "/tmp"
    artifacts: dict[str, str] = {}
    if os_name == "Linux":
        artifacts[RAT_SCRIPT_LINUX] = "Python RAT (Linux)"
    if os_name == "Darwin":
        artifacts[RAT_BINARY_MACOS] = "RAT binary (macOS)"
    if os_name == "Windows":
        artifacts[RAT_PS_COPY_WIN] = "kopia PowerShell używana przez RAT"
        artifacts[os.path.join(tmp, f"{DROPPER_ID}.vbs")] = "dropper VBScript"
        artifacts[os.path.join(tmp, f"{DROPPER_ID}.ps1")] = "payload PowerShell"
    else:
        for d in (tmp, "/tmp"):
            artifacts[os.path.join(d, DROPPER_ID)] = "tymczasowy dropper"

    for path, what in artifacts.items():
        if Path(path).exists():
            hit("CRITICAL", f"Artefakt RAT — {what}",
                path, "Plik IOC istnieje — MASZYNA MOŻE BYĆ SKOMPROMITOWANA")
        else:
            ok(f"{path} nie istnieje")


# ─────────────────────────────────────────────
#  5. Procesy — orphaned python3 z ld.py
# ─────────────────────────────────────────────

# Command-line indicators. ld.py must be a whole path component, so e.g.
# `python3 build.py` does not match.
PROC_PATTERNS = [
    re.compile(r"(^|[\s/\\])ld\.py(\s|$)"),
    re.compile(re.escape(RAT_BINARY_MACOS)),
    re.compile(r"(^|[\s/\\])" + DROPPER_ID + r"(\.vbs|\.ps1)?(\s|$)"),
    re.compile(re.escape(C2_DOMAIN)),
    re.compile(re.escape(C2_IP)),
]


def check_processes():
    os_name = platform.system()
    if os_name in ("Linux", "Darwin"):
        out = _run(["ps", "aux"])
        if out is None:
            print(f"  {YEL}[WARN]{RST} ps aux niedostępne")
            return
        for line in out.splitlines():
            if any(p.search(line) for p in PROC_PATTERNS):
                hit("CRITICAL", "Podejrzany proces", "ps aux", line.strip())
    elif os_name == "Windows":
        # tasklist shows image names only, and wt.exe is also Windows
        # Terminal's name, so match the full executable path instead.
        out = _run(["powershell", "-NoProfile", "-NonInteractive", "-Command",
                    "Get-CimInstance Win32_Process | ForEach-Object "
                    "{ [string]$_.ExecutablePath + '|' + [string]$_.CommandLine }"],
                   timeout=30)
        if out is None:
            print(f"  {YEL}[WARN]{RST} PowerShell niedostępny — pominięto procesy")
            return
        for line in out.splitlines():
            exe, _, cmdline = line.partition("|")
            if exe.strip().lower() == RAT_PS_COPY_WIN.lower() or \
               any(p.search(cmdline) for p in PROC_PATTERNS):
                hit("CRITICAL", "Podejrzany proces (Windows)", "Win32_Process", line.strip())


# ─────────────────────────────────────────────
#  6. Sieć — C2 domain/IP w hosts, conntrack, netstat
# ─────────────────────────────────────────────

def check_network():
    os_name = platform.system()

    # /etc/hosts
    hosts_file = Path("/etc/hosts") if os_name != "Windows" else Path(
        os.environ.get("SYSTEMROOT", "C:\\Windows") + "\\System32\\drivers\\etc\\hosts"
    )
    if hosts_file.exists():
        try:
            content = hosts_file.read_text(encoding="utf-8", errors="replace")
            if C2_DOMAIN in content or C2_IP in content:
                hit("WARN", "C2 IOC w /etc/hosts",
                    str(hosts_file),
                    f"Znaleziono {C2_DOMAIN} lub {C2_IP} — może być blokada lub dowód aktywności")
        except Exception:
            pass

    # netstat / ss
    if os_name in ("Linux", "Darwin"):
        cmd = ["ss", "-tnp"] if os_name == "Linux" else ["netstat", "-an"]
        out = _run(cmd)
        if out:
            for line in out.splitlines():
                if C2_IP in line or C2_DOMAIN in line:
                    hit("CRITICAL", "Aktywne połączenie z C2",
                        " ".join(cmd), line.strip())
    elif os_name == "Windows":
        out = _run(["netstat", "-an"])
        if out:
            for line in out.splitlines():
                if C2_IP in line:
                    hit("CRITICAL", "Aktywne połączenie z C2 (Windows)",
                        "netstat -an", line.strip())



def check_npm_cache():
    """plain-crypto-js w lokalnym cache npm (lokalny odczyt, bez sieci)."""
    out = _run(["npm", "cache", "ls", "--json"], timeout=15)
    if out is None:
        ok("npm niedostępny — pominięto cache")
        return
    if out and MALICIOUS_DEP in out:
        hit("WARN", "plain-crypto-js w npm cache",
            "npm cache", f"{MALICIOUS_DEP} znaleziony w lokalnym cache npm — wyczyść: npm cache clean --force")
    else:
        ok("Brak plain-crypto-js w cache npm")


# ─────────────────────────────────────────────
#  7. Historia npm install (jeśli dostępna)
# ─────────────────────────────────────────────

def check_npm_logs():
    """Sprawdź logi npm pod kątem instalacji złych wersji."""
    possible_log_dirs = []
    os_name = platform.system()

    if os_name in ("Linux", "Darwin"):
        possible_log_dirs += [
            Path.home() / ".npm" / "_logs",
            Path("/var/log"),
        ]
    elif os_name == "Windows":
        appdata = os.environ.get("APPDATA", "")
        possible_log_dirs.append(Path(appdata) / "npm-cache" / "_logs")

    for log_dir in possible_log_dirs:
        if not log_dir.exists():
            continue
        for log_file in sorted(log_dir.glob("*.log"), reverse=True)[:20]:  # ostatnie 20
            try:
                content = log_file.read_text(encoding="utf-8", errors="replace")
                bad_ver = _mentions_bad_axios(content)
                if bad_ver:
                    hit("WARN", "Ślad w logach npm",
                        str(log_file),
                        f"axios@{bad_ver} wzmiankowany w logach npm — sprawdź datę pliku")
                if MALICIOUS_DEP in content:
                    hit("WARN", "plain-crypto-js w logach npm",
                        str(log_file), "Złośliwa zależność wzmiankowana w logach")
            except Exception:
                continue


# ─────────────────────────────────────────────
#  8. Sprawdzenie bezpiecznych wersji do downgrade
# ─────────────────────────────────────────────

def print_remediation():
    print(f"\n{BOLD}{CYN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━{RST}")
    print(f"{BOLD}  REMEDIATION / CO ROBIĆ{RST}\n")
    print(f"  Bezpieczne wersje:")
    print(f"    axios@1.14.0  (lub niżej z gałęzi 1.x)")
    print(f"    axios@0.30.3  (lub niżej z gałęzi 0.x)\n")
    print(f"  Natychmiastowe kroki:")
    print(f"    1. npm install axios@1.14.0   # lub 0.30.3")
    print(f"    2. rm -rf node_modules && npm ci")
    print(f"    3. npm cache clean --force")
    print(f"    4. Jeśli masz CRITICAL findingi:")
    print(f"       → ROTUJ wszystkie sekrety: SSH keys, API keys, cloud creds, npm tokens")
    print(f"       → PRZEBUDUJ maszynę ze świeżego snapshotu — nie próbuj czyścić w miejscu")
    print(f"       → SPRAWDŹ logi CI/CD z okna 2026-03-31 00:21–03:29 UTC")
    print(f"       → BLOKUJ egress do {C2_DOMAIN} / {C2_IP}")
    print(f"    5. docker images zbudowane w tym oknie czasowym → rebuild\n")
    print(f"  GHSA : GHSA-fw8c-xr5c-95f9")
    print(f"  Ref  : https://github.com/axios/axios/issues/10604")
    print(f"{BOLD}{CYN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━{RST}\n")


# ─────────────────────────────────────────────
#  MAIN
# ─────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="axios RAT supply-chain checker — GHSA-fw8c-xr5c-95f9"
    )
    parser.add_argument(
        "paths",
        nargs="*",
        default=["."],
        help="Katalogi do przeszukania (domyślnie: bieżący katalog)"
    )
    parser.add_argument(
        "--no-global",
        action="store_true",
        help="Pomiń globalne node_modules"
    )
    parser.add_argument(
        "--no-network",
        action="store_true",
        help="Pomiń sprawdzanie sieci/procesów"
    )
    parser.add_argument(
        "--json-out",
        metavar="FILE",
        help="Zapisz wyniki jako JSON do pliku"
    )
    args = parser.parse_args()

    banner()

    scan_roots = [Path(p).resolve() for p in args.paths]

    print(f"{BOLD}[1/8] Skanowanie package.json w podanych ścieżkach...{RST}")
    for root in scan_roots:
        if not root.exists():
            print(f"  {YEL}[WARN]{RST} Ścieżka nie istnieje: {root}")
            continue
        check_package_json(root)
        check_lockfile(root)

    print(f"\n{BOLD}[2/8] Globalne node_modules...{RST}")
    if not args.no_global:
        check_global_nm()
    else:
        print("  Pominięte (--no-global)")

    print(f"\n{BOLD}[3/8] Artefakty RAT...{RST}")
    check_rat_artifacts()

    if not args.no_network:
        print(f"\n{BOLD}[4/8] Procesy...{RST}")
        check_processes()

        print(f"\n{BOLD}[5/8] Sieć — C2 IOC...{RST}")
        check_network()

    print(f"\n{BOLD}[6/8] Cache npm...{RST}")
    check_npm_cache()

    print(f"\n{BOLD}[7/8] Logi npm...{RST}")
    check_npm_logs()

    # ── Podsumowanie ──
    print(f"\n{BOLD}[8/8] PODSUMOWANIE{RST}")
    print(f"  {'─'*50}")
    critical = [f for f in findings if f["severity"] == "CRITICAL"]
    warn     = [f for f in findings if f["severity"] == "WARN"]
    info_f   = [f for f in findings if f["severity"] == "INFO"]

    if not findings:
        print(f"  {GRN}{BOLD}Brak wykrytych śladów ataku.{RST}")
        print(f"  Jeśli instalowałeś pakiety npm w oknie 2026-03-31 00:21–03:29 UTC,")
        print(f"  sprawdź logi CI/CD ręcznie — RAT usuwa własne ślady po wykonaniu.")
    else:
        print(f"  {RED}CRITICAL : {len(critical)}{RST}")
        print(f"  {YEL}WARN     : {len(warn)}{RST}")
        print(f"  {CYN}INFO     : {len(info_f)}{RST}")

    print_remediation()

    if args.json_out:
        out = {
            "timestamp_utc": datetime.now(timezone.utc).isoformat(),
            "platform": f"{platform.system()} {platform.release()}",
            "scanned_paths": [str(r) for r in scan_roots],
            "findings": findings,
            "summary": {
                "critical": len(critical),
                "warn": len(warn),
                "info": len(info_f),
            }
        }
        with open(args.json_out, "w", encoding="utf-8") as fh:
            json.dump(out, fh, indent=2, ensure_ascii=False)
        print(f"  Wyniki JSON zapisane do: {args.json_out}")

    sys.exit(1 if critical else 0)


if __name__ == "__main__":
    main()