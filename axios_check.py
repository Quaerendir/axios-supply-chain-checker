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
RAT_SCRIPT_LINUX  = "/tmp/ld.py"
RAT_PERSISTENCE_WIN = os.path.join(os.environ.get("PROGRAMDATA", "C:\\ProgramData"), "system.bat")
RAT_REGISTRY_KEY  = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
ATTACK_WINDOW_UTC = ("2026-03-31T00:21:00Z", "2026-03-31T03:29:00Z")

BOLD  = "\033[1m"
RED   = "\033[91m"
YEL   = "\033[93m"
GRN   = "\033[92m"
CYN   = "\033[96m"
RST   = "\033[0m"

findings: list[dict] = []


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
    for pj in root.rglob("package.json"):
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
            if "axios" in deps:
                ver_spec = deps["axios"]
                # caret range mogła rozwiązać do złej wersji
                if any(bad in ver_spec for bad in MALICIOUS_AXIOS):
                    hit("WARN", "Bezpośrednia zależność od złej wersji axios",
                        str(pj),
                        f"{dep_field}[axios] = {ver_spec!r} — pinned do zainfekowanej wersji")

    if not found_any:
        ok(f"Brak złośliwych axios/plain-crypto-js w: {root}")


# ─────────────────────────────────────────────
#  2. Lockfiles — sprawdź rozwiązane wersje
# ─────────────────────────────────────────────

def check_lockfile(root: Path):
    # package-lock.json
    for lf in root.rglob("package-lock.json"):
        if "node_modules" in str(lf):
            continue
        try:
            data = json.loads(lf.read_text(encoding="utf-8", errors="replace"))
        except Exception:
            continue
        packages = data.get("packages", {})
        # npm v7+ format
        for pkg_path, info in packages.items():
            n = info.get("name", pkg_path.split("/")[-1] if "/" in pkg_path else "")
            v = info.get("version", "")
            if ("axios" in pkg_path or n == "axios") and v in MALICIOUS_AXIOS:
                hit("CRITICAL", "package-lock.json — zainfekowany axios",
                    str(lf),
                    f"Rozwiązany axios@{v} — lockfile może odzwierciedlać zainfekowaną instalację")
            if MALICIOUS_DEP in pkg_path or n == MALICIOUS_DEP:
                if v == MALICIOUS_DEP_VER:
                    hit("CRITICAL", "package-lock.json — plain-crypto-js",
                        str(lf),
                        f"{MALICIOUS_DEP}@{v} znaleziony w lockfile")

    # yarn.lock — prymitywne grep
    for lf in root.rglob("yarn.lock"):
        if "node_modules" in str(lf):
            continue
        try:
            content = lf.read_text(encoding="utf-8", errors="replace")
        except Exception:
            continue
        for bad_ver in MALICIOUS_AXIOS:
            if f'axios@' in content and f'"version" "{bad_ver}"' in content:
                hit("WARN", "yarn.lock — podejrzana wersja axios",
                    str(lf), f"Możliwy axios@{bad_ver} w yarn.lock")
        if f'{MALICIOUS_DEP}@' in content:
            hit("CRITICAL", "yarn.lock — plain-crypto-js",
                str(lf), f"{MALICIOUS_DEP} znaleziony w yarn.lock")

    # pnpm-lock.yaml
    for lf in root.rglob("pnpm-lock.yaml"):
        if "node_modules" in str(lf):
            continue
        try:
            content = lf.read_text(encoding="utf-8", errors="replace")
        except Exception:
            continue
        if MALICIOUS_DEP in content:
            hit("CRITICAL", "pnpm-lock.yaml — plain-crypto-js",
                str(lf), f"{MALICIOUS_DEP} znaleziony w pnpm-lock.yaml")
        for bad_ver in MALICIOUS_AXIOS:
            if f"axios/{bad_ver}" in content or f"axios@{bad_ver}" in content:
                hit("CRITICAL", "pnpm-lock.yaml — zainfekowany axios",
                    str(lf), f"axios@{bad_ver} w pnpm-lock.yaml")


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

    # Linux / macOS — /tmp/ld.py
    if os_name in ("Linux", "Darwin"):
        p = Path(RAT_SCRIPT_LINUX)
        if p.exists():
            hit("CRITICAL", "RAT artefakt — /tmp/ld.py",
                str(p), "Python RAT plik istnieje — MASZYNA MOŻE BYĆ SKOMPROMITOWANA")
        else:
            ok("/tmp/ld.py nie istnieje")

    # Windows — system.bat + registry
    if os_name == "Windows":
        bat = Path(RAT_PERSISTENCE_WIN)
        if bat.exists():
            hit("CRITICAL", "RAT persistence — system.bat",
                str(bat), "Plik bat RAT dropper istnieje w %PROGRAMDATA%")
        else:
            ok(f"Brak {RAT_PERSISTENCE_WIN}")

        # Registry Run key
        try:
            import winreg
            key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, RAT_REGISTRY_KEY)
            i = 0
            while True:
                try:
                    name, val, _ = winreg.EnumValue(key, i)
                    if "system.bat" in str(val).lower() or C2_DOMAIN in str(val).lower():
                        hit("CRITICAL", "RAT persistence — Registry Run",
                            f"HKLM\\{RAT_REGISTRY_KEY}\\{name}",
                            f"Wartość: {val!r}")
                    i += 1
                except OSError:
                    break
            winreg.CloseKey(key)
        except ImportError:
            pass
        except Exception as e:
            print(f"  [WARN] Registry check: {e}")


# ─────────────────────────────────────────────
#  5. Procesy — orphaned python3 z ld.py
# ─────────────────────────────────────────────

def check_processes():
    os_name = platform.system()
    if os_name in ("Linux", "Darwin"):
        out = _run(["ps", "aux"])
        if out is None:
            print(f"  {YEL}[WARN]{RST} ps aux niedostępne")
            return
        for line in out.splitlines():
            if "ld.py" in line or C2_DOMAIN in line or C2_IP in line:
                hit("CRITICAL", "Podejrzany proces", "ps aux", line.strip())
    elif os_name == "Windows":
        # /v generuje verbose output z dowolnymi stringami (np. ścieżki z akcentami)
        # co wysadza cp1250 — używamy prostego /fo csv bez /v
        out = _run(["tasklist", "/fo", "csv"], timeout=15)
        if out is None:
            print(f"  {YEL}[WARN]{RST} tasklist niedostępne")
            return
        for line in out.splitlines():
            if "ld.py" in line.lower() or "system.bat" in line.lower():
                hit("CRITICAL", "Podejrzany proces (Windows)", "tasklist /fo csv", line.strip())


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

    # DNS cache (Linux systemd-resolved)
    if os_name == "Linux":
        cache_dir = Path("/run/systemd/resolve")
        if cache_dir.exists():
            for f in cache_dir.rglob("*"):
                try:
                    if C2_DOMAIN in f.read_text(errors="replace"):
                        hit("WARN", "C2 domain w cache systemd-resolved", str(f), C2_DOMAIN)
                except Exception:
                    pass

    # macOS DNS cache — nie ma łatwego odczytu, pomiń
    # Sprawdź npm cache — czy zawiera plain-crypto-js
    out = _run(["npm", "cache", "ls", "--json"], timeout=15)
    if out and MALICIOUS_DEP in out:
        hit("WARN", "plain-crypto-js w npm cache",
            "npm cache", f"{MALICIOUS_DEP} znaleziony w lokalnym cache npm — wyczyść: npm cache clean --force")


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
                for bad_ver in MALICIOUS_AXIOS:
                    if f"axios@{bad_ver}" in content or f"axios/{bad_ver}" in content:
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

    print(f"{BOLD}[1/7] Skanowanie package.json w podanych ścieżkach...{RST}")
    for root in scan_roots:
        if not root.exists():
            print(f"  {YEL}[WARN]{RST} Ścieżka nie istnieje: {root}")
            continue
        check_package_json(root)
        check_lockfile(root)

    print(f"\n{BOLD}[2/7] Globalne node_modules...{RST}")
    if not args.no_global:
        check_global_nm()
    else:
        print("  Pominięte (--no-global)")

    print(f"\n{BOLD}[3/7] Artefakty RAT (pliki persistence)...{RST}")
    check_rat_artifacts()

    if not args.no_network:
        print(f"\n{BOLD}[4/7] Procesy...{RST}")
        check_processes()

        print(f"\n{BOLD}[5/7] Sieć — C2 IOC...{RST}")
        check_network()

    print(f"\n{BOLD}[6/7] Logi npm...{RST}")
    check_npm_logs()

    # ── Podsumowanie ──
    print(f"\n{BOLD}[7/7] PODSUMOWANIE{RST}")
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