# axios-supply-chain-checker

> Cross-platform detector for the axios npm supply-chain attack (2026-03-31)  
> Wieloplatformowy detektor ataku supply-chain na axios (2026-03-31)

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.8%2B-blue.svg)](https://python.org)
[![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20macOS%20%7C%20Windows-lightgrey.svg)]()

---

## 🇵🇱 Polski

### Czym jest ten atak?

30–31 marca 2026 r. atakujący przejął konto maintainera biblioteki **axios** na npm i opublikował dwie zainfekowane wersje:

| Zainfekowana wersja | Bezpieczna wersja |
|---|---|
| `axios@1.14.1` | `axios@1.14.0` ← downgrade tutaj |
| `axios@0.30.4` | `axios@0.30.3` ← downgrade tutaj |

Złośliwa zależność `plain-crypto-js@4.2.1` (nigdy nie importowana w kodzie axios) uruchamiała skrypt `postinstall`, który:

1. Pobierał platform-specific RAT ze `sfrclak.com:8000`
2. Wykonywał go jako orphaned background process
3. **Usuwał wszelkie ślady swojej obecności** (self-destruct)

RAT zbierał: SSH keys, API keys, cloud credentials, npm tokens, zmienne środowiskowe, listę procesów, strukturę katalogów — i co 60 sekund wysyłał dane do C2.

Artefakty payloadu: Linux `/tmp/ld.py`, macOS `/Library/Caches/com.apple.act.mond`, Windows `%PROGRAMDATA%\wt.exe` (kopia PowerShell) oraz tymczasowe droppery `6202033` (`$TMPDIR/6202033`, `%TEMP%\6202033.vbs` / `.ps1`).

**Jeśli zainstalowałeś axios w oknie 2026-03-31 00:21–03:29 UTC — zakładaj pełny kompromis maszyny.**

GHSA: `GHSA-fw8c-xr5c-95f9` / `MAL-2026-2306`  
GitHub issue: [axios/axios#10604](https://github.com/axios/axios/issues/10604)

### Wymagania

- Python 3.8+
- Brak zewnętrznych zależności (stdlib only)

### Użycie

```bash
# Sklonuj i uruchom
git clone https://github.com/Quaerendir/axios-supply-chain-checker
cd axios-supply-chain-checker

# Przez wrapper bash (zalecane)
./check.sh

# Przez Python bezpośrednio
python3 axios_check.py

# Konkretne projekty
./check.sh /srv/app /home/user/frontend

# Z JSON output (do integracji z SIEM/logów)
./check.sh /srv/app --json-out wyniki.json

# Bez sprawdzania sieci/procesów (np. w izolowanym środowisku)
./check.sh --no-network

# Pomiń globalne node_modules
./check.sh --no-global
```

### Co sprawdza skrypt?

| # | Check | Opis |
|---|---|---|
| 1 | `package.json` (rekursywnie) | Szuka `axios@1.14.1/0.30.4` i `plain-crypto-js@4.2.1`; zakresy `^`/`~` obejmujące złą wersję → INFO |
| 2 | Lockfiles | `package-lock.json` (v1–v3), `yarn.lock` (v1 i berry), `pnpm-lock.yaml` |
| 3 | Globalne node_modules | npm / yarn / pnpm global root |
| 4 | RAT artefakty | `/tmp/ld.py` (Linux), `/Library/Caches/com.apple.act.mond` (macOS), `%PROGRAMDATA%\wt.exe` + `%TEMP%\6202033.vbs/.ps1` (Windows), `$TMPDIR/6202033` |
| 5 | Procesy | `ld.py`, `com.apple.act.mond`, `6202033`, C2 w `ps aux`; na Windows ścieżka `%PROGRAMDATA%\wt.exe` (Win32_Process) |
| 6 | Sieć | `sfrclak.com` / `142.11.206.73` w `/etc/hosts`, `ss`/`netstat` |
| 7 | npm cache | `plain-crypto-js` w lokalnym cache npm |
| 8 | npm logs | Ostatnie 20 logów npm pod kątem wzmianek |

### Remediation

```bash
# Downgrade axios
npm install axios@1.14.0   # gałąź 1.x
npm install axios@0.30.3   # gałąź 0.x

# Pełna reinstalacja
rm -rf node_modules
npm cache clean --force
npm ci

# Blokuj C2 na firewallu
# iptables -A OUTPUT -d 142.11.206.73 -j DROP
# hosts: 0.0.0.0 sfrclak.com
```

Jeśli skrypt wykrył **CRITICAL**:
- Rotuj **wszystkie** sekrety z tej maszyny — SSH keys, API keys, cloud credentials, npm/GitHub tokens
- Nie próbuj "czyścić" — przebuduj maszynę ze świeżego snapshotu
- Sprawdź logi CI/CD z okna `2026-03-31 00:21–03:29 UTC`
- Każdy artefakt (Docker image, bundle) zbudowany w tym oknie → **rebuild**

---

## 🇬🇧 English

### What happened?

On March 30–31, 2026, an attacker compromised the npm account of an axios maintainer and published two malicious versions:

| Malicious version | Safe version |
|---|---|
| `axios@1.14.1` | `axios@1.14.0` ← downgrade here |
| `axios@0.30.4` | `axios@0.30.3` ← downgrade here |

The injected dependency `plain-crypto-js@4.2.1` (never imported in axios source) ran a `postinstall` script that:

1. Downloaded a platform-specific RAT from `sfrclak.com:8000`
2. Launched it as an orphaned background process
3. **Self-destructed**, removing all evidence from `node_modules`

The RAT harvested SSH keys, API keys, cloud credentials, npm tokens, env vars, process lists and directory trees — beaconing every 60 seconds to C2. Payload artefacts: Linux `/tmp/ld.py`, macOS `/Library/Caches/com.apple.act.mond`, Windows `%PROGRAMDATA%\wt.exe` (a renamed PowerShell copy), plus temporary `6202033` droppers (`$TMPDIR/6202033`, `%TEMP%\6202033.vbs` / `.ps1`).

**If you ran `npm install` during 2026-03-31 00:21–03:29 UTC — assume full machine compromise.**

GHSA: `GHSA-fw8c-xr5c-95f9` / `MAL-2026-2306`  
GitHub issue: [axios/axios#10604](https://github.com/axios/axios/issues/10604)

### Requirements

- Python 3.8+
- No external dependencies (stdlib only)

### Usage

```bash
git clone https://github.com/Quaerendir/axios-supply-chain-checker
cd axios-supply-chain-checker

# Bash wrapper (recommended)
./check.sh

# Direct Python
python3 axios_check.py

# Specific paths
./check.sh /srv/app /home/user/frontend

# JSON output (SIEM/log integration)
./check.sh /srv/app --json-out results.json

# Skip network/process checks
./check.sh --no-network

# Skip global node_modules
./check.sh --no-global
```

### What does the script check?

| # | Check | Description |
|---|---|---|
| 1 | `package.json` (recursive) | Finds `axios@1.14.1/0.30.4` and `plain-crypto-js@4.2.1`; `^`/`~` ranges that admit a malicious version → INFO |
| 2 | Lockfiles | `package-lock.json` (v1–v3), `yarn.lock` (classic and berry), `pnpm-lock.yaml` |
| 3 | Global node_modules | npm / yarn / pnpm global root |
| 4 | RAT artifacts | `/tmp/ld.py` (Linux), `/Library/Caches/com.apple.act.mond` (macOS), `%PROGRAMDATA%\wt.exe` + `%TEMP%\6202033.vbs/.ps1` (Windows), `$TMPDIR/6202033` |
| 5 | Processes | `ld.py`, `com.apple.act.mond`, `6202033`, C2 in `ps aux`; on Windows the `%PROGRAMDATA%\wt.exe` path (Win32_Process) |
| 6 | Network | `sfrclak.com` / `142.11.206.73` in `/etc/hosts`, `ss`/`netstat` |
| 7 | npm cache | `plain-crypto-js` in local npm cache |
| 8 | npm logs | Last 20 npm log files for any mentions |

### Tests

```bash
python3 -m unittest discover -s tests -v
```

CI runs them on Python 3.8, 3.9, 3.12 and 3.13.

### Exit codes

| Code | Meaning |
|---|---|
| `0` | No critical findings |
| `1` | At least one CRITICAL finding |
| `2` | Runtime error (missing Python, missing script) |

### Remediation

```bash
# Downgrade axios
npm install axios@1.14.0   # 1.x branch
npm install axios@0.30.3   # 0.x branch

# Full reinstall
rm -rf node_modules
npm cache clean --force
npm ci

# Block C2
# iptables -A OUTPUT -d 142.11.206.73 -j DROP
# hosts: 0.0.0.0 sfrclak.com
```

If CRITICAL findings are detected:
- Rotate **all** secrets from the affected machine
- Do not attempt cleanup — rebuild from a known-clean snapshot
- Audit CI/CD logs for the `2026-03-31 00:21–03:29 UTC` window
- Rebuild any Docker images or build artifacts produced during that window

---

## IOCs

| Type | Value |
|---|---|
| Malicious npm package | `plain-crypto-js@4.2.1` |
| Malicious axios versions | `1.14.1`, `0.30.4` |
| C2 domain | `sfrclak[.]com` |
| C2 IP | `142.11.206.73` |
| C2 port | `8000` |
| C2 path / dropper ID | `/6202033` (`$TMPDIR/6202033`, `%TEMP%\6202033.vbs`, `%TEMP%\6202033.ps1`) |
| Linux RAT path | `/tmp/ld.py` |
| macOS RAT path | `/Library/Caches/com.apple.act.mond` |
| Windows artefact | `%PROGRAMDATA%\wt.exe` (renamed PowerShell copy) |
| npm publisher (attacker) | `nrwise` (email: `nrwise@proton.me`) |
| Compromised maintainer | `jasonsaayman` |

---

## References

- [StepSecurity — initial disclosure](https://www.stepsecurity.io/blog/axios-compromised-on-npm-malicious-versions-drop-remote-access-trojan)
- [Snyk analysis](https://snyk.io/blog/axios-npm-package-compromised-supply-chain-attack-delivers-cross-platform/)
- [Socket.dev analysis](https://socket.dev/blog/axios-npm-package-compromised)
- [Wiz blog](https://www.wiz.io/blog/axios-npm-compromised-in-supply-chain-attack)
- [The Hacker News](https://thehackernews.com/2026/03/axios-supply-chain-attack-pushes-cross.html)
- [axios/axios#10604](https://github.com/axios/axios/issues/10604)

---

*Quaerendir — 2026*
