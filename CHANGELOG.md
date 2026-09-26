# Changelog

All notable changes to `axios-supply-chain-checker` are documented here.

## [1.1.0] — 2026-09-26

### Fixed — detection (false negatives)
- `yarn.lock` never matched a malicious axios: the old pattern fit neither classic (`version "X"`) nor berry (`version: X`) entries. Both formats are now parsed.
- `package-lock.json` lockfileVersion 1 (npm ≤ 6) was ignored; its nested `dependencies` tree is now walked, including `plain-crypto-js`.
- macOS and Windows IOCs were wrong. The checker now looks for `/Library/Caches/com.apple.act.mond` (macOS), `%PROGRAMDATA%\wt.exe` and `%TEMP%\6202033.vbs/.ps1` (Windows) and `$TMPDIR/6202033`, as reported by StepSecurity, Snyk and Socket. `system.bat` and the Registry Run key, which none of them mention, are no longer checked.

### Fixed — false positives
- Any process with `ld.py` in its command line (`python3 build.py`) was CRITICAL; `ld.py` must now be a whole path component. On Windows the full `%PROGRAMDATA%\wt.exe` path is matched, since Windows Terminal is also `wt.exe`.
- `axios-retry@1.14.1` (substring of the package path) and `axios@1.14.10` (version prefix) were reported as the malicious axios.
- `"^1.14.10"` was reported as pinned to a malicious version.

### Fixed — other
- Python 3.8, the documented minimum, crashed at import (PEP 585 annotations); the traceback exited 1, which means CRITICAL.
- The banner's GHSA line was one character short of the frame.

### Changed
- `^`/`~` ranges that admit a malicious version are reported as INFO ("check the lockfile").
- The npm cache check is its own step and no longer skipped by `--no-network`.
- Removed the systemd-resolved "DNS cache" check (`/run/systemd/resolve` holds no cache).

### Added
- `--version`; the version is shown in the banner and written to the JSON output.
- Regression tests (`tests/`, stdlib `unittest`) and CI on Python 3.8, 3.9, 3.12 and 3.13, plus ShellCheck for `check.sh`.

## [1.0.1] — 2026-03-31

### Fixed
- Windows: subprocess output decoding crash on non-UTF-8 code pages (cp1250/cp852).

## [1.0.0] — 2026-03-31

Initial release: detector for the axios npm supply-chain attack (GHSA-fw8c-xr5c-95f9 / MAL-2026-2306).
