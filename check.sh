#!/usr/bin/env bash
# check.sh — wrapper dla axios-supply-chain-checker
# Użycie: ./check.sh [ścieżka1] [ścieżka2] ... [opcje]
#
# Przykłady:
#   ./check.sh
#   ./check.sh /srv/app /home/user/projects
#   ./check.sh --no-network --json-out wyniki.json
#   ./check.sh /srv/app --json-out wyniki.json

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MAIN="$SCRIPT_DIR/axios_check.py"

# ── Wymagania ──────────────────────────────────────────────────────────────
if ! command -v python3 &>/dev/null; then
    echo "[ERROR] python3 nie znaleziony w PATH." >&2
    exit 2
fi

PY_VER=$(python3 -c "import sys; print(f'{sys.version_info.major}{sys.version_info.minor}')")
if [[ "$PY_VER" -lt 38 ]]; then
    echo "[ERROR] Wymagany Python >= 3.8 (znaleziony: $(python3 --version))" >&2
    exit 2
fi

if [[ ! -f "$MAIN" ]]; then
    echo "[ERROR] Nie znaleziono $MAIN" >&2
    exit 2
fi

# ── Domyślna ścieżka = bieżący katalog jeśli brak argumentów ──────────────
if [[ $# -eq 0 ]]; then
    echo "[INFO] Brak argumentów — skanowanie bieżącego katalogu: $(pwd)"
    python3 "$MAIN" .
else
    python3 "$MAIN" "$@"
fi
