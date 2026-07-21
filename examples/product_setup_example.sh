#!/usr/bin/env bash
# Public ecloud product setup example (claim=false; no CDP; no official client install).
# Customer provides OWN account in cloud_pc.json — never commit tokens.
set -euo pipefail
REPO="${REPO:-$(cd "$(dirname "$0")/.." && pwd)}"
cd "$REPO"

echo "== offline selfcheck =="
python3 main.py setup --selfcheck

if [[ ! -f cloud_pc.json ]]; then
  cat <<'J'
# Create cloud_pc.json first (example skeleton; fill YOUR credentials):
{
  "username": "YOUR_ACCOUNT",
  "password": "YOUR_PASSWORD",
  "cag_host": "36.212.224.105",
  "cag_port": 8899,
  "csapip": "192.168.1.200:30087"
}
# Or: python3 main.py login
J
  exit 2
fi

echo "== login if needed =="
python3 - <<'PY'
import json, os, sys
from pathlib import Path
p = Path("cloud_pc.json")
cfg = json.loads(p.read_text()) if p.exists() else {}
if not cfg.get("access_token"):
    print("no access_token → run: python3 main.py login", file=sys.stderr)
    sys.exit(3)
print("token present (not printed)")
PY

echo "== product setup: power_once + mint (no path_B yet) =="
python3 main.py setup --plain "${PLAIN:-$HOME/.cache/ecloud-pathb/connectstr.plain}"

echo "== optional: 1-round path_B after mint =="
echo "# python3 main.py setup --with-path-b --heart-listen 30"
echo "# or: bin/public-spice-keepalive setup --with-path-b"
echo "== then long loop =="
echo "# bin/public-spice-keepalive run   # or main.py path-b-keepalive / spice-oracle loop"
