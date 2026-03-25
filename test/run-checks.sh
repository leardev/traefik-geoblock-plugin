#!/usr/bin/env sh
# run-checks.sh — Geo-blocking integration test cases.
# Used by both the CSV and MMDB CI jobs, and can be run locally.
# Expects Traefik to be reachable at http://localhost/.
# Exits 0 if all checks pass, 1 if any fail.

set -e

PASS=0
FAIL=0

check() {
  local desc="$1" ip="$2" expected="$3"
  local code
  code=$(curl -s -o /dev/null -w '%{http_code}' -H "X-Forwarded-For: $ip" http://localhost/)
  if [ "$code" = "$expected" ]; then
    printf '✅ %s: %s -> %s\n' "$desc" "$ip" "$code"
    PASS=$((PASS + 1))
  else
    printf '❌ %s: %s -> %s (expected %s)\n' "$desc" "$ip" "$code" "$expected"
    FAIL=$((FAIL + 1))
  fi
}

# --- IPv4 ---
check "Private IPv4 (allow)"       "10.0.0.1"      200
check "German IPv4 (allow)"        "91.0.0.1"      200
check "Austrian IPv4 (allow)"      "77.116.0.1"    200
check "Swiss IPv4 (allow)"         "178.197.224.1" 200
check "US IPv4 (block)"            "8.8.8.8"       403
check "Chinese IPv4 (block)"       "1.0.1.1"       403
check "Russian IPv4 (block)"       "5.3.0.1"       403

# --- IPv6 ---
# Google public DNS → US → blocked
check "Google DNS IPv6 (block)"    "2001:4860:4860::8888" 403
# Google Frankfurt prefix → DE → allowed
check "German IPv6 (allow)"        "2a00:1450:4001::1"    200
# Loopback → private → allowed
check "Private IPv6 (allow)"       "::1"                  200

echo ""
echo "Results: $PASS passed, $FAIL failed"

[ "$FAIL" -eq 0 ]
