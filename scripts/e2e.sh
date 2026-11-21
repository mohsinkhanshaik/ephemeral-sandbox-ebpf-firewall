#!/usr/bin/env bash
# End-to-end checks against a real kernel. Run as root.
set -uo pipefail

BIN=${BIN:-./bin/sbx}
pass=0
fail=0

ok()  { echo "PASS  $1"; pass=$((pass + 1)); }
bad() { echo "FAIL  $1"; fail=$((fail + 1)); }

echo "== prerequisites"
"$BIN" check || exit 1

echo "== allowed destination is reachable"
if "$BIN" run --allow 1.1.1.1:443 -- curl -sS --max-time 10 -o /dev/null https://1.1.1.1; then
  ok "allow 1.1.1.1:443"
else
  bad "allow 1.1.1.1:443"
fi

echo "== other destinations are blocked"
if "$BIN" run --allow 1.1.1.1:443 -- curl -sS --max-time 5 -o /dev/null https://8.8.8.8; then
  bad "8.8.8.8 should be denied"
else
  ok "deny 8.8.8.8:443"
fi

echo "== port is enforced, not just the host"
if "$BIN" run --allow 1.1.1.1:443 -- curl -sS --max-time 5 -o /dev/null http://1.1.1.1; then
  bad "1.1.1.1:80 should be denied"
else
  ok "deny 1.1.1.1:80"
fi

echo "== UDP is enforced (DNS to an unlisted resolver)"
if "$BIN" run -- bash -c 'exec 3<>/dev/udp/9.9.9.9/53 && echo x >&3'; then
  bad "UDP to 9.9.9.9:53 should be denied"
else
  ok "deny udp 9.9.9.9:53"
fi

echo "== TTL kills the sandbox"
"$BIN" run --ttl 2s -- sleep 30
rc=$?
[[ $rc -eq 124 ]] && ok "ttl exit code 124" || bad "ttl exit code was $rc"

echo "== background processes are reaped"
"$BIN" run --ttl 3s -- bash -c 'sleep 300 & sleep 300 & wait'
# Each sandbox is a child cgroup directory; the parent's own control files stay.
left=$(find /sys/fs/cgroup/sbx -mindepth 1 -maxdepth 1 -type d 2>/dev/null)
[[ -z "$left" ]] && ok "no leftover sandbox cgroups" || bad "leftover sandbox cgroups: $left"

echo "== memory limit is applied"
"$BIN" run --memory 64M -- python3 -c 'b = bytearray(256 * 1024 * 1024)'
rc=$?
[[ $rc -ne 0 ]] && ok "OOM inside 64M sandbox (rc=$rc)" || bad "allocating 256M under a 64M limit succeeded"

echo
echo "$pass passed, $fail failed"
[[ $fail -eq 0 ]]
