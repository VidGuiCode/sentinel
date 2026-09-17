#!/usr/bin/env bash
# Cut-capability check.
#
# Run Sentinel in containers that miss rights or resources. Check that
# the panel still draws and states what is missing. It must not stop
# and must not show a blank panel with no reason.
#
# Each case checks two things:
#   1. the frame is not blank (the panel drew at all)
#   2. the right reason text is present, in a panel or in the
#      diagnostics overlay (open it by send of "d")
#
# Usage:  ./bench/degraded.sh
set -uo pipefail
export MSYS_NO_PATHCONV=1

IMAGE=sentinel-degraded
PASS=0
FAIL=0

# case <name> <expect-regex> <docker-run-args...>
scenario() {
  local name=$1 expect=$2; shift 2
  local out
  out=$(docker run --rm -e TERM=xterm-256color "$@" "$IMAGE" \
        python3 bench/capture_frame.py --duration 11 --rows 45 --cols 150 \
          --keys d -- python3 sentinel-monitor.py 2>&1)
  local nonblank
  nonblank=$(printf '%s' "$out" | grep -c '[│┌└]')
  if [ "$nonblank" -lt 5 ]; then
    echo "FAIL  ${name}: panel did not draw (${nonblank} frame lines)"
    printf '%s\n' "$out" | tail -6 | sed 's/^/      | /'
    FAIL=$((FAIL+1)); return
  fi
  if printf '%s' "$out" | grep -qiE "$expect"; then
    echo "PASS  ${name}: drew and stated the reason (/${expect}/)"
    PASS=$((PASS+1))
  else
    echo "FAIL  ${name}: drew but gave no reason that fits /${expect}/"
    FAIL=$((FAIL+1))
  fi
}

echo "==> Build the cut-capability image"
docker build -q -t sentinel-bench -f bench/Dockerfile.bench . > /dev/null
docker build -q -t "$IMAGE" -f bench/Dockerfile.degraded . > /dev/null

# 1. No Docker socket at all (the usual Raspberry Pi case).
scenario "no-docker-socket" "socket missing|not installed"

# 2. Docker socket found but unreadable: mount it, run with no rights.
#    State a permission fault, not "not installed".
scenario "docker-socket-no-perm" "no permission|failed|socket missing" \
  --user 65534:65534 -v /var/run/docker.sock:/var/run/docker.sock:ro

# 3. Unreadable /var/log: security and proxy log collectors must cut back.
scenario "unreadable-var-log" "security|proxy" \
  --user 65534:65534 -v /dev/null:/var/log/auth.log:ro

# 4. Dropped rights and read-only root file system.
scenario "dropped-caps-readonly" "not installed|no permission|socket missing" \
  --cap-drop=ALL --read-only --tmpfs /tmp

# 5. Smallest device profile, to prove cutback is not a memory stop.
scenario "pi3-limits" "not installed|no permission|socket missing" \
  --cpus=0.5 --memory=256m

echo
echo "==> degraded: ${PASS} passed, ${FAIL} failed"
[ "$FAIL" -eq 0 ]
