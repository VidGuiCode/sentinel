#!/usr/bin/env bash
# ARM smoke test (aarch64 and armv7) under QEMU user-mode emulation.
#
# This checks COMPATIBILITY ONLY, not speed. QEMU turns ARM commands
# into x86_64 commands on the host with a large and rough slowdown.
# So all times from here mean nothing. Do not print numbers from it.
#
# Need first (it links qemu-aarch64 and qemu-arm with binfmt_misc):
#     docker run --privileged --rm tonistiigi/binfmt --install arm64,arm
#
# Usage:  ./bench/arm_smoke.sh
set -uo pipefail
export MSYS_NO_PATHCONV=1

PASS=0
FAIL=0

check() {
  local label=$1 expect=$2 output=$3
  if printf '%s' "$output" | grep -qiE "$expect"; then
    echo "  PASS  ${label}"
    PASS=$((PASS+1))
  else
    echo "  FAIL  ${label} (expected /${expect}/)"
    printf '%s\n' "$output" | tail -5 | sed 's/^/        | /'
    FAIL=$((FAIL+1))
  fi
}

run_arch() {
  local platform=$1 tag=$2 expect_machine=$3
  echo "==> ${platform} (${expect_machine})"

  if ! docker build -q --platform "$platform" -t "$tag" -f bench/Dockerfile.arm . > /dev/null; then
    echo "  FAIL  image build"
    FAIL=$((FAIL+1)); return
  fi

  check "runs on ${expect_machine}" "$expect_machine" \
    "$(docker run --rm --platform "$platform" "$tag" uname -m 2>&1)"

  check "--version" "Sentinel v" \
    "$(docker run --rm --platform "$platform" "$tag" python3 sentinel-monitor.py --version 2>&1)"

  check "--help" "service mode" \
    "$(docker run --rm --platform "$platform" "$tag" python3 sentinel-monitor.py --help 2>&1)"

  # Headless mode must send true read values. Then /proc parse works.
  check "--service emits samples" "CPU: +[0-9]+\.[0-9]%.*MEM: +[0-9]+\.[0-9]%" \
    "$(docker run --rm --platform "$platform" "$tag" \
        timeout 12 python3 sentinel-monitor.py --service 2>&1)"

  check "--service --light emits samples" "CPU: +[0-9]+\.[0-9]%" \
    "$(docker run --rm --platform "$platform" "$tag" \
        timeout 12 python3 sentinel-monitor.py --service --light 2>&1)"

  # The curses panel must truly draw a frame (box shapes present).
  check "TUI renders a frame" "[│┌└]" \
    "$(docker run --rm --platform "$platform" -e TERM=xterm-256color "$tag" \
        python3 bench/capture_frame.py --duration 25 --rows 45 --cols 150 \
          -- python3 sentinel-monitor.py 2>&1)"

  check "light TUI renders a frame" "[│┌└]" \
    "$(docker run --rm --platform "$platform" -e TERM=xterm-256color "$tag" \
        python3 bench/capture_frame.py --duration 25 --rows 45 --cols 150 \
          -- python3 sentinel-monitor.py --light 2>&1)"

  # Cut-feature reports must work here too, not only on x86_64.
  check "degraded features explained" "not installed|socket missing|no permission" \
    "$(docker run --rm --platform "$platform" -e TERM=xterm-256color "$tag" \
        python3 bench/capture_frame.py --duration 25 --rows 45 --cols 150 --keys d \
          -- python3 sentinel-monitor.py 2>&1)"
}

echo "NOTE: QEMU user-mode emulation checks compatibility, not speed."
echo

run_arch linux/arm64   sentinel-arm64 aarch64
echo
run_arch linux/arm/v7  sentinel-armv7 armv7l

echo
echo "==> arm smoke: ${PASS} passed, ${FAIL} failed"
[ "$FAIL" -eq 0 ]
