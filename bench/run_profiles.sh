#!/usr/bin/env bash
# Baseline benchmark orchestration (host-side, Git Bash).
# Builds the bench image once, then runs each tool under simulated
# low-end hardware profiles inside Docker containers.
#
# Results are written container-local (/results) and copied out with
# `docker cp` after each run - nothing is written into the (possibly
# cloud-synced) repo mount while containers run, which avoids transient
# share errors on Windows/Docker Desktop.
#
# Usage:  ./bench/run_profiles.sh [results-subdir]
# Env:    DURATION=30 (seconds per run)
set -euo pipefail

# Git Bash mangles container-side absolute paths (e.g. /sentinel/...) into
# Windows paths unless path conversion is disabled.
export MSYS_NO_PATHCONV=1

IMAGE=sentinel-bench
DURATION=${DURATION:-30}
# Which sentinel source file to measure. Point this at a checkout of an older
# revision to produce before/after numbers in the same session, under the same
# host load - results from different sessions are not comparable.
SENTINEL_SCRIPT=${SENTINEL_SCRIPT:-sentinel-monitor.py}
TOOLS=${TOOLS:-"sentinel-tui sentinel-service btop htop"}
SUBDIR=${1:-baseline}
RESULTS_DIR="bench/results/${SUBDIR}"
REPO_WIN="$(pwd -W)"

mkdir -p "$RESULTS_DIR"

echo "==> Building bench image (if needed)"
docker build -q -t "$IMAGE" -f bench/Dockerfile.bench . > /dev/null

run_one() {
  local profile=$1 run=$2 tty=$3; shift 3
  local cpus mem
  case "$profile" in
    pi3) cpus=0.5 mem=256m ;;
    pi4) cpus=1   mem=512m ;;
    *) echo "unknown profile: $profile" >&2; return 1 ;;
  esac
  local name="${profile}-${run}"
  local cname="sentinel-bench-${name}"
  local ttyarg=()
  [ "$tty" = "tty" ] && ttyarg=(--tty)
  local envargs=()
  if [[ "$run" == sentinel-* ]]; then
    envargs=(-e "SENTINEL_PROFILE=/results/profile-${name}.jsonl")
  fi

  # Under Docker Desktop for Windows a constrained container occasionally
  # dies during interpreter start-up (an import fails reading from the
  # bind-mounted checkout) and the run yields 0 samples. That is a host
  # artifact, not a property of the tool under test, so retry rather than
  # publish a hole in the results table.
  local attempt
  for attempt in 1 2 3; do
    echo "==> ${name} (cpus=${cpus} mem=${mem} duration=${DURATION}s, attempt ${attempt})"
    docker rm -f "$cname" > /dev/null 2>&1 || true
    docker run --name "$cname" --cpus="$cpus" --memory="$mem" \
      -v "${REPO_WIN}:/sentinel" \
      ${envargs[@]+"${envargs[@]}"} \
      "$IMAGE" \
      python3 /opt/bench/runner.py --name "$name" --duration "$DURATION" \
        --out "/results/${name}.json" ${ttyarg[@]+"${ttyarg[@]}"} -- "$@"
    docker cp "$cname":/results/. "$RESULTS_DIR/" 2>/dev/null || true
    docker rm "$cname" > /dev/null 2>&1 || true
    if python -c "import json,sys; d=json.load(open(sys.argv[1])); sys.exit(0 if d.get('samples') else 1)" \
         "${RESULTS_DIR}/${name}.json" 2>/dev/null; then
      return 0
    fi
    echo "    (no samples; retrying)" >&2
  done
  echo "    !! ${name} produced no samples after 3 attempts" >&2
}

for profile in pi3 pi4; do
  for tool in $TOOLS; do
    case "$tool" in
      sentinel-tui)     run_one "$profile" sentinel-tui     tty   python3 "$SENTINEL_SCRIPT" ;;
      sentinel-service) run_one "$profile" sentinel-service notty python3 "$SENTINEL_SCRIPT" --service ;;
      sentinel-light)   run_one "$profile" sentinel-light   tty   python3 "$SENTINEL_SCRIPT" --light ;;
      btop)             run_one "$profile" btop             tty   btop ;;
      htop)             run_one "$profile" htop             tty   htop ;;
      *) echo "unknown tool: $tool" >&2; exit 1 ;;
    esac
  done
done

echo "==> Done. Results in ${RESULTS_DIR}/"
python bench/summarize.py "$RESULTS_DIR" 2>/dev/null || true
