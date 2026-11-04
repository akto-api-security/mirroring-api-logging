#!/usr/bin/env bash
# Runs the standard rate-sweep baseline (2 non-kafka configs, +2 kafka configs
# if kafka-internal is up: json, json+threat) x 3 runs each,
# against ebpf/connections/callback_ratesweep_test.go, using today's date as
# the testname prefix (or an explicit prefix passed as $1).
#
# Output: connections/pprof/<prefix>-<config>-r<N>/... (test's own layout,
# untouched) plus a stdout.log in each of those dirs (for OOM-line detection —
# metrics.json never gets written for a tier the process died before reaching).
#
# Never aborts the matrix on one config's failure (including build/vet or a
# missing Kafka broker for the kafka configs) — logs it and moves on, so a
# single bad config doesn't block the rest of the baseline.
set -uo pipefail

REPO_ROOT="$(git -C "$(dirname "${BASH_SOURCE[0]}")" rev-parse --show-toplevel)"
EBPF_DIR="$REPO_ROOT/ebpf"
PREFIX="${1:-$(date +%-d-%b | tr '[:upper:]' '[:lower:]')}"
RUNS=3
MEM_RESTART=1800
MEM_HARD=2048
GOMAXPROCS=2
TIMEOUT=400s
KAFKA_BROKER="${AKTO_KAFKA_BROKER_URL:-localhost:9092}"
KAFKA_CONTAINER="${RATESWEEP_KAFKA_DOCKER:-kafka-internal}"

cd "$EBPF_DIR" || { echo "FATAL: cannot cd to $EBPF_DIR"; exit 1; }

if compgen -G "connections/pprof/${PREFIX}-*-r*" >/dev/null; then
	echo "FATAL: connections/pprof/${PREFIX}-*-r* already exists — this prefix was used before."
	echo "Pass a different prefix as \$1 (e.g. ${PREFIX}-2) to avoid clobbering the existing baseline."
	exit 1
fi

echo "== rate-sweep-baseline: prefix=$PREFIX =="

echo "-- precheck: go vet + short tests --"
if ! go vet ./connections/ || ! go test -short ./connections/... >/tmp/rsb-precheck.log 2>&1; then
	echo "FATAL: build/vet/short-test check failed — aborting before the full sweep. See /tmp/rsb-precheck.log"
	cat /tmp/rsb-precheck.log
	exit 1
fi
echo "precheck OK"

KAFKA_OK=0
if docker ps --filter "name=$KAFKA_CONTAINER" --format '{{.Status}}' 2>/dev/null | grep -qi healthy; then
	KAFKA_OK=1
	echo "-- precheck: $KAFKA_CONTAINER is healthy, kafka configs will run --"
else
	echo "WARNING: $KAFKA_CONTAINER not running/healthy — skipping the 2 kafka configs, running the other 2 only."
fi

# name | extra test flags (testname/-r<n> appended by run_config)
# ebpf-core has one wire encoder (JSON), so there are no flatbuffers configs.
CONFIGS=(
	"parse-off|-parse=off"
	"parse-on-json|-parse=on -encoder=json"
)
KAFKA_CONFIGS=(
	"parse-on-json-kafka|-parse=on -encoder=json -kafka=true"
	"parse-on-json-kafka-threat|-parse=on -encoder=json -kafka=true -threat=true"
)
if [ "$KAFKA_OK" = "1" ]; then
	CONFIGS+=("${KAFKA_CONFIGS[@]}")
fi

run_config() {
	local slug="$1" flags="$2" run="$3"
	local testname="${PREFIX}-${slug}-r${run}"
	# The test's own -testname dir is under connections/pprof/ (its cwd is
	# ./connections/ via `go test ./connections/`), not ebpf/pprof/ — stdout.log
	# must land in the SAME dir so parse_results.py finds both together.
	local outdir="connections/pprof/${testname}"
	mkdir -p "$outdir"

	echo "-- running $testname --"
	env AKTO_MEM_THRESH_RESTART="$MEM_RESTART" AKTO_SYS_MEM_HARD_LIMIT="$MEM_HARD" \
		AKTO_KAFKA_BROKER_URL="$KAFKA_BROKER" \
		go test -run TestRateSweep -v -count=1 -timeout "$TIMEOUT" ./connections/ \
		-args -testname="$testname" -gomaxprocs="$GOMAXPROCS" $flags \
		>"$outdir/stdout.log" 2>&1
	local status=$?

	if grep -q "^--- PASS" "$outdir/stdout.log"; then
		echo "   $testname: completed clean (no OOM hit)"
	elif grep -q "Refreshing, current" "$outdir/stdout.log"; then
		grep "Refreshing, current" "$outdir/stdout.log" | tail -1 | sed "s/^/   $testname: OOM - /"
	else
		echo "   $testname: FAILED for a reason other than the mem watchdog (exit=$status) — see $outdir/stdout.log"
	fi
	return 0 # never propagate failure — matrix must keep going (see file header)
}

for entry in "${CONFIGS[@]}"; do
	slug="${entry%%|*}"
	flags="${entry#*|}"
	for run in $(seq 1 "$RUNS"); do
		run_config "$slug" "$flags" "$run"
	done
done

echo "== sweep done: prefix=$PREFIX =="
echo "Next (from ebpf/): python3 ../skills/rate-sweep-baseline/scripts/parse_results.py $PREFIX"
