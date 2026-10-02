#!/usr/bin/env bash
# Runs TLC over every configuration in this directory and checks that each one
# reports what it is supposed to report.
#
# Eight of the ten configurations are expected to FAIL: a model that cannot
# reproduce the two races ADR-010 records is too coarse to be evidence
# for anything, so "TLC found no counterexample" is a failure there. The same
# holds for Migrate.tla, whose four failing configurations are the mistakes
# ADR-022's design avoids and the one precondition it cannot do without.
#
# Usage:  ./check.sh [config-name ...]     (default: all of them)
# Env:    TLA_TOOLS    path to tla2tools.jar (default ../../.tools/tla2tools.jar)
#         TLC_WORKERS  worker threads (default: auto)
set -uo pipefail

cd "$(dirname "$0")"
TLA_TOOLS=${TLA_TOOLS:-../../.tools/tla2tools.jar}
TLC_WORKERS=${TLC_WORKERS:-auto}

if [[ ! -f $TLA_TOOLS ]]; then
    echo "tla2tools.jar not found at $TLA_TOOLS -- run 'make tla-tools' first" >&2
    exit 1
fi

# config                   module     expectation   what the run is evidence for
CASES=(
  "MCFixed                 Multipart  holds         I1 and I2 hold under R1-R4 with conditional rotation"
  "MCLegacyCleanup         Multipart  I1            completion deleting every other manifest of the key (10.8, race 2)"
  "MCLegacyGc              Multipart  I1            gc not checking for open uploads (10.8, race 1)"
  "MCGcOrder               Multipart  I1            R4 steps 1 and 2 swapped"
  "MCUnconditionalRotate   Multipart  I2            rotate --allow-unconditional"
  "MCMigrate               Migrate    holds         migrate-names keeps every write and converges after an abort"
  "MCMigrateNoCreateGuard  Migrate    NoLostWrite   the copy published without If-None-Match"
  "MCMigrateLeaveOnResume  Migrate    Converged     a restart that leaves P when it finds the copy"
  "MCMigrateStaleWriter    Migrate    NoLostWrite   an instance still serving names in clear, If-Match or not"
  "MCMigrateClientDelete   Migrate    NoLostDelete  a client delete of an object not yet migrated"
)

run_one() {
    local name=$1 module=$2 expect=$3 why=$4 log rc
    log=$(mktemp)
    printf '%-23s ' "$name"
    java -XX:+UseParallelGC -cp "$TLA_TOOLS" tlc2.TLC \
        -config "$name.cfg" -workers "$TLC_WORKERS" -cleanup "$module.tla" >"$log" 2>&1
    rc=$?

    local distinct depth collision
    distinct=$(grep -oE '[0-9]+ distinct states found' "$log" | tail -1 | cut -d' ' -f1)
    depth=$(grep -oE 'state graph search is [0-9]+' "$log" | tail -1 | grep -oE '[0-9]+$')
    # TLC fingerprints states into 64 bits, so an exhaustive run is exhaustive
    # up to a collision probability it estimates itself. Worth printing rather
    # than burying: at tens of millions of states it is not negligible.
    collision=$(grep -A1 'based on the actual fingerprints' "$log" | grep -oE 'val = [0-9.E-]+' | tail -1 | cut -d' ' -f3)

    if [[ $expect == holds ]]; then
        if [[ $rc -eq 0 ]] && grep -q 'No error has been found' "$log"; then
            echo "OK    no counterexample (${distinct:-?} distinct states, depth ${depth:-?}, P(collision) ${collision:-?}) -- $why"
            rm -f "$log"; return 0
        fi
        echo "FAIL  expected no counterexample"
    else
        if grep -q "Invariant $expect is violated" "$log"; then
            echo "OK    $expect violated as expected (${distinct:-?} distinct states) -- $why"
            rm -f "$log"; return 0
        fi
        echo "FAIL  expected a counterexample to $expect; the model is too coarse"
    fi

    echo "--- tail of TLC output ---" >&2
    tail -n 40 "$log" >&2
    rm -f "$log"
    return 1
}

failed=0
for case in "${CASES[@]}"; do
    read -r name module expect why <<<"$case"
    if [[ $# -gt 0 ]] && [[ ! " $* " == *" $name "* ]]; then continue; fi
    run_one "$name" "$module" "$expect" "$why" || failed=1
done
exit $failed
