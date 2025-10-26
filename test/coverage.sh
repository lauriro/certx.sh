#!/bin/sh
# Run tests with kcov line coverage

BIN=$(cd "${0%/*}/.."; pwd)
COV="$BIN/coverage"

command -v kcov >/dev/null 2>&1 || { echo "kcov not found" >&2; exit 1; }

KCOV_TMP=$(mktemp -d)
rm -rf "$COV"
export CMD="kcov --include-path=$BIN/certx.sh $KCOV_TMP $BIN/certx.sh"
sh "$BIN/test/run.sh"
RET=$?

cp -rL "$KCOV_TMP/certx.sh" "$COV"
rm -rf "$KCOV_TMP"

FILE="$COV/coverage.json"
[ -f "$FILE" ] && {
	PCT=$(sed -n 's/.*"percent_covered": *"\([^"]*\)".*/\1/p' "$FILE" | tail -1)
	HIT=$(sed -n 's/.*"covered_lines": *"*\([0-9]*\)"*.*/\1/p' "$FILE" | tail -1)
	ALL=$(sed -n 's/.*"total_lines": *"*\([0-9]*\)"*.*/\1/p' "$FILE" | tail -1)
	printf '\nCoverage: %s/%s lines (%s%%)\n' "$HIT" "$ALL" "$PCT"
	printf 'Report:   %s\n' "$COV/index.html"
}

exit $RET
