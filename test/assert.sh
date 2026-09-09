#!/bin/sh
# shellcheck disable=SC2145,SC2059,SC2015

LANG=C
SUB=$1
SUITE=${0##*/}

export SEQ=1000 TMP=${TMP:-/tmp/shell-test} TZ=UTC

rm -rf "$TMP" && mkdir -p "$TMP"

: "${SNAP:=$ROOT/test/snap/${SUITE%.*}} ${PASS:=0} ${FAIL:=0} ${SYNC:=0}"

COLOR=$(diff --color=always /dev/null /dev/null 2>/dev/null && echo --color=always)

red="\033[31m"
green="\033[32m"
yellow="\033[33m"
reset="\033[0m"
bold="\033[1m"

OUT="${green}${bold}PASS:%s${reset} FAIL:%s"
ERR="^^^\n  ${red}✘${reset}"
OK="  ${green}✔${reset}"

[ "$SUB" = "up" ] && ERR="  ${yellow}ℹ${reset}" && mkdir -p "$SNAP" && rm -f "$SNAP"/*

bye() {
	printf "\n$OUT\n\n" "$PASS" "$FAIL"
	times
	[ "$SUB" = "up" ] && git -C "$ROOT" add "$SNAP/"
	exit "$FAIL"
}

trap "bye" 0 1 2 3 6 15

cd "$TMP"
echo "Test '$CMD' in '$TMP'"

Check() {
	set -- "$SNAP/$1${2-".$NAME"}" "$TMP/$1" "$3"
	A=$1
	[ -n "$3" ] && {
		sed "$3" "$1" > "$TMP/_diff1" 2>/dev/null
		sed "$3" "$2" > "$TMP/_diff2"
		set -- "$TMP/_diff1" "$TMP/_diff2"
	}
	# shellcheck disable=SC2086 # COLOR is empty when diff lacks --color (BSD)
	diff -uN $COLOR "$1" "$2" &&: $((PASS+=1)) || {
		LINE=$ERR
		OUT="PASS:%s ${red}${bold}FAIL:%s${reset}"
		[ "$SUB" = "up" ] && mkdir -p "$(dirname "$A")" && cp "$2" "$A" &&: $((SYNC+=1)) ||: $((FAIL+=1))
	}
}

It() {
	assert 0 "It $@"
}
Test() {
	assert 0 "Test $@"
}
Fail() {
	EXIT=$1
	shift
	assert "$EXIT" "Fail $@"
}
# Assert a `test` expression; restore CMD, sh keeps assignments made on a function call
Is() {
	_CMD=$CMD CMD=test
	assert 0 "Test $@"
	CMD=$_CMD
}

assert() {
	: $((SEQ+=1))
	EXIT=$1
	NAME="${SEQ#?}. $2"
	LINE=$OK
	shift 2
	$CMD "$@" >"$TMP/$NAME.stdout" 2>"$TMP/$NAME.stderr"
	_EXIT=$?
	Check "$NAME.stderr" "" "$FILTER"
	Check "$NAME.stdout" "" "$FILTER"
	if [ "$_EXIT" != "$EXIT" ]; then
		LINE="exit status expected:$EXIT actual:$_EXIT\n$ERR"
		OUT="PASS:%s ${red}${bold}FAIL:%s${reset}"
		: $((FAIL+=1))
	fi
	printf "$LINE $NAME\n"

	[ "$SUB" = "debug" ] && {
		echo "\$ $CMD $*"
		cat "$TMP/$NAME.stdout" "$TMP/$NAME.stderr"
		sleep 1
	}
}

