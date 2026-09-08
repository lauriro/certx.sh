#!/bin/sh
# End-to-end test against a local Pebble ACME server
#
# Pebble binaries are downloaded to test/.pebble on first run.
# Requires: python3 (serves the webroot), openssl, curl, tar


ROOT=$(cd "$(dirname "$0")/.." && pwd) || exit 1
TMP=/tmp/certx-e2e
CMD="${CMD:-$ROOT/certx.sh}"


export CERTX_CONF="$TMP/certx.conf" CERTX_LOG="$TMP/certx.log" TEST_LOG=1


# Pebble ACME api, Pebble management, webroot, challtestsrv dns/management
ACME=14000 MGMT=15000 HTTP=5002 DNS=8053 CTSRV=8055 ZONE=example.test
PEBBLE=$ROOT/test/.pebble
WEB=$TMP/webroot
DEPLOY=$TMP/deploy
CA_BUNDLE="$TMP/pebble.crt"

PASS=0 FAIL=0
COLOR=$(diff --color=always /dev/null /dev/null 2>/dev/null && echo --color=always)
red="\033[31m" green="\033[32m" bold="\033[1m" reset="\033[0m"
[ -n "$COLOR" ] || red='' green='' bold='' reset=''


die() {
	printf "\n${red}${bold}%s${reset}\n" "$1" >&2
	exit 1
}
pass() {
	printf "  ${green}✔${reset} %s\n" "$1"
	PASS=$((PASS+1))
}
fail() {
	printf "  ${red}✘${reset} %s%s\n" "$1" "${2:+" - $2"}"
	FAIL=$((FAIL+1))
}
bye() {
	# Keep the status die() exited with, or CI passes a run that never started
	RC=$?
	kill_pids
	[ $((PASS+FAIL)) -eq 0 ] || {
		printf "\n${green}${bold}PASS:%s${reset} " "$PASS"
		[ "$FAIL" -eq 0 ] && printf 'FAIL:0\n\n' || printf "${red}${bold}FAIL:%s${reset}\n\n" "$FAIL"
	}
	[ "$FAIL" -eq 0 ] || RC=$FAIL
	exit "$RC"
}

Run() {
	DESC=$1
	shift
	if "$CMD" "$@" >"$TMP/out" 2>"$TMP/err"; then
		pass "$DESC"
	else
		fail "$DESC" "exit $?"
		sed 's/^/      /' "$TMP/err"
	fi
}
Fails() {
	DESC=$1
	shift
	if "$CMD" "$@" >"$TMP/out" 2>"$TMP/err"; then
		fail "$DESC" 'expected failure, got exit 0'
	else
		pass "$DESC"
	fi
}
Yes() {
	DESC=$1
	shift
	if "$@" >/dev/null 2>&1; then
		pass "$DESC"
	else
		fail "$DESC"
	fi
}
Is() {
	if [ "$2" = "$3" ]; then
		pass "$1"
	else
		fail "$1" "expected '$2', got '$3'"
	fi
}


install_pebble() {
	OS=$(uname -s | tr '[:upper:]' '[:lower:]')
	case "$(uname -m)" in
	x86_64|amd64) ARCH=amd64 ;;
	aarch64|arm64) ARCH=arm64 ;;
	*) die "Unsupported architecture: $(uname -m)" ;;
	esac
	URL="${PEBBLE_VER:-"latest/"}download${PEBBLE_VER:+"/$PEBBLE_VER"}"
	for NAME in pebble pebble-challtestsrv; do
		[ -x "$PEBBLE/$NAME" ] && continue
		echo "Downloading $URL/$NAME-$OS-$ARCH.tar.gz"
		curl -fsSL "https://github.com/letsencrypt/pebble/releases/$URL/$NAME-$OS-$ARCH.tar.gz" |
			tar -xzf - -C "$PEBBLE" --strip-components 3 "$NAME-$OS-$ARCH/$OS/$ARCH/$NAME" ||
			die "Cannot download $NAME"
		chmod +x "$PEBBLE/$NAME"
	done
	PEBBLE_VER=$("$PEBBLE/pebble" -version | sed -n 's/.*version: *\([^ ]*\).*/\1/p')
}

save_pid() {
	printf '%s %s\n' "$1" "$(ps -o comm= -p "$1" 2>/dev/null)" >>"$TMP/pids"
}
kill_pids() {
	[ -f "$TMP/pids" ] || return 0
	while read -r P C; do
		# Validate command to be ours
		[ "$(ps -o comm= -p "$P" 2>/dev/null)" = "$C" ] && kill "$P" 2>/dev/null
	done <"$TMP/pids"
	: >"$TMP/pids"
}
wait_up() {
	NAME=$1 LOG=$TMP/$2.log
	shift 2
	i=0;while [ $((i+=1)) -le 30 ]; do
		curl -s -o /dev/null "$@" && return 0
		sleep 1
	done
	sed 's/^/  /' "$LOG" >&2
	die "$NAME did not start"
}

start() {
	openssl req -x509 -newkey rsa:2048 -noenc -days 1 -subj '/CN=localhost' \
		-addext 'subjectAltName=DNS:localhost,IP:127.0.0.1' \
		-addext 'basicConstraints=critical,CA:TRUE' \
		-keyout "$TMP/pebble.key" -out "$CA_BUNDLE" 2>/dev/null ||
		die 'Cannot create Pebble server certificate'

	cat >"$TMP/pebble.json" <<-EOF
		{
		  "pebble": {
		    "listenAddress": "127.0.0.1:$ACME",
		    "managementListenAddress": "127.0.0.1:$MGMT",
		    "certificate": "$TMP/pebble.crt",
		    "privateKey": "$TMP/pebble.key",
		    "httpPort": $HTTP,
		    "tlsPort": 5001,
		    "ocspResponderURL": "",
		    "externalAccountBindingRequired": false
		  }
		}
	EOF

	"$PEBBLE/pebble-challtestsrv" -defaultIPv4 127.0.0.1 -defaultIPv6 '' \
		-http01 '' -https01 '' -tlsalpn01 '' -doh '' \
		-dnsserver ":$DNS" -management ":$CTSRV" >"$TMP/challtestsrv.log" 2>&1 &
	save_pid "$!"

	python3 -m http.server "$HTTP" --bind 127.0.0.1 --directory "$WEB" >"$TMP/webroot.log" 2>&1 &
	save_pid "$!"

	"$PEBBLE/pebble" -config "$TMP/pebble.json" -dnsserver "127.0.0.1:$DNS" \
		>"$TMP/pebble.log" 2>&1 &
	save_pid "$!"

	wait_up 'pebble-challtestsrv' challtestsrv "http://127.0.0.1:$CTSRV/"
	wait_up 'Webroot server' webroot "http://127.0.0.1:$HTTP/"
	wait_up 'Pebble' pebble -f --cacert "$CA_BUNDLE" "https://127.0.0.1:$ACME/dir"
}

conf() {
	grep -q "$1" "$CERTX_CONF"
}
serial() {
	openssl x509 -noout -serial -in "$1" | cut -d= -f2
}
sans() {
	openssl x509 -noout -text -in "$1" | sed -n '/Subject Alternative Name/{n;s/^ *//;p;}'
}


# Before the wipe - kill servers the last run may left behind
kill_pids
rm -rf "$TMP"
mkdir -p "$PEBBLE" "$DEPLOY" "$WEB/.well-known/acme-challenge"

install_pebble
export CURL_CA_BUNDLE=$CA_BUNDLE

trap 'bye' 0 1 2 3 6 PIPE 15
start
cd "$TMP" || die "Cannot enter $TMP"


printf '%s\n' \
	'_terms = YES' \
	"_ca = https://127.0.0.1:$ACME/dir" \
	'_email = e2e@example.test' \
> "$CERTX_CONF"

echo "Test '$CMD' against Pebble ${PEBBLE_VER:-unknown} in '$TMP'"


echo
echo 'Account and configuration'
Run 'Configure domain' domain "$ZONE" http "$WEB"
Run 'Add cert' cert web "www.$ZONE"
Run 'Deploy crt' cert web crt_path "$DEPLOY/web.crt"
Run 'Deploy key' cert web key_path "$DEPLOY/web.key"
Run 'Set post-hook' cert web post_hook touch "$TMP/hook.done"
Fails 'Reject cert for unconfigured domain' cert stray other.invalid

echo
echo 'First order registers the account'
Run 'Order cert' cert web order
Yes 'Account registered' conf '^_kid = https://127.0.0.1'
Yes 'Account key stored' conf '^_key = '
Run 'Show account' account
Yes 'Certificate deployed' test -s "$DEPLOY/web.crt"
Yes 'Key deployed' test -s "$DEPLOY/web.key"
Yes 'Post-hook ran' test -f "$TMP/hook.done"
Is 'Certificate names' "DNS:www.$ZONE" "$(sans "$DEPLOY/web.crt")"
Yes 'Challenge file removed' test -z "$(ls "$WEB/.well-known/acme-challenge")"
Yes 'Order backup removed' test -z "$(ls web.order-* 2>/dev/null)"
Yes 'Renewal info stored' conf '^cert web ari = '

echo
echo 'Multiple names and CA profiles'
Run 'Add multi-name cert' cert multi "a.$ZONE,b.$ZONE" default
Run 'Order multi-name cert' cert multi order
Yes 'Certificate written' test -s multi.crt
Is 'Certificate names' "DNS:a.$ZONE, DNS:b.$ZONE" "$(sans multi.crt)"

echo
echo 'Renewal replaces the certificate'
OLD=$(serial "$DEPLOY/web.crt")
Run 'Renew every cert' renew-all 100%
Is 'Certificate replaced' 'changed' "$([ "$(serial "$DEPLOY/web.crt")" = "$OLD" ] || echo changed)"
Yes 'Nothing due on second pass' test -z "$($CMD renew-all 1 2>&1 >/dev/null | grep -v 'Nothing to renew')"

echo
echo 'Account key rollover'
OLD=$(sed -n 's/^_key = //p' "$CERTX_CONF")
KID=$(sed -n 's/^_kid = //p' "$CERTX_CONF")
Run 'Roll over account key' account-rollover
Is 'Account key replaced' 'changed' "$([ "$(sed -n 's/^_key = //p' "$CERTX_CONF")" = "$OLD" ] || echo changed)"
Is 'Account URI unchanged' "$KID" "$(sed -n 's/^_kid = //p' "$CERTX_CONF")"
# The deployed file is removed first, so this cannot pass on the previous order
rm -f "$DEPLOY/web.crt"
Run 'Order with the new key' cert web order
Yes 'Certificate deployed' test -s "$DEPLOY/web.crt"

echo
echo 'Revoke and remove'
Run 'Revoke certificate' cert web revoke 4
Fails 'Reject a second revoke' cert web revoke 4
Fails 'Reject an unknown authorization' authz-deactivate "https://127.0.0.1:$ACME/authZ/nope"
Run 'Drop cert' cert web drop
Yes 'Cert configuration removed' test -z "$(sed -n '/^cert web/p' "$CERTX_CONF")"
Run 'Drop domain' domain "$ZONE" drop
Fails 'Reject order without domain' cert multi order

echo
echo 'Account deactivation'
Run 'Deactivate account' account-deactivate
Yes 'Account configuration cleared' test -z "$(sed -n '/^_\(kid\|key\|jwk\|thumb\) = /p' "$CERTX_CONF")"
Yes 'CA still configured' conf '^_ca = '
Run 'Reset CA' ca-reset
Yes 'CA configuration cleared' test -z "$(sed -n '/^_/p' "$CERTX_CONF")"

