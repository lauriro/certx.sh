#!/bin/sh
# Run './test/run.sh up' to generate snapshots

export BIN=$(cd ${0%/*}/..;pwd)
export CMD="${CMD:-$BIN/certx.sh}"
. ${0%/*}/assert.sh

export CERTX_CONF="$TMP/certx.conf"
export CERTX_LOG="$TMP/certx.log"

printf '%s\n' \
	'_terms = YES' \
	'_ca = https://acme-staging-v02.api.letsencrypt.org/directory' \
	'_email = lauri@rooden.ee' \
> "$CERTX_CONF"

STRIP_TIMESTAMP_AND_PID='s/^.*--//'
STRIP_TMP='s|/tmp/tmp\.[^/]*|/tmp/TMP|g'

echo "Test '$CMD' in '$TMP'"

Test "Add domain" domain example.com dns manual
Check "certx.conf"

Test "Add domain http" domain sub.example.com http /var/www/html
Check "certx.conf"

Test "Overwrite domain method" domain example.com dns cloudflare MYTOKEN
Check "certx.conf"

Test "List domains" domain

Test "Add cert" cert mycert1 example.com,www.example.com
Check "certx.conf"

Test "Set key_path" cert mycert1 key_path /etc/ssl/mycert1.key
Check "certx.conf"

Test "Set crt_path" cert mycert1 crt_path /etc/ssl/mycert1.crt
Check "certx.conf"

Test "Set post_hook" cert mycert1 post_hook "systemctl reload nginx"
Check "certx.conf"

Test "Add second cert" cert mycert2 sub.example.com
Check "certx.conf"

Test "List certs" cert

Test "Overwrite cert domains" cert mycert1 example.com
Check "certx.conf"

Test "Drop cert" cert mycert2 drop
Check "certx.conf"

Test "Drop domain" domain sub.example.com drop
Check "certx.conf"

Test "Renew-all nothing" renew-all

Test "No arguments"

Test "Invalid command" invalidcmd

Check "certx.log" ".config" "$STRIP_TIMESTAMP_AND_PID"

# --- Order test with mocked curl ---

# Generate test cert for mock response (only if doesn't exist)
[ -f "$BIN/test/mock/resp/mock-cert.pem" ] || {
	openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
		-keyout /dev/null -out "$BIN/test/mock/resp/mock-cert.pem" -days 90 -nodes \
		-subj '/CN=example.com' 2>/dev/null
}

# Build cert response (headers + PEM body)
printf 'HTTP/2 200\nreplay-nonce: mock-nonce-009\n\n' > "$BIN/test/mock/resp/cert"
cat "$BIN/test/mock/resp/mock-cert.pem" >> "$BIN/test/mock/resp/cert"

# Set up mock environment
export MOCK_STATE="$TMP"
export PATH="$BIN/test/mock:$PATH"
cd "$TMP"

Test "Add cert for order" cert testcert example.com

# Custom assert: filter varying cert date and days count from stderr
FILTER_VARYING='s/Expires: .*/Expires: FILTERED/;s/([0-9]* days)/(N days)/'
: $((SEQ+=1))
NAME="${SEQ#?}. Test Order cert"
LINE=$OK
$CMD cert testcert order >"$TMP/$NAME.stdout" 2>"$TMP/$NAME.stderr"
_EXIT=$?
sed "$FILTER_VARYING" "$TMP/$NAME.stderr" > "$TMP/$NAME.stderr.f" && mv "$TMP/$NAME.stderr.f" "$TMP/$NAME.stderr"
Check "$NAME.stderr" ""
Check "$NAME.stdout" ""
[ "$_EXIT" = "0" ] ||: LINE="exit status expected:0 actual:$_EXIT\n$ERR"
printf "$LINE $NAME\n"

# Filter random keys and dates from config/log
FILTER_CONF='/^_key =/d;/^_jwk/d;/^_thumb/d;/cert .* key =/d;/cert .* end/d'
Check "certx.conf" ".order" "$FILTER_CONF"
Check "certx.log" ".order" "$STRIP_TIMESTAMP_AND_PID;$FILTER_VARYING;$STRIP_TMP"

# --- Test order with pending auth → challenge → valid ---
export MOCK_TEST=pending

# Set up domain with http challenge (reuse existing domain config)
mkdir -p "$TMP/webroot/.well-known/acme-challenge"
$CMD domain example.com http "$TMP/webroot" 2>/dev/null

Test "Add cert for pending auth" cert pendingcert example.com

: $((SEQ+=1))
NAME="${SEQ#?}. Test Order with pending auth"
LINE=$OK
$CMD cert pendingcert order >"$TMP/$NAME.stdout" 2>"$TMP/$NAME.stderr"
_EXIT=$?
sed "$FILTER_VARYING" "$TMP/$NAME.stderr" > "$TMP/$NAME.stderr.f" && mv "$TMP/$NAME.stderr.f" "$TMP/$NAME.stderr"
Check "$NAME.stderr" ""
Check "$NAME.stdout" ""
[ "$_EXIT" = "0" ] ||: LINE="exit status expected:0 actual:$_EXIT\n$ERR"
printf "$LINE $NAME\n"

Check "certx.conf" ".pending" "$FILTER_CONF;$STRIP_TMP"
Check "certx.log" ".pending" "$STRIP_TIMESTAMP_AND_PID;$FILTER_VARYING;$STRIP_TMP"

# --- Test order with DNS challenge (Cloudflare) ---
export MOCK_TEST=dns
rm -f "$MOCK_STATE"/auth-challenged "$MOCK_STATE"/finalized  # Clean mock state from previous tests

# Set up domain with cloudflare DNS challenge
$CMD domain dns.example.com dns cloudflare TESTTOKEN 2>/dev/null

Test "Add cert for DNS challenge" cert dnscert dns.example.com

# Get the thumb value that will be used, then compute expected TXT for mock dig
# The test will use the existing _thumb from previous tests
THUMB=$(grep "^_thumb = " "$CERTX_CONF" | cut -d' ' -f3)
TOKEN="mock-dns-token"
# Compute VAL the same way certx.sh does: sha256(token.thumb) in base64url
EXPECTED_VAL=$(printf '%s.%s' "$TOKEN" "$THUMB" | openssl dgst -sha256 -binary | base64 | tr '+/' '-_' | tr -d '=')
export MOCK_DNS_TXT='"'$EXPECTED_VAL'"'

: $((SEQ+=1))
NAME="${SEQ#?}. Test Order with DNS challenge"
LINE=$OK
$CMD cert dnscert order >"$TMP/$NAME.stdout" 2>"$TMP/$NAME.stderr"
_EXIT=$?
sed "$FILTER_VARYING" "$TMP/$NAME.stderr" > "$TMP/$NAME.stderr.f" && mv "$TMP/$NAME.stderr.f" "$TMP/$NAME.stderr"
Check "$NAME.stderr" ""
Check "$NAME.stdout" ""
[ "$_EXIT" = "0" ] ||: LINE="exit status expected:0 actual:$_EXIT\n$ERR"
printf "$LINE $NAME\n"

Check "certx.conf" ".dns" "$FILTER_CONF;$STRIP_TMP"
Check "certx.log" ".dns" "$STRIP_TIMESTAMP_AND_PID;$FILTER_VARYING;$STRIP_TMP"

# --- Test account rollover ---
export MOCK_TEST=""

: $((SEQ+=1))
NAME="${SEQ#?}. Test Account rollover"
LINE=$OK
$CMD account-rollover >"$TMP/$NAME.stdout" 2>"$TMP/$NAME.stderr"
_EXIT=$?
Check "$NAME.stderr" ""
Check "$NAME.stdout" ""
[ "$_EXIT" = "0" ] ||: LINE="exit status expected:0 actual:$_EXIT\n$ERR"
printf "$LINE $NAME\n"

# Verify key was updated but _kid stayed the same
Check "certx.conf" ".rollover" "$FILTER_CONF;$STRIP_TMP"
Check "certx.log" ".rollover" "$STRIP_TIMESTAMP_AND_PID;$FILTER_VARYING;$STRIP_TMP"

# --- Test account deactivation ---
: $((SEQ+=1))
NAME="${SEQ#?}. Test Account deactivate"
LINE=$OK
$CMD account-deactivate >"$TMP/$NAME.stdout" 2>"$TMP/$NAME.stderr"
_EXIT=$?
Check "$NAME.stderr" ""
Check "$NAME.stdout" ""
[ "$_EXIT" = "0" ] ||: LINE="exit status expected:0 actual:$_EXIT\n$ERR"
printf "$LINE $NAME\n"

# Verify account config was cleared
Check "certx.conf" ".deactivate" "$FILTER_CONF;$STRIP_TMP"
Check "certx.log" ".deactivate" "$STRIP_TIMESTAMP_AND_PID;$FILTER_VARYING;$STRIP_TMP"

