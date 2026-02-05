#!/bin/sh
# Run './test/run.sh up' to generate snapshots

export BIN=$(cd ${0%/*}/..;pwd)
export CMD="${CMD:-$BIN/certx.sh}"
export SEQ
. ${0%/*}/assert.sh

export CERTX_CONF="$TMP/certx.conf"
export CERTX_LOG="$TMP/certx.log"

printf '%s\n' \
	'_terms = YES' \
	'_ca = https://acme-staging-v02.api.letsencrypt.org/directory' \
	'_email = lauri@rooden.ee' \
> "$CERTX_CONF"

STRIP_PID='s/\[[0-9]*\] [^ ]*/[*]/'

export PATH="$BIN/test/mock:$PATH"
cd "$TMP"

echo "Test '$CMD' in '$TMP'"

Test "No arguments"
Test "Invalid command" invalidcmd
Test "Help" help
Test "Help ca" help ca
Test "Help domain" help domain

Check "certx.conf"

Test "Add domain" domain example.com dns manual
Check "certx.conf"

Test "Add domain http" domain sub.example.com http /var/www/html
Check "certx.conf"

Test "Overwrite domain method" domain example.com dns cloudflare MYTOKEN
Check "certx.conf"

Test "List domains" domain

Test "Add ip" ip 203.0.113.1 http /var/www/html
Check "certx.conf"

Test "List ips" ip

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

Test "Drop ip" ip 203.0.113.1 drop
Check "certx.conf"

Test "Renew-all nothing" renew-all

# Non-expiring cert should not be renewed
$CMD cert mycert1 end "Dec 31 23:59:59 2099 GMT" 2>/dev/null
Test "Renew-all non-expiring" renew-all
$CMD cert mycert1 end "" 2>/dev/null

Fail 1 "authz-deactivate no URL" authz-deactivate

Check "certx.log" ".config" "$STRIP_PID"

# --- Order test with mocked curl ---

# Generate test cert for mock response (only if doesn't exist)
[ -f "$BIN/test/mock/resp/mock-cert.pem" ] || {
	openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
		-keyout /dev/null -out "$BIN/test/mock/resp/mock-cert.pem" -days 90 -nodes \
		-subj '/CN=example.com' 2>/dev/null
	# Build cert response (headers + PEM body)
	printf 'HTTP/2 200\nreplay-nonce: mock-nonce-009\n\n' > "$BIN/test/mock/resp/cert"
	cat "$BIN/test/mock/resp/mock-cert.pem" >> "$BIN/test/mock/resp/cert"
}

# Set up mock environment
export MOCK_STATE="$TMP"

Test "Add cert for order" cert testcert example.com

Test "Order cert" cert testcert order

# Filter random keys from config (keys vary per run, dates are deterministic via mock date)
FILTER_CONF='/^_key =/d;/^_jwk/d;/^_thumb/d;/cert .* key =/d'
Check "certx.conf" ".order" "$FILTER_CONF"
Check "certx.log" ".order" "$STRIP_PID"

# --- Test order with pending auth → challenge → valid ---
export MOCK_TEST=pending

# Set up domain with http challenge (reuse existing domain config)
mkdir -p "$TMP/webroot/.well-known/acme-challenge"
$CMD domain example.com http "$TMP/webroot" 2>/dev/null

Test "Add cert for pending auth" cert pendingcert example.com

Test "Order with pending auth" cert pendingcert order

Check "certx.conf" ".pending" "$FILTER_CONF"
Check "certx.log" ".pending" "$STRIP_PID"

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

Test "Order with DNS challenge" cert dnscert order

Check "certx.conf" ".dns" "$FILTER_CONF"
Check "certx.log" ".dns" "$STRIP_PID"

# --- Test account rollover ---
export MOCK_TEST=""

Test "Account rollover" account-rollover

# Verify key was updated but _kid stayed the same
Check "certx.conf" ".rollover" "$FILTER_CONF"
Check "certx.log" ".rollover" "$STRIP_PID"

# --- Test account deactivation ---
Test "Account deactivate" account-deactivate

# Verify account config was cleared
Check "certx.conf" ".deactivate" "$FILTER_CONF"

# --- Test ca-reset (must be last - wipes CA config) ---
Test "Ca-reset" ca-reset
Check "certx.conf" ".careset" "$FILTER_CONF"

Check "certx.log" ".end" "$STRIP_PID"

