#!/bin/sh -ef
#-
#- certx.sh - v26.2.4 - Simple ACME client for green certificates. https://github.com/lauriro/certx.sh
#
#  Install:
#    curl -JO certx.sh
#    chmod +x certx.sh
#    ./certx.sh
#-
#- Commands:
#-   domain                                     - list configured domains
#-   domain [name] [dns|http] [opts]..          - configure domain validation
#-   domain [name] drop                         - remove domain configuration
#-   ip                                         - list configured IPs
#-   ip [addr] http [opts]..                    - configure IP validation
#-   ip [addr] drop                             - remove IP configuration
#-   cert                                       - list created certificates
#-   cert [name] [domain,..] [profile]          - configure cert domains and optional CA profile (eg. shortlived)
#-   cert [name] [key_path|crt_path] [paths,..]
#-   cert [name] post_hook [cmd]                - commands to run after cert deployment
#-   cert [name] order                          - order and deploy named cert
#-   cert [name] drop                           - remove cert configuration
#-   account-rollover                           - change account key
#-   account-deactivate                         - deactivate account
#-   authz-deactivate [url]                     - deactivate authorization
#-   ca-reset                                   - delete all CA/account configuration
#-   renew-all [days]                           - renew via ARI, fallback to [days] before expiry (default: 15)
#-   retry [order-file]                         - retry failed order
#-   help [topic]
#-
#- Examples:
#-   ./certx.sh domain example.com dns cloudflare YOUR-API-TOKEN
#-   ./certx.sh cert mycert 'example.com,*.example.com'
#-   ./certx.sh cert mycert 'example.com,203.0.113.1' shortlived
#-   ./certx.sh cert mycert order
#-
#ca-
#ca- CA Directory URLs:
#ca-   LetsEncrypt Test: https://acme-staging-v02.api.letsencrypt.org/directory
#ca-   LetsEncrypt Live: https://acme-v02.api.letsencrypt.org/directory
#ca-   Google Test: https://dv.acme-v02.test-api.pki.goog/directory
#ca-   Google Live: https://dv.acme-v02.api.pki.goog/directory
#ca-   ZeroSSL Live: https://acme.zerossl.com/v2/DV90
#ca-
#dns-
#dns- Automated DNS validation requires executable script: ./dns-PROVIDER.sh
#dns- Script adds TXT record and outputs cleanup commands to stdout.
#dns-
#dns- Available providers: cloudflare, digitalocean, linode, zone.eu
#dns-   curl -O certx.sh/dns-PROVIDER.sh && chmod +x dns-PROVIDER.sh
#dns-
#eab-
#eab- Request External Account Binding (EAB) credentials:
#eab-    Google: gcloud publicca external-account-keys create
#eab       - run locally or in cloud shell web https://console.cloud.google.com/welcome?cloudshell=true
#eab-    ZeroSSL: curl --data 'email=your@email.com' https://api.zerossl.com/acme/eab-credentials-email
#eab-
#domain-
#domain- Configure domain/ip validation before ordering certificates.
#domain-
#domain- Examples:
#domain-   ./certx.sh domain example.com dns manual                  # Interactive (you add TXT record)
#domain-   ./certx.sh domain example.com dns cloudflare TOKEN        # Automated via ./dns-cloudflare.sh script
#domain-   ./certx.sh domain example.com http /www                   # Creates HTTP challenge file to /www/.well-known/acme-challenge/
#domain-   ./certx.sh ip 203.0.113.1 http ssh://203.0.113.1/www      # IP identifiers only support http-01 validation
#domain-
#order-
#order- In case of error "Could not validate ARI 'replaces' field" - try second time again, ARI is used once.
#order-
# shellcheck disable=SC2015 # A && B || C used intentionally

: "${CERTX_CONF:="./certx.conf"} ${CERTX_LOG:="./certx-$(date +%Y-%m).log"} ${CERTX_PID:=$$}"

umask 077
export LC_ALL=C UA='certx.sh/26.2.4' CERTX_CONF CERTX_LOG
NOW=$(date +%s) ARI='' KID='' NL='
'

usage() {
	sed -n "/^#$1- \{0,1\}/s,,,p" "$0" >&2
}
log() {
	printf "%s\n" "$3$1" >&2
	printf '%s [%s] %s -- %s\n' "$(date +%Y-%m-%d\ %H:%M:%S)" "$CERTX_PID" "${SUDO_USER-$USER}" "$1" >>"$CERTX_LOG"
	[ -z "$2" ] || usage "$2"
}
die() {
	log "ERROR: $1" "$2" "$NL"
	exit 1
}
has() {
	for cmd; do CMD=$cmd; command -v "$cmd" >/dev/null || return 1; done
}
_conf() {
	sed -n "/^$(printf %s "$1" | sed 's/[][\\.^$*]/\\&/g')$3 *= */$2" "$CERTX_CONF"
}
conf_has() {
	_VAL=$(_conf "$1" '!b;s,,,p;q')
	[ -n "$_VAL" ]
}
conf_get() {
	conf_has "$1" && printf '%s\n' "$_VAL"
}
conf_set() {
	REST="$(_conf "$1" '!p' "$3")"
	printf '%s\n' "${2:+"$1 = $2"}" "$REST" | sort | sed '/^$/d' >"$CERTX_CONF"
}
conf_find() {
	_conf "$1" "!b;s,,$3\1 = ,p" " \([^ ]*\) $2"
}
conf_ask() {
	conf_has "$1" || {
		printf '\n%b: ' "$2" >&2
		read -r R && [ -n "$R" ] && conf_set "$1" "$R"
	}
}
b64url() {
	openssl base64 | tr '/+' '_-' | tr -d '=\n'
}
b64dec() {
	printf "%s%$(((4-${#1}%4)%4))s\n" "$1" '' | tr '_ -' '/=+' | openssl base64 -d
}
shaB64() {
	printf %s "$1" | openssl sha256 -binary | b64url
}
hexB64() {
	# shellcheck disable=SC2046 # Intentionally split
	printf %b "$(printf '\\%03o' $(sed 's/../0x& /g'))" | b64url
}
json() { # [key] [file] [section-matcher]
	_VAL=$(tr -d '\011\n ' <"${2:-_dir}" | sed 's/{/\n{/g' | sed -n "/${3-.}/p" | sed -n 's/.*"'"$1"'":\("[^"]\{1,\}"\|\[[^]]\{1,\}\]\|[[:alnum:]]*\).*/\1/p' | sed 's/","/\n/g;s/[]["]//g')
	[ -n "$_VAL" ] && printf '%s\n' "$_VAL"
}
sign() { # [URL] [PAYLOAD] [JWK] [KEY]
	PROT=$(printf '{"alg":"ES256",%s,"url":"%s"}' "${3:-"$KID"}$5" "$1" | b64url)
	DATA=$(printf %s "$2" | b64url)
	# shellcheck disable=SC2046 # Intentionally split
	SIG=$(printf %64s $(printf %s.%s "$PROT" "$DATA" | openssl sha256 -sign "${4:-_key}" | openssl asn1parse -inform der | cut -d: -f4) | tr ' ' 0 | hexB64)
	printf '{"protected":"%s","payload":"%s","signature":"%s"}' "$PROT" "$DATA" "$SIG"
}
req() {
	[ -n "$2" ] && {
		[ -n "$NONCE" ] || req "$(json newNonce)" >_res || die 'Cannot get Nonce'
		set -- -H 'Content-Type: application/jose+json' -d "$(sign "$1" "$2" "$3" "$4" ',"nonce":"'"$NONCE"'"')" "$1"
	}
	RES=$(curl -si -A "$UA" --retry 30 --retry-connrefused "$@" | sed 's/[[:space:]]*$//')
	NONCE=$(printf %s "$RES" | sed -n 's/replay-nonce: *//pi')
	CODE=$(printf %s "${RES#* }500" | head -n1)
	[ "${CODE%% *}" -lt 300 ] && printf '%s\n' "$RES" || { printf '%s\n' "$RES" >&2; false; }
}
create_key() {
	log "Creating key '$2'"
	openssl ecparam -genkey -name prime256v1 -noout >"$2"
	conf_set "$1" "$(openssl ec -in "$2" -no_public -conv_form compressed -outform DER 2>/dev/null | b64url)"
}
# Expand compressed key from config or create a new one
expand_key() {
	b64dec "$(conf_get "$1")" | openssl ec -inform DER 2>/dev/null >"$2" || create_key "$@"
}
jwk() {
	openssl ec -in "$1" -pubout -outform DER 2>/dev/null >_pub
	printf '{"crv":"P-256","kty":"EC","x":"%s","y":"%s"}' "$(tail -c64 _pub | head -c32 | b64url)" "$(tail -c32 _pub | b64url)"
}
get_kid() {
	[ -z "$KID" ] || return
	log "CA: $CA"
	req "$CA" >_dir || die "Cannot get CA directory '$CA'"
	conf_ask _terms "CA Terms of Service: $(json termsOfService)\nAccept? (type YES)"
	expand_key _key _key
	conf_has _kid || {
		log 'Registering account'
		JWK=$(jwk _key)
		conf_set _jwk "$JWK"
		conf_set _thumb "$(shaB64 "$JWK")"
		EMAIL=$(conf_get _email) && EMAIL=',"contact":["mailto:'"$EMAIL"'"]' ||:
		EAB=''
		[ "$(json externalAccountRequired)" = "true" ] && {
			log 'External Account Binding required!' eab
			conf_ask _kid 'EAB key ID'
			conf_ask _mac 'EAB HMAC'
			PROTECTED=$(printf '{"alg":"HS256","kid":"%s","url":"%s"}' "$(conf_get _kid)" "$(json newAccount)" | b64url)
			PAYLOAD=$(printf %s "$JWK" | b64url)
			HEX=$(b64dec "$(conf_get _mac)" | od -An -tx1 | tr -d ' \n')
			SIG=$(printf %s.%s "$PROTECTED" "$PAYLOAD" | openssl mac -digest sha256 -macopt "hexkey:$HEX" -binary HMAC | b64url)
			EAB=',"externalAccountBinding":{"protected":"'$PROTECTED'","payload":"'$PAYLOAD'","signature":"'$SIG'"}'
		}
		req "$(json newAccount)" '{"termsOfServiceAgreed":true'"${EMAIL}${EAB}}" '"jwk":'"$JWK" >_res || die 'Registration failed'
		conf_set _kid "$(sed -n 's/^location: *//pi' _res)"
	}
	ARI=$(json renewalInfo ||:)
	KID='"kid":"'$(conf_get _kid)'"'
}
cleanup() {
	[ -s _cleanup ] || return 0
	log 'Cleanup challenges'
	sh _cleanup || log 'Warning: Cleanup failed'
	:>_cleanup
}
seconds_to() {
	T=$1 && [ -n "$T" ] && {
		[ "$T" -gt 0 ] || T=$(($(date -d"$T" +%s || date -jf'%b %d %T %Y %Z' "$T" +%s || date -jf'%Y-%m-%dT%H:%M:%SZ' "$T" +%s)-NOW))
	} 2>/dev/null && printf '%s\n' "$T"
}
deploy_file() {
	for TARGET in $2; do
		log "Deploying $1 to $TARGET"
		P=${TARGET#*://}
		# shellcheck disable=SC2029 # Client-side expansion of path is intended
		case "$TARGET" in
		ssh://*)
			ssh "${P%%/*}" "cat > '/${P#*/}'" <"$1"
			[ -z "$3" ] || printf 'ssh "%s" "rm %s"\n' "${P%%/*}" "'/${P#*/}'" >>_cleanup
			;;
		ftps?://*)
			curl -sS -T "$1" "$TARGET"
			[ -z "$3" ] || printf 'curl -sS "ftp://%s" -Q "DELE %s"\n' "${P%%/*}" "'/${P#*/}'" >>_cleanup
			;;
		file://*|/*)
			cat "$1" >"$P"
			[ -z "$3" ] || printf 'rm %s\n' "'$P'" >>_cleanup
			;;
		*) false;;
		esac || die 'Deploy failed'
	done
}
dns_query() {
	if has dig; then
		dig +short "$1" "$2" ${3:+"@$3"} | cut -d' ' -f1
	elif has host; then
		host -t "$1" "$2" ${3:+"$3"} | cut -d' ' -f$((4+($#<3)))
	fi 2>/dev/null | sed -n "/${4:-.}/p"
}
wait_dns() {
	has dig || has host || {
		log 'WARNING: dig/host not found, sleeping 120s without verification'
		sleep 120
		return 0
	}
	log "Waiting for DNS propagation $2"
	SOA=$(dns_query SOA "$1")
	for i in $(seq 1 150); do
		[ -n "$(dns_query TXT "$2" "$SOA" "$3")" ] && { log "  OK ($((i*2))s)"; return 0; }
		sleep 2; printf "."
	done >&2
	die "DNS propagation timeout $2"
}
get_domain() {
	NAME=$1
	TYPE=$2 && conf_has "ip $1" && TYPE=$3 || while ! conf_has "domain $NAME"; do
		[ "$NAME" = "${NAME#*.}" ] && die "No domain/ip config for '$1'" domain
		NAME=${NAME#*.}
	done
	printf '%s\n' "$NAME"
}

challenge() {
	NAME=$(json value _auth) || die 'No identifier in authorization'
	RR="_acme-challenge.$NAME"
	DOMAIN=$(get_domain "$NAME")
	log "Authorization $NAME: $1"
	# shellcheck disable=SC2046 # Intentionally split into positional params
	set -- $(conf_get "domain $DOMAIN" || conf_get "ip $DOMAIN")
	TOK=$(json token _auth '"type":"'"$1"'-01"') || die 'No challenge token'
	THUMB=$(conf_get _thumb)
	VAL=$(shaB64 "$TOK.$THUMB")

	case "$1.$2" in
	dns.manual)
		printf 'Add DNS record: %s TXT="%s"\nDone? ' "$RR" "$VAL"
		read -r _
		printf "echo 'Remove DNS record: %s TXT=\"%s\"'\n" "$RR" "$VAL" >>_cleanup
		wait_dns "$DOMAIN" "$RR" "$VAL"
		;;
	dns.*)
		[ -x "./dns-${2}.sh" ] || die "Hook $2: not executable" dns
		log "Running hook: $2"
		sh "./dns-${2}.sh" "$DOMAIN" "$RR" "$VAL" "$@" >>_cleanup || die "Hook $2 failed"
		wait_dns "$DOMAIN" "$RR" "$VAL"
		;;
	http.*)
		[ -z "$2" ] && die "Webroot required: domain set $NAME http /var/www/html"
		printf %s "$TOK.$THUMB" >"_challenge"
		deploy_file "_challenge" "$2/.well-known/acme-challenge/$TOK" cleanup
		;;
	esac
	req "$(json url _auth '"type":"'"$1"'-01"')" "{}" >_res || die "Validation Trigger Fail"
}

# Usage: order [cert-name] [retry-file]
order() {
	get_kid
	FILE=$1
	BACKUP=$2
	# shellcheck disable=SC2046 # Intentionally split
	set -- $(conf_get "cert $FILE")
	[ -n "$1" ] || die "No names configured: $FILE" cert
	log "Order $FILE: $*"
	NAMES=$(IFS=,;for N in $1;do get_domain "$N" dns ip >/dev/null && printf '{"type":"%s","value":"%s"},' "$TYPE" "$N"; done)

	[ -z "$BACKUP" ] && {
		BACKUP="$FILE.order-$(date +%Y%m%d-%H%M%S)-$$"
		ID=$(conf_has "cert $FILE ari_replace" && conf_get "cert $FILE ari") && ID=',"replaces":"'"$ID"'"'
		conf_set "cert $FILE ari" '' '[^=]*'
		req "$(json newOrder)" '{"identifiers":['"${NAMES%?}"']'"${2:+",\"profile\":\"$2\""}${ID}"'}' >_order || die 'Creating order failed' order
		cp _order "$BACKUP"
	}
	ORDER_URL=$(sed -n 's/^location: *//pi' _order)
	[ -n "$ORDER_URL" ] || die 'No order location'
	for AUTH in $(json authorizations _order); do
		req "$AUTH" >_auth || die 'Auth failed'
		[ "$(json status _auth '"challenges"')" = "pending" ] && challenge "$AUTH"
	done

	expand_key "cert $FILE key" "$FILE.key"
	while req "$ORDER_URL" >_order; do
		case "$(json status _order)" in
		pending|processing)
			SLEEP=$(seconds_to "$(sed -n 's/retry-after: *//pi' _order)") ||:
			sleep "${SLEEP:-2}"
			;;
		ready)
			log "Sending CSR"
			ALT=$(IFS=,;for N in $1;do get_domain "$N" DNS IP >/dev/null && printf '%s:%s,' "$TYPE" "$N"; done)
			CSR=$(openssl req -new -sha256 -key "$FILE.key" -subj '/' -addext "subjectAltName=${ALT%,}" -outform DER | b64url)
			req "$(json finalize _order)" '{"csr":"'"$CSR"'"}' >_res || die 'CSR failed'
			;;
		valid)
			log "Downloading certificate: $FILE.crt"
			req "$(json certificate _order)" >_res || die 'Certificate download failed'
			sed '1,/^$/d' _res >"$FILE.crt"
			EXP=$(openssl x509 -noout -enddate -in "$FILE.crt" | cut -d= -f2)
			log "Expires: $EXP ($(($(seconds_to "$EXP")/86400)) days)"
			conf_set "cert $FILE end" "$EXP"

			AKI=$(openssl x509 -noout -ext authorityKeyIdentifier -in "$FILE.crt" | sed -n '2s/[^0-9A-Fa-f]//gp' | hexB64) 2>/dev/null
			[ -z "$AKI" ] || {
				conf_set "cert $FILE ari_replace" 1
				conf_set "cert $FILE ari" "$AKI.$(openssl x509 -noout -serial -in "$FILE.crt" | cut -d= -f2 | hexB64)"
			}

			# Deploy if configured
			for EXT in key crt; do
				TARGETS=$(conf_get "cert $FILE ${EXT}_path" | tr ',' ' ')
				[ -n "$TARGETS" ] && deploy_file "$FILE.$EXT" "$TARGETS" && rm "$FILE.$EXT"
			done

			rm "$BACKUP"
			cleanup

			HOOK=$(conf_get "cert $FILE post_hook") && {
				log 'Running post-hook'
				sh -c "$HOOK" || log 'Warning: Post-hook failed'
			}
			return 0
			;;
		*) break ;;
		esac
	done
	cleanup
	die 'Order failed'
}

[ "$1" = lib ] && return 0

# Check dependencies
has cp curl cut date head od openssl sed sort tail tr || die "Missing command: $CMD"

# Touch config file if not writable
[ -w "$CERTX_CONF" ] || :>"$CERTX_CONF" || die "Cannot create config: $CERTX_CONF"
:>_cleanup
trap 'cleanup; rm -f _dir _auth _challenge _key _pub _order _cleanup _newkey _res' EXIT INT TERM

CA=$(conf_get _ca) || {
	log 'No CA configured' ca
	printf "CA directory URL: " >&2
	read -r CA && conf_set _ca "$CA"
	conf_ask _email 'Account email (optional)'
}

case "$1.$3" in
cert.order|cert.renew)
	order "$2"
	;;
cert.end|cert.key|cert.key_path|cert.crt_path|cert.post_hook)
	K="$1 $2 $3"
	shift 3
	conf_set "$K" "$*"
	;;
domain.drop|cert.drop|ip.drop)
	log "Deleting $1: $2"
	conf_set "$1 $2" '' '[^=]*'
	;;
ca-reset.)
	log 'Deleting all CA configuration'
	conf_set "_" '' '[^=]*'
	;;
cert.?*|domain.dns|domain.http|ip.http)
	[ "$1" != cert ] || (IFS=,;for N in $3; do get_domain "$N"; done >/dev/null)
	K="$1 $2"
	shift 2
	conf_set "$K" "$*"
	[ "$1" != dns ] || [ "$2" = manual ] || [ -x "./dns-${2}.sh" ] || die 'No executable DNS validation hook!' dns
	;;
cert.|domain.|ip.)
	printf 'List of %ss:\n' "$1"
	conf_find "$1" '' '  '
	;;
account-rollover.)
	conf_has _kid || die 'No account to rollover'
	log 'Rolling over account key'
	get_kid

	expand_key _newkey _newkey
	JWK=$(jwk _newkey)
	URL=$(json keyChange) || die 'No keyChange url'

	req "$URL" "$(sign "$URL" '{"account":"'"$(conf_get _kid)"'","oldKey":'"$(conf_get _jwk)"'}' '"jwk":'"$JWK" _newkey)">_res || die 'Key rollover failed'

	conf_set _key "$(conf_get _newkey)"
	conf_set _jwk "$JWK"
	conf_set _thumb "$(shaB64 "$JWK")"
	conf_set _newkey ''

	log 'Account key rollover completed'
	;;
account-deactivate.)
	conf_has _kid || die 'No account to deactivate'
	log 'Deactivating account'
	get_kid
	req "$(conf_get _kid)" '{"status":"deactivated"}'>_res || die 'Account deactivation failed'
	conf_set '_' '' '\(kid\|key\|jwk\|thumb\)'
	log 'Account deactivated successfully'
	;;
authz-deactivate.)
	[ -z "$2" ] && die 'Authorization URL required'
	log "Deactivating authorization: $2"
	get_kid
	req "$2" '{"status":"deactivated"}' >_res || die 'Authorization deactivation failed'
	log "Authorization status: $(json status _res)"
	;;
renew-all.)
	RENEW=$(IFS=$NL; for C in $(conf_find cert end); do
		DUE=$((${2:-15}*86400)) END=${C##*= } NAME=${C%% =*}
		ID=$(conf_get "cert $NAME ari") && get_kid && [ -n "$ARI" ] && DUE=0 && {
			# Stored ARI start reached - renew
			END=$(seconds_to "$(conf_get "cert $NAME ari_start")") && [ "$END" -le 0 ] || {
				RA=$(conf_get "cert $NAME ari_retry") && [ "$RA" -gt "$NOW" ] || {
					req "$ARI/$ID" >_res && START=$(json start _res) && conf_set "cert $NAME ari_start" "$START" && END=$START
					RA=$(seconds_to "$(sed -n 's/retry-after: *//pi' _res)") && [ "${RA:-0}" -gt 0 ] && conf_set "cert $NAME ari_retry" "$((RA+NOW))"
				}
			}
		}
		[ "$(seconds_to "${END:-$DUE}")" -lt "$DUE" ] && printf ' %s' "$NAME" ||:
	done 2>/dev/null)
	[ -z "$RENEW" ] && { log 'Nothing to renew'; exit 0; }
	log "Renewing: $RENEW"
	for CERT in $RENEW; do
		( order "$CERT" ) || log "Warning: Failed to renew $CERT"
	done
	;;
retry.)
	[ -f "$2" ] && CERT=${2%.*} && conf_has "cert $CERT" || die "Invalid order to retry $2"
	cp "$2" _order && order "$CERT" "$2"
	;;
*)
	[ $# -gt 0 ] && [ "$1" != help ] && die 'Invalid command!' "-*"
	usage "${2}"
	;;
esac


# <link rel="icon" type="image/svg+xml" href="/favicon.svg"><link href="themes/prism.css" rel="stylesheet"><script src="prism.js"></script>
# <script defer src='https://static.cloudflareinsights.com/beacon.min.js' data-cf-beacon='{"token": "37416beff4f94535b73c513688552327"}'></script>
