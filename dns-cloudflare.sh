#!/bin/sh -e
#
# Cloudflare DNS hook
#
# IMPORTANT: Send ONLY cleanup commands to stdout!
#
# Arguments passed to hook:
#   $1 = DOMAIN    (base domain, e.g., example.com)
#   $2 = RR        (full record name, e.g., _acme-challenge.sub.example.com)
#   $3 = VAL       (TXT record value)
#   $4 = "dns"
#   $5 = PROVIDER
#   $6+ = Additional args from domain config
#
# Manual testing:
#   ./dns-cloudflare.sh example.com _acme-challenge.example.com TXT_RECORD_CONTENT dns cloudflare YOUR-API-TOKEN
#

# Save stdout to FD 3 for cleanup commands and log everything to stderr
exec 3>&1 >&2

DOMAIN=$1 RR=$2 VAL=$3 AUTH=$6
API="https://api.cloudflare.com/client/v4/zones"

# dash do not support '. ./certx.sh lib'
set -- lib
. ./certx.sh

api() {
	curl -fs --retry 30 --retry-connrefused -H "Authorization: Bearer $AUTH" -H 'Content-Type: application/json' "$@"
}

api "$API?name=$DOMAIN&status=active" >_res || die "Zone get API failed"
ZONE_ID=$(json id _res '"status"') || {
	cat _zone
	die "No zone for $DOMAIN"
}

# shellcheck disable=SC1003 # DNS TXT records must be quoted: "content":"\"value\""
DATA='{"type":"TXT","name":"'"$RR"'","content":"\"'"$VAL"'\"","ttl":120}'
api -X POST --data "$DATA" "$API/$ZONE_ID/dns_records" > _res || {
	log "Failed to create TXT record, checking existing one"
	api "$API/$ZONE_ID/dns_records?type=TXT&name=$RR&content=\"$VAL\"" > _res
} || die "Failed to find TXT record"
RID=$(json id _res '"type":"TXT"') || die "No id for TXT record"

# Send cleanup commands to FD 3
printf "curl -fs --retry 30 --retry-connrefused -H 'Authorization: Bearer %s' -H 'Content-Type: application/json' -X DELETE '%s' >/dev/null\n" "$AUTH" "$API/$ZONE_ID/dns_records/$RID" >&3

