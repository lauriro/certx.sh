# Run './test/json.sh up' to generate snapshots

export BIN=$(cd ${0%/*}/..;pwd)
export CMD="json" SNAP=$BIN/test/snap/json
. ${0%/*}/assert.sh
set -- lib
. ./certx.sh

echo "Test '$CMD' in '$TMP'"

J=test/data/json

# Create minified version for testing
minify() {
	sed -E ':a;N;$!ba;s,[[:space:]]|("([^"\\]|\\.)*"|.),\1,g' < "$1" > "$TMP/min.json"
}

# Test both pretty and minified JSON
Test2() {
	Test "$1" "$2" "$J/$3" "$4"
	minify "$J/$3"
	Test "$1 (min)" "$2" "$TMP/min.json" "$4"
}

# Directory endpoint (json KEY FILE)
Test2 "directory newNonce" newNonce directory.json
Test2 "directory newAccount" newAccount directory.json
Test2 "directory newOrder" newOrder directory.json
Test2 "directory keyChange" keyChange directory.json
Test2 "directory renewalInfo" renewalInfo directory.json
Test2 "directory revokeCert" revokeCert directory.json
Test2 "directory termsOfService" termsOfService directory.json

Test2 "directory-eab externalAccountRequired" externalAccountRequired directory-eab.json

# Order (json KEY FILE)
Test2 "order-pending status" status order-pending.json
Test2 "order-pending finalize" finalize order-pending.json
Test2 "order-pending authorizations" authorizations order-pending.json
Test2 "order-ready status" status order-ready.json
Test2 "order-processing status" status order-processing.json
Test2 "order-valid status" status order-valid.json
Test2 "order-valid certificate" certificate order-valid.json

# Authorization (json KEY FILE MATCH)
Test2 "authz value" value authz-pending.json
Test2 "authz status challenges" status authz-pending.json '"challenges"'
Test2 "authz token dns-01" token authz-pending.json '"type":"dns-01"'
Test2 "authz url dns-01" url authz-pending.json '"type":"dns-01"'
Test2 "authz token http-01" token authz-pending.json '"type":"http-01"'
Test2 "authz-ip value" value authz-pending-ip.json
Test2 "authz-ip token http-01" token authz-pending-ip.json '"type":"http-01"'

# Challenge response
Test2 "challenge status" status challenge-pending.json
Test2 "challenge token" token challenge-pending.json

# Error responses
Test2 "error type" type error-unauthorized.json
Test2 "error detail" detail error-malformed.json

# ARI (renewal info)
Test2 "ari start" start ari.json






