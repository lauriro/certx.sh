# certx.sh

Simple ACME client for green certificates.
Works with Let's Encrypt, Google Trust, ZeroSSL.
Just a shell script - requires curl, openssl, and standard Unix utilities (sed, sort, etc.).

~500 lines of POSIX shell includes
DNS/HTTP challenges, multi-server deployment (ssh/ftp), account rollover/deactivation, EAB, ARI, wildcard/IP/shortlived/alternate certs.

> CA-friendly: creates one account and reuses it for all certificates.


## Quick Start

```bash
curl -JO certx.sh
chmod +x certx.sh
./certx.sh domain example.com dns cloudflare YOUR-API-TOKEN
./certx.sh cert mycert 'example.com,*.example.com'
./certx.sh cert mycert order
# Output: mycert.key, mycert.crt
```

On first run it'll prompt for CA URL and optional email. The account is created once and reused for all certificates.

## Validation

```bash
# DNS - interactive (you add TXT record manually)
./certx.sh domain example.com dns manual

# Automated DNS validation requires executable script: ./dns-PROVIDER.sh
# Script adds TXT record and outputs cleanup commands to stdout.

# Available providers: cloudflare, digitalocean, linode, zone.eu
curl -O certx.sh/dns-PROVIDER.sh && chmod +x dns-PROVIDER.sh

# HTTP - writes challenge file to webroot (supports ssh://, needs key login for automation)
# Note: Webroot directory `/.well-known/acme-challenge/` should exist and be accessible via HTTP.
./certx.sh domain example.com http /www
./certx.sh domain example.com http ssh://server/www

# IP - only HTTP validation, can mix with domains
./certx.sh ip 203.0.113.1 http ssh://203.0.113.1/www
./certx.sh cert mycert 'example.com,*.example.com,203.0.113.1'
```

## Deployment

Deploy certs to multiple locations (local, SSH, or FTP):

```bash
./certx.sh cert mycert key_path /etc/ssl/private/key
./certx.sh cert mycert crt_path /etc/ssl/certs/cert,ssh://server1/etc/ssl/cert,ftp://user:pass@host/etc/ssl/cert
# Happens automatically after cert order/renewal
```

## Renewal

```bash
./certx.sh cert mycert order              # order new cert ignoring expiry
./certx.sh renew-all                      # renew via ARI, fallback to 20% of validity
./certx.sh renew-all 33%                  # renew at 33% of validity (ignores ARI)
./certx.sh renew-all 7                    # renew 7 days before expiry (ignores ARI)
```

Note: `renew-all` only works for certificates that have been successfully ordered at least once manually using `cert <name> order`.
Without arguments, ARI (ACME Renewal Information) is used if the CA supports it. Explicit days/% overrides ARI.

Cron: /etc/cron.daily/certx
```bash
#!/bin/sh
MAILTO=admin@example.com
cd /srv/certx
./certx.sh renew-all
```

Systemd timer:
```bash
# /etc/systemd/system/certx.service
[Unit]
Description=Renew SSL certificates
After=network-online.target

[Service]
Type=oneshot
Environment="CERTX_CONF=/etc/certx/certx.conf"
Environment="CERTX_LOG=/var/log/certx/certx.log"
ExecStart=/usr/local/bin/certx.sh renew-all
ExecStartPost=/bin/systemctl reload nginx
```

```bash
# /etc/systemd/system/certx.timer
[Unit]
Description=Renew SSL certificates daily

[Timer]
OnCalendar=daily
Persistent=true

[Install]
WantedBy=timers.target
```

## Other

**Wildcards** need DNS validation:
```bash
./certx.sh cert wildcard '*.example.com,example.com'
```

**Short-lived IP certificate** (6-day cert, hourly renewal recommended):
```bash
./certx.sh ip 203.0.113.1 http /www
./certx.sh cert myip 203.0.113.1 shortlived
./certx.sh cert myip order
```

**Post-deployment hook:**
```bash
./certx.sh cert mycert post_hook "systemctl reload nginx"
```

**Retry failed orders:**
Failed orders leave a order file, that can retried
```bash
./certx.sh retry mycert.order-20260201-120000-12345
```

**Account rollover:**
```bash
./certx.sh account-rollover
```

**EAB** required for Google Trust and ZeroSSL, the script will ask credentials:
```bash
# Google: gcloud publicca external-account-keys create
# ZeroSSL: curl --data 'email=you@ex.com' https://api.zerossl.com/acme/eab-credentials-email
```

**Environment vars:**
```bash
CERTX_CONF=/etc/certx-staging.conf ./certx.sh cert mycert order
CERTX_LOG=/var/log/certx.log ./certx.sh renew-all
```

## Commands

```bash
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
#-   cert [name] chain [N]                      - set alternate cert positional index (1-..)
#-   cert [name] order                          - order and deploy named cert
#-   cert [name] revoke [reason]                - revoke certificate (reason: 0-10, default: 0)
#-   cert [name] drop                           - remove cert configuration
#-   account-rollover                           - change account key
#-   account-deactivate                         - deactivate account
#-   authz-deactivate [url]                     - deactivate authorization
#-   ca-reset                                   - delete all CA/account configuration
#-   renew-all [days|%]                         - renew via ARI or days/% of validity (default: ARI, 20%)
#-   retry [order-file]                         - retry failed order
#-   help [topic]
```

## License

MIT

---

https://github.com/lauriro/certx.sh
