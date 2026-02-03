# certx.sh

Simple ACME client for green certificates.  
Just a shell script - requires curl, openssl, and standard Unix utilities (sed, sort, etc.).

Works with Let's Encrypt, Google Trust, ZeroSSL.  
Supports DNS/HTTP validation, account rollover, EAB, ARI, IP certs, and multi-server deployment via SSH/FTP.  
CA-friendly: creates one account and reuses it for all certificates.  


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

# DNS - automated via provider hook
./certx.sh domain example.com dns cloudflare TOKEN
./certx.sh domain example.com dns digitalocean TOKEN
./certx.sh domain example.com dns linode TOKEN

# HTTP - writes challenge file to webroot (supports ssh://, needs key login for automation)
# Note: Webroot directory `/.well-known/acme-challenge/` should exist and be accessible via HTTP.
./certx.sh domain example.com http /www
./certx.sh domain example.com http ssh://server/www

# IP - only HTTP validation, can mix with domains
./certx.sh ip 203.0.113.1 http ssh://203.0.113.1/www
./certx.sh cert mycert example.com,203.0.113.1
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
./certx.sh cert mycert renew              # force renew one
./certx.sh renew-all                      # renew all expiring within 15 days
./certx.sh renew-all 30                   # renew all expiring within 30 days
```

Note: `renew-all` only works for certificates that have been successfully ordered at least once manually using `cert <name> order`.
If the CA supports ARI (ACME Renewal Information), `renew-all` uses the CA's suggested renewal window instead of the days-based check.

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
ExecStart=/usr/local/bin/certx.sh renew-all 30
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

**DNS hooks**
```bash
# Available: cloudflare, digitalocean, linode, zone.eu
curl -O certx.sh/dns-PROVIDER.sh && chmod +x dns-PROVIDER.sh
./certx.sh domain example.com dns PROVIDER YOUR-API-TOKEN
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
# Domains
domain <name> dns manual|PROVIDER TOKEN
domain <name> http /webroot
domain <name> drop
domain                             # list all

# IP addresses
ip <addr> http /webroot
ip <addr> drop
ip                                 # list all

# Certificates
cert <name> <domains,ips>          # set identifiers
cert <name> order
cert <name> key_path <paths>       # local, ssh://, or ftp://
cert <name> crt_path <paths>
cert <name> post_hook <command>
cert <name> drop
cert                               # list all

# Renewal
renew-all [days]                   # default: 15 days
retry <order-file>                 # retry failed order

# Account
account-rollover                   # change account key
account-deactivate                 # deactivate account
authz-deactivate <url>             # deactivate authorization
ca-reset                           # delete all CA configuration

# Help
help [topic]
```

## License

MIT

---

https://github.com/lauriro/certx.sh
