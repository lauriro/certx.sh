# certx.sh

Simple ACME v2 client for green certificates.
Just a shell script - requires curl, openssl, and standard Unix utilities (sed, sort, etc.).

Works with Let's Encrypt, Google Trust, ZeroSSL.
Supports DNS (manual/Cloudflare/hooks), HTTP validation.
Can deploy certs to multiple servers via SSH.
CA-friendly: creates one account and reuses it for all certificates.

## Quick Start

```bash
curl -JO certx.sh
chmod +x certx.sh
./certx.sh domain example.com dns manual
./certx.sh cert mycert example.com,www.example.com
./certx.sh cert mycert order
# Files: mycert.key, mycert.crt
```

On first run it'll ask for CA URL (use `https://acme-v02.api.letsencrypt.org/directory` for Let's Encrypt) and optional email. The account is automatically created once and registered with the CA, then reused for all future certificate orders and renewals.

## Challenge Methods

**Manual DNS** - interactive only, prompts you to add TXT record:
```bash
./certx.sh domain example.com dns manual
```

**Cloudflare** - automated via API:
```bash
./certx.sh domain example.com dns cloudflare YOUR-API-TOKEN
```

**HTTP** - writes challenge file to webroot (supports ssh://, needs key login for automation):
```bash
./certx.sh domain example.com http /var/www/html
./certx.sh domain example.com http ssh://server/var/www/html
```

Note: Webroot directory `/.well-known/acme-challenge/` should exist and be accessible via HTTP.

## Deployment

Deploy certs to multiple locations (local, SSH, or FTP):

```bash
./certx.sh cert mycert key_path /etc/ssl/private/key
./certx.sh cert mycert crt_path /etc/ssl/certs/cert,ssh://server1/etc/ssl/cert,ftp://user:pass@host/etc/ssl/cert

# Happens automatically after cert order/renewal
```

## Renewal

```bash
./certx.sh cert mycert renew              # renew one
./certx.sh renew-all                      # renew all expiring within 15 days
./certx.sh renew-all 30                   # renew all expiring within 30 days
```

Note: `renew-all` only works for certificates that have been successfully ordered at least once manually using `cert <name> order`.

Add to cron for auto-renewal, rely on cron's built-in MAILTO for failure notification:
```bash
# /etc/cron.daily/certx
#!/bin/sh
MAILTO=admin@example.com
cd /srv/certx
./certx.sh renew-all
```

Or use systemd timer (recommended for system-wide deployment):

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

Setup:
```bash
# Install script
sudo cp certx.sh /usr/local/bin/
sudo chmod +x /usr/local/bin/certx.sh

# Create directories
sudo mkdir -p /etc/certx /var/log/certx

# Configure (interactive or copy existing certx.conf)
sudo CERTX_CONF=/etc/certx/certx.conf /usr/local/bin/certx.sh domain example.com dns manual
sudo CERTX_CONF=/etc/certx/certx.conf /usr/local/bin/certx.sh cert mycert example.com
sudo CERTX_CONF=/etc/certx/certx.conf /usr/local/bin/certx.sh cert mycert order

# Enable timer
sudo systemctl enable --now certx.timer
sudo systemctl status certx.timer

# Test run
sudo systemctl start certx.service
sudo journalctl -u certx.service -f
```

## Other Stuff

**Wildcards** need DNS validation:
```bash
./certx.sh cert wildcard "*.example.com,example.com"
```

**Post-deployment hook** to reload services:
```bash
./certx.sh cert mycert post_hook "systemctl reload nginx"
```

**Change CA** - edit `certx.conf` and set `_ca`:
```
# Let's Encrypt
_ca = https://acme-v02.api.letsencrypt.org/directory          # production
_ca = https://acme-staging-v02.api.letsencrypt.org/directory  # staging

# Google Trust Services (requires EAB)
_ca = https://dv.acme-v02.api.pki.goog/directory              # production
_ca = https://dv.acme-v02.test-api.pki.goog/directory         # test

# ZeroSSL (requires EAB)
_ca = https://acme.zerossl.com/v2/DV90                        # production
```

**Custom DNS hooks** for other providers:
```bash
# Create hook script: ./dns-PROVIDER.sh
# Hook must output cleanup commands to stdout (send logs to stderr if needed)
# Example: Get Cloudflare hook
curl -JO certx.sh/dns-cloudflare.sh && chmod +x dns-cloudflare.sh
./certx.sh domain example.com dns cloudflare YOUR-API-TOKEN

# Example: Custom provider
./certx.sh domain example.com dns myprovider YOUR-ARGS

# For help on writing hooks:
./certx.sh help dns
```

**Retry failed orders** - if an order fails, you can retry it later:
```bash
./certx.sh retry mycert.order-20260201-120000-12345
```

**Account rollover** - change your account key (useful for key rotation):
```bash
./certx.sh account-rollover
```

**External Account Binding (EAB)** - required for Google Trust Services and ZeroSSL:

For Google, get EAB credentials:
```bash
# In Google Cloud Shell
gcloud publicca external-account-keys create
```

For ZeroSSL:
```bash
curl --data 'email=your@email.com' https://api.zerossl.com/acme/eab-credentials-email
```

The script will prompt for EAB key ID and HMAC when registering with CAs that require it.

**Config** - all settings stored in simple text file `certx.conf` with key=value pairs. Safe to edit manually. Contains account keys, domain configs, cert settings. Use different config files for different CAs.

**Environment vars:**
```bash
CERTX_CONF=/etc/certx-staging.conf ./certx.sh cert mycert order  # staging CA
CERTX_CONF=/etc/certx-prod.conf ./certx.sh cert mycert order     # production CA
CERTX_LOG=/var/log/certx.log ./certx.sh renew-all
```

## Commands

```bash
# Domains
domain <name> dns manual|cloudflare TOKEN
domain <name> http /webroot
domain <name> drop
domain                             # list all

# Certificates
cert <name> <domains>              # set domains
cert <name> order|renew
cert <name> key_path <paths>       # local or ssh://
cert <name> crt_path <paths>
cert <name> post_hook <command>
cert <name> drop
cert                               # list all

# Renewal
renew-all [days]                   # default: 15 days
retry <order-file>                 # retry failed order

# Account Management
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
