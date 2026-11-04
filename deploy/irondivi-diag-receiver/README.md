# `irondivi-diag-receiver` Deployment (`diag.irondivi.com`)

Production deployment artifacts for the `docs/plans/diag.md` §9 Flight Recorder diagnostic package receiver.

## Architecture & Privacy Model

- **Public endpoint**: `https://diag.irondivi.com` (`15.204.117.157`, `dnsdivi`, plain OVH VM with direct nginx TLS termination — no CDN or managed load balancer).
- **TLS**: Let's Encrypt ECDSA certificate via webroot (`/var/www/acme`), TLSv1.2 / TLSv1.3.
- **Reverse proxy** ([nginx-diag.irondivi.com.conf](./nginx-diag.irondivi.com.conf)):
  - `access_log off;` and `error_log /var/log/nginx/diag.irondivi.com.error.log emerg;` (suppresses per-connection error logging that would include client IPs).
  - `proxy_request_buffering off;` and `proxy_buffering off;` so nginx streams encrypted bodies straight to the receiver without writing temporary body files to disk.
  - `client_max_body_size 110m;` outer cap in front of the receiver's 100 MiB package cap.
  - Forwards `$remote_addr` in `X-Diag-Peer` for the receiver's ephemeral in-memory salted-hash rate limiter (`10` uploads/hour, `1 GB`/day) and strips `X-Forwarded-For` / `X-Real-IP`.
- **Service** ([irondivi-diag-receiver.service](./irondivi-diag-receiver.service)):
  - Runs as unprivileged system user `irondivi-diag` bound strictly to `127.0.0.1:8795`.
  - Stores `<TICKET>.age` and `<TICKET>.meta` (`size`, `sha256`, `arrived`) in `/var/lib/irondivi-diag` (`0700`, `UMask=0077`), swept hourly with a 90-day retention cap.
  - Developer routes (`GET /v1/dev`, `GET /v1/dev/<ticket>`, `DELETE /v1/dev/<ticket>`) authenticate via constant-time comparison against `/etc/irondivi-diag/token.sha256` passed via systemd `LoadCredential=`.

## Secrets (1Password via `secret get` — Never On Disk or CLI Argv)

- **Developer `age` private identity**: `op://global_secret_store/irondivi_diag/age_identity` (public recipient `age10r8rlmzg5c3n8c0cslzzpa9vjq879pq32fghv2skmfu3twzl4vmqt7lq0j`, fingerprint `9274ffc0368679fe` in `crates/divi-diag/src/consent.rs`).
- **Developer download bearer token**: `op://global_secret_store/irondivi_diag_receiver/download_token` (only its hex SHA-256 digest is stored on `dnsdivi` at `/etc/irondivi-diag/token.sha256`).

## Build & Rollout (on `hp1` -> `dnsdivi`)

```sh
# 1. Build release binaries on hp1 (never on macOS):
ssh hp1 '. ~/.cargo/env && cargo test --release -p irondivi-diag-receiver && cargo build --release -p irondivi-diag-receiver'

# 2. Install binary on dnsdivi with rollback backup and restart service:
sudo cp -a /usr/local/bin/irondivi-diag-receiver /usr/local/bin/irondivi-diag-receiver.bak
sudo install -m 0755 irondivi-diag-receiver /usr/local/bin/irondivi-diag-receiver
sudo systemctl restart irondivi-diag-receiver
systemctl is-active irondivi-diag-receiver

# 3. Install/update nginx config and reload:
sudo cp -a /etc/nginx/sites-available/diag.irondivi.com /etc/nginx/sites-available/diag.irondivi.com.bak
sudo cp nginx-diag.irondivi.com.conf /etc/nginx/sites-available/diag.irondivi.com
sudo nginx -t && sudo systemctl reload nginx
```

## Developer Ticket Workflow

```sh
# List waiting tickets:
irondivi-diag-open --list

# Download, verify SHA-256, decrypt, unpack (0700 dir), and verify 02-manifest.txt:
irondivi-diag-open <TICKET> --out /tmp/diag-<TICKET>

# Close and delete a ticket from the receiver:
irondivi-diag-open --close <TICKET>
```
