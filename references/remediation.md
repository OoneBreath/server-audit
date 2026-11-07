# Remediation playbook

Fixes happen only after the operator approves a specific list (see SKILL.md). Every change follows
the same loop:

1. **Backup** the file/state with a dated suffix (`cp -a FILE FILE.bak-$(date -u +%Y%m%d-%H%M%S)`),
   and keep backups of secret-bearing files at mode 600 outside web roots and git trees.
2. **Change** the smallest thing that removes the exposure.
3. **Validate** before applying (`sshd -t`, `caddy validate`, `nginx -t`, `docker compose config`).
4. **Apply** (reload rather than restart where the service supports it).
5. **Verify with the same check that found the problem** — outside-in if it was found outside-in.
6. **Record** what changed, where the backup is, and how to roll back.

Order fixes so that the riskiest-to-lockout changes come last, one at a time, with a working
session kept open.

## Lockout-prone changes (SSH, firewall)

- Keep the current SSH session open for the whole change. Test the new state from a **second**
  connection before closing anything.
- Before disabling password auth: confirm that every person and system that logs in has a working
  key (accepted logins in the journal show the method), and that the operator has provider console
  access as a fallback.
- SSH: put the override in the lowest-sorting drop-in so it is read first, e.g.
  `/etc/ssh/sshd_config.d/00-hardening.conf` with `PasswordAuthentication no` and
  `KbdInteractiveAuthentication no` — or fix the drop-in that wins. Then `sshd -t`, then
  `systemctl reload ssh`, then verify `sshd -T | grep -i passwordauthentication` and the outside-in
  probe (auth methods offered: `publickey` only).
- ufw: add the allow rule for SSH before enabling or tightening; `ufw status numbered` and delete
  by number only after reading the live list (rules are often narrower than docs say). For risky
  changes, schedule an automatic rollback first, e.g. `echo "ufw disable" | at now + 10 minutes`,
  and cancel it (`atrm`) after verifying access.

## firewalld (RHEL family)

- Close a stale or unwanted port: `firewall-cmd --zone=public --remove-port=8080/tcp` (runtime, test it),
  then the same with `--permanent` and `firewall-cmd --reload`. Services: `--remove-service=cockpit`.
- Restrict a port to a source instead of opening it to all: a rich rule,
  `firewall-cmd --permanent --zone=public --add-rich-rule='rule family=ipv4 source address=203.0.113.4/32
  port port=5432 protocol=tcp accept'`, and remove the open port.
- Keep the SSH service in the zone while changing anything; runtime first, permanent only after a new
  SSH session works.

## Docker-published ports

- Preferred: bind to loopback in the compose file — `"127.0.0.1:5432:5432"` — then
  `docker compose up -d --no-deps <service>` (recreates only that container). Check that nothing
  outside the host needed the port (look at the proxy config and other hosts first).
- If a port must stay published but only for some sources, filter in the `DOCKER-USER` chain
  (e.g. `iptables -I DOCKER-USER -i <wan-if> -p tcp --dport 5432 ! -s <allowed> -j DROP`) and make it
  persistent (ufw's `after.rules` or a systemd unit) — ufw rules alone do not apply.
- Never recreate a container whose bind-mounted working tree is on a feature branch or has
  unmerged changes: the new container runs whatever is on disk.
- `.env` changes for compose services need `up -d` (recreate); `restart` does not re-read env.

## App servers bound to all interfaces

- Bind to 127.0.0.1 where the process is started (systemd `ExecStart` flags, `gunicorn --bind`,
  `HOSTNAME=127.0.0.1` for Next.js standalone, `--host 127.0.0.1` for uvicorn). Use a systemd
  drop-in (`systemctl edit <unit>`) rather than editing a packaged unit. `daemon-reload`, restart,
  check `ss -tlnp`.
- Admin panels: loopback bind + SSH tunnel (`ssh -L 5000:127.0.0.1:5000 host`) beats an IP allowlist.
- Then remove the now-stale firewall allow rules.

## nginx

- Protect an admin location: `auth_basic "restricted"; auth_basic_user_file /etc/nginx/.htpasswd;` (create
  the file with `htpasswd -B`, mode 640 root:nginx/www-data), or `allow <office-ip>; deny all;`.
  Validate with `nginx -t`, apply with `systemctl reload nginx`, verify outside-in (401/403).
- Directory listing: remove `autoindex on` (or scope it to a location behind auth).
- HTTP → HTTPS: the port-80 block becomes `return 301 https://$host$request_uri;` once TLS works.
- `server_tokens off;` in the `http` block.
- Dotfiles: `location ~ /\.(?!well-known) { deny all; }` in each server that has a `root`.

## Reverse-proxy auth gaps

- Protect by default, open by exception: put the auth on the whole site/upstream and carve out the
  public paths, instead of listing private paths one by one.
- Machine clients (agents, drones, the site's own server-side calls) should use their own
  credentials (tokens in the app, or a separate proxy user) — not the operator's password — and,
  where possible, talk to the upstream over 127.0.0.1 instead of through the public proxy.
- Backup the config, `caddy validate --config /etc/caddy/Caddyfile` (or `nginx -t`), reload, then
  re-run the outside-in URL matrix: private → 401/403, public → 2xx.
- **Caddy sorts directives**: `handle`/`handle_path` run before `respond`, `abort` and `error`, so a bare
  `respond @matcher 403` in a site that uses `handle` blocks is never reached. Put the block in its own
  `handle @matcher { respond 403 }` (first in the site) and prove it with a request from a disallowed source.
- **Testing a `remote_ip` rule from the host itself is a trap**: `curl --interface <docker-bridge-IP>` is
  rewritten by Docker's MASQUERADE to the host's public IP, so the proxy sees the host, not a stranger. Either
  leave the host's own IP out of the allow list (then a self-request through `--resolve name:443:<public-ip>`
  is a valid "foreign" test) or test from another machine.
- CDN origin bypass: if the origin uses a static origin certificate, restrict 80/443 to the CDN's
  published ranges; if it obtains certificates with ACME HTTP-01 on :80, restricting :80 breaks
  renewal — use authenticated origin pulls (mTLS between CDN and origin) or DNS-01 instead.

## Secrets

Rotation order (never revoke first):

1. Create the new secret at the provider (or generate it locally: `openssl rand -base64 32`).
2. Put it where consumers read it (EnvironmentFile 600, `.env` 600, credential store). Find **every**
   consumer first — the fingerprint list from `find_secrets.py` shows copies and reuse.
3. Restart/recreate the consumers; check they authenticate (logs, a health call).
4. Revoke the old secret at the provider.
5. Delete or redact old copies: `.bak` files, deploy backups, shell history lines, archived configs.
   Git history: rotation is what protects you; rewriting history is optional and does not reach
   existing clones.

Rules:
- Do not print secrets while doing this. Write new values with an editor or a command that reads
  from stdin/a file; verify with masked tools; never `cat` the file or `echo` the value.
- Generated credentials the operator must know: write them to a root-only file (600), tell the
  operator the path, and ask them to read and delete it.
- Moving `Environment=` secrets: create `/etc/<name>.env` (root:root 600), reference it with
  `EnvironmentFile=` in a drop-in, remove the `Environment=` lines, `daemon-reload`, restart, and
  confirm `systemctl show -p Environment <unit>` no longer lists them.
- Permissions: `chmod 600` secret files, `chmod 700` their directories and `~/.ssh`, `~/.claude`.

## Persistence and availability

- Anything started with `nohup`/`screen`/an agent shell that must survive a reboot: write a systemd
  unit (`Restart=on-failure`, `User=`, `WorkingDirectory=`, `EnvironmentFile=`), `enable --now`, stop
  the old process, confirm the port is served by the unit (`ss -tlnp`, `systemctl status`).
- Reboot-required: schedule the reboot with the operator (it interrupts every service); check
  afterwards that every expected listener and container is back (compare with the inventory).
- Backups: make the job fail loudly (non-zero exit on empty dump, status file with size, alert on
  missing status), and copy offsite only with the operator's choice of destination — that is data
  leaving the host.

## Backups: restore test and protection from the host itself

**Restore test** (an approved fix like any other; read-only towards live data):

1. Fetch the newest backup into a fresh temporary directory (`mktemp -d`, mode 700), outside web roots
   and git trees. Use the backup tool's own restore (`restic restore`, `borg extract`, `rclone copy`
   from the crypt remote) — never restore over the live paths.
2. Check what came back: archives list cleanly (`tar -tzf`), SQLite passes `PRAGMA integrity_check`,
   PostgreSQL dumps load into a throwaway database (`createdb restore_test && pg_restore -d restore_test`
   or `psql -f`, then a row count on a key table), MySQL dumps into a throwaway schema.
3. Compare with live: row counts or file counts in the same order of magnitude, newest timestamps.
4. Delete the temporary directory and the throwaway database (they hold the same secrets as production).
5. Record the date, backup name, what was checked and the result. Only now is the backup `verified`.

**Offsite copies the host cannot destroy:** credentials that can delete the remote copy should not live
on the host that is being protected. In order of effort: enable provider-side versioning/trash retention
(S3 versioning + object lock; B2: a key without `deleteFiles` and a bucket set to keep all versions — a
lifecycle rule that deletes hidden files turns a write-only key into a delete key; Google Drive trash is not
enough, the same token can empty it); an append-only repository (restic `rest-server --append-only`, borg
`borg serve --append-only` in the server's `authorized_keys`); or a pull-based copy made by another machine
with read-only access to this one. Separate credentials per host, so one compromised host cannot touch the
others' backups.

**Make failures reach a human:** the job exits non-zero on any problem and alerts through a channel the
operator reads daily (mail with a dedicated label that is not auto-archived, a chat webhook, a dead-man
switch such as a healthcheck ping that alerts when the success ping does not arrive). A missing source must
not stop the rest of the backup: back up what is there, alert "partial".

## Disk and logs

- Docker log rotation for new containers: `/etc/docker/daemon.json`
  `{"log-driver": "json-file", "log-opts": {"max-size": "10m", "max-file": "3"}}` → `systemctl reload docker`
  (or restart in a maintenance window). Existing containers keep their old settings until recreated
  (`docker compose up -d --force-recreate <service>`), so recreate only the noisy ones, at a quiet time,
  with the operator. Per service in compose: `logging: {driver: json-file, options: {max-size: "10m",
  max-file: "3"}}`. Do not truncate a live log file without the operator's yes (it destroys evidence).
- journald: `SystemMaxUse=` in `/etc/systemd/journald.conf.d/size.conf`, then
  `systemctl restart systemd-journald`; `journalctl --vacuum-size=` only with the operator's yes.

## DNS and mail authentication

Changes happen at the DNS provider/registrar, not on the host: give the operator the exact records.

- Dangling CNAME: delete the record (or re-create the resource it points to) — today, before someone
  claims it.
- CDN name exposing the origin: switch the record to proxied, then make the origin refuse non-CDN sources
  for that site (remote_ip/allow list, per site — see Reverse-proxy auth gaps).
- SPF: one record per name; end with `-all` (or `~all` with an enforcing DMARC); domains that send no mail:
  `v=spf1 -all`. DMARC: start `p=none; rua=mailto:…` for a week of reports, then `p=quarantine`, then
  `p=reject`; non-mail domains `v=DMARC1; p=reject`. DKIM: 2048-bit keys; rotate by publishing the new
  selector first, switching the signer, then removing the old record after a week.
- CAA: `0 issue "letsencrypt.org"` (plus any other CA actually used) and `0 iodef "mailto:…"`.
  DNSSEC: enable at the DNS provider, then publish the DS record at the registrar.
