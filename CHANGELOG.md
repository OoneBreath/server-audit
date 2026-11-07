# Changelog

## 0.3.2: fixes from a real audit

Released 7 November 2026. Reported by an operator after a full audit of a production Ubuntu 22.04 host
(1819 secret-scan hits, mostly noise).

- **find_secrets on web apps**: translation and UI strings are no longer secrets (`"forgot_password":
  "Forgot password?"`, `confirm_password`, `password_label: "Passwort"`, `token_expired: "Expired"`, any
  text value with a space that names the secret itself, like "Your password"). A real value under the same
  keys (`NEW_PASSWORD=Xk29-…`) is still found.
- **Prose files** (`.md`, `.txt`, `.rst`, `.adoc`): `key = value` counts only at the start of a line or a
  list item, so a sentence such as "the guessed password = root" is not a leak.
- **The skill's own outputs** (`~/.server-audit/`) are skipped while walking directories: they are masked
  and already leak-checked. Naming a file explicitly still scans it, so the check before a report leaves
  the host works as before.
- **Backup status lines**: zero counters (`fail=0`, `errors: 0`, `0 failed`) are success, not a problem.
- **Stopped containers** are reported as stopped ("stopped container X (Exited (0) 9 months ago; risk only
  when started)"), with the ports they would publish on all interfaces when started. They no longer count
  for memory limits, log growth or unpinned images, and the inventory lists them for clean-up.

## 0.3.1: backups that survive the host, fewer false alarms

Released 7 November 2026.

- **Can the offsite backup be deleted from this host?** A new rung in the backup ladder,
  `deletable_from_host`. `yes` when the job itself prunes or deletes offsite data (restic forget/prune,
  borg prune/compact, rclone delete/purge/cleanup, aws s3 rm, duplicity remove-*) or the rclone remote is
  a Drive-like token, also under a crypt remote. `unknown` for buckets, restic `rest:`/`sftp:` and borg over
  SSH, with what to check: for B2, the key's capabilities and lifecycle rules (a rule that deletes hidden
  files lets a write-only key delete; thanks to the `b2-key-check` in mattabate/life-distributable for
  that point); for S3, versioning, Object Lock and the IAM policy.
- **Jobs that mirror deletions offsite** (`rclone sync` without `--backup-dir`, `rsync --delete` to
  another host, `aws s3 sync --delete`) are flagged: ransomware here becomes ransomware there.
- **find_secrets on source trees**: 30 false hits on a real open-source repo dropped to 2 true ones.
  No longer reported: `fetch()` options (`credentials: 'same-origin'`), status words (`unknown`), shell
  expansions (`$(cat …)`, `` `cmd` ``, `"$DIR/.token"`), keys that describe a secret (`TOKEN_FILE`,
  `SESSION_TOKEN_TTL`), calls and indexes (`token=auth["…"]`), ternaries (`ok ? 'PASS' : 'FAIL'`),
  `date -u +%Y…` read as curl's `-u USER:PASSWORD`. Test files by name (`_test.go`, `test_*.py`, `*.spec.ts`,
  `*Tests.swift`) count as examples. Public-by-design keys (PostHog `phc_`, Stripe `pk_`, Mapbox `pk.`)
  are counted, not listed. Masking is unchanged: these lines are still redacted in inventories.
- **`--only backups` was wrong**: the cron jobs it relies on come from the cron section, which a partial
  run skipped, so it reported "backups exist only on this host" and a stale backup. Sections a partial run
  depends on now run quietly (no output, no candidates, no state).
- **Drift noise**: a backup timer's last start time, PID and exit status no longer count as a change;
  `dpkg-db-backup.timer` (the distribution's own housekeeping) is no longer a backup job.
- Lab: the RHEL lab has an rclone crypt-over-Drive offsite copy synced with `rclone sync`.

## 0.3.0: beyond Ubuntu and Caddy

Released 6 November 2026.

- **nginx** is parsed like Caddy: every server block with its names, `listen`, protection
  (`auth_basic`, `auth_request`, allow/deny) and the locations that serve content without it. Flags
  admin-like paths and admin-like sites without proxy-level auth, `autoindex`, plain-HTTP blocks that do
  not redirect, HTTP-only sites. `nginx -T` prints included files separately; server blocks from
  `sites-enabled`/`conf.d` are handled at the top level of their file.
- **Apache**: `Options Indexes` and `server-status`/`server-info` without `Require local/ip`.
- **RHEL family** (RHEL, Rocky, AlmaLinux, Oracle Linux, CentOS Stream): dnf security advisories from
  the local cache (the audit never downloads metadata), `needs-restarting -r`, dnf-automatic, firewalld
  zones with open services/ports and stale ports, SELinux mode, rpm ownership of SUID binaries,
  end-of-support dates (major release).
- **No host firewall at all** is flagged on any distribution (no active ufw/firewalld and an empty
  ACCEPT INPUT chain).
- **Machine-readable output**: `diff_state.py --json --exit-code`, `collect.py --fail-on-drift` for a
  nightly drift check without an agent, and an optional `findings.json` next to the report.
- **Second lab**: `lab/rhel` (AlmaLinux 9 + nginx); `lab/` moved to `lab/ubuntu`. CI runs the unit tests
  and both labs end to end.
- Open-source housekeeping: LICENSE (MIT), CONTRIBUTING, ROADMAP, vulnerability reporting in SECURITY,
  test fixtures without names from any real deployment.

## 0.2.0: drift, backups, DNS

Released 6 November 2026, from operator feedback and three external reviews.

- Drift: `state.json` per run, changes since the previous audit at the top of the inventory,
  `diff_state.py` for any two runs.
- Backups: the ladder (exists → fresh → offsite → encrypted → restore-tested), offsite credentials on the
  host, alerts, last status in the job's log, jobs found through the script they run. Restore-test
  procedure in the playbook.
- New checks: disk and inodes, container logs without limits, databases on public addresses, Cloudflare
  Tunnel/WireGuard/Tailscale, host paths mounted into containers, unpinned images, registry credentials,
  dormant accounts, system accounts with a shell, end of OS support, text addressed to AI agents.
- `dns_check.py` (SPF, DMARC, DKIM, CAA, DNSSEC, dangling CNAMEs, origin exposure) and IPv6 in the probe.
- Report: attack paths, `verified-partial` and `not-checked`, backup ladder, drift section.
- Lab container and end-to-end test; Quickstart and "What is checked" in the README.
- Fixes: cron jobs that call a backup script were not recognised as backups; Debian's `/var/backups`
  was counted as a scheduled backup; registry credentials were only checked where the Docker engine is
  installed; `auth`/`identitytoken` keys are now masked.

## 0.1.3

- Glued secret key names (`PGPASSWORD`, `SMTPPASSWORD`, `CSRFTOKEN`, `REDISCLI_AUTH`, …) were neither
  detected nor masked. Found by a lab audit, where the agent caught the miss by hand.

## 0.1.2

- Caddy runs `handle`/`handle_path` before `respond`, so block with `handle @matcher { respond 403 }`.
- `remote_ip` tests from the host are invalid behind Docker MASQUERADE.
- A per-site CDN-only rule for when port 443 has to stay open for other sites.

## 0.1.1: lessons from the first real audit

- No `$1` in the SKILL.md body (Claude Code substitutes skill arguments there).
- Agent prompt histories are tagged `TRANSCRIPT`.
- Fixture paths in git history count as examples.
- A constant holding its own name is not a secret.
- New checks: CrowdSec without a bouncer is detection only; public FastAPI `/docs` and `/openapi.json`;
  proxy site blocks without DNS.

## 0.1.0

- Read-only masked inventory, secret locator, outside-in probe.
- Check catalogue, remediation playbook, report template.
- Tests, including the read-only and no-network invariants.
