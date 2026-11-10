# Changelog

## 0.5.0 (unreleased)

- **`findings.json` is a contract.** It is required in a full audit, next to `report.md` and with the
  same ids, severities and statuses, and it is checked before the chat summary.
  - **The schema.** `references/findings-schema.json` documents it; nothing loads it at run time. It
    adds `mode`, `run_dir`, `rejected[]` (dropped false positives, so the drop is explicit),
    `not_checked[]`, and per finding: `reachability`, `impact`, `evidence[]` (command, observation,
    inside/outside), `confirm_by` and `verifier`.
  - **The validator.** `scripts/validate_findings.py`, stdlib only, no network, writes nothing. It
    checks that:
    - severity matches the reachability × impact table: the MEDIUM–HIGH cell accepts both, one level
      off needs `adjust_reason`, two levels off is never valid, and a hardening gap that needs root
      is INFO only;
    - `confirm_by` is present for inferred or partial findings;
    - ids are unique across findings and rejected;
    - an attack path joins at least two findings;
    - `restore_tested: true` comes with a restore in the evidence;
    - no string carries a secret (secretlib) or a fingerprint (`fp=`, `xfp=`). Masked forms such as
      `<REDACTED>` pass.
    
    Exit 0 = valid, 1 = invalid (`path: message`), 2 = unreadable; `--quiet`.
  - **Docs and tests.** `report-template.md` now points to the schema and has one minimal valid
    example, which a test checks. Tests are in `tests/test_v050_units.py`, and the script is in
    `test_invariants`.
- CI: the Python 3.9 unit job runs on `ubuntu-24.04`. setup-python has no 3.9 for `ubuntu-latest` (now
  Ubuntu 26.04), so the next run on the old matrix would have failed before any test ran.

## 0.4.4: one finding per missed run, the firewall behind a root app

Released 8 November 2026. From a re-run of the 0.4.3 field audit.

- **A missed backup run is reported once.** A job that writes its own log and whose output cron also
  redirects to a second log showed the same hole twice. Holes that overlap across logs are now one
  candidate that names every log ("nightly-backup.log and cron.log show no success between …");
  different holes stay separate.
- **A root web app names what ufw lets reach it.** For an app bound to a public address, the candidate now
  says when ufw admits the port only from some sources ("ufw admits port 8500 only from 203.0.113.7, not
  from the whole internet"), or from nowhere outside, so the rating can account for the compensating
  control. A port the reverse proxy forwards to is still reported as internet-reachable. Rules with a v6
  source count only for sockets that accept IPv6. `--only web` now reads ufw too.

## 0.4.3: missed backups, a faster secret scan, less noise

Released 8 November 2026. From a field audit of a single-operator host (root, Caddy, an rclone offsite
backup), where every candidate was checked by hand.

- **A missed backup run is reported.** When the host is off at backup time the job never starts: no error,
  no failure mail, and a staleness check that fires after 36 h sees nothing once the next night succeeds.
  The inventory now reads each backup log's success lines, learns the usual interval (the median gap) and
  reports gaps longer than 1.5 times that interval in the last 45 days ("a missed backup run went
  unnoticed"), with the downtime from `last -x` that explains the gap.
- **Shutdowns that came from outside the guest** (`systemd-logind: System is powering down (hypervisor
  initiated shutdown)`, `qemu-ga: guest-shutdown called`, an ACPI power-button event) are an availability
  event of their own, with the time the host came back; downtimes of an hour or more are listed in HOST.
- **The secret scan is several times faster.** The assignment pattern backtracked quadratically on a quoted
  value that never meets its closing quote (base64 in a long transcript line): seconds per line, most of the
  run on a host with large agent transcripts. It is rewritten to match the same values in linear time (a
  regression test keeps it there). On a test host the full scan (`--git-history --transcripts`) went from
  401 s to 83 s with the same findings.
- **Package caches, SDKs and editor servers are skipped by default**: `~/.pub-cache`, `~/.gradle`, `~/.m2`,
  `~/.cargo/registry`, Flutter and Android SDKs (recognised by their contents, so a project called `flutter`
  is still scanned), `~/.vscode-server`, `~/.cursor-server`, `~/.windsurf-server` and similar. In the field
  audit they produced over 90% of the 3800 hits. The credential files next to them stay in the scan
  (`~/.pub-cache/credentials.json`, `~/.gradle/gradle.properties`, `~/.m2/settings.xml`,
  `~/.cargo/credentials.toml`); `--include-caches` scans everything, and a cache named on the command line is
  scanned.
- find_secrets: progress on stderr (`scanning <root> (n/N)…`, a heartbeat every 15 s, the git history of each
  repo, `done in N s`; `--quiet` turns it off), `--max-seconds N` (a partial report that says what was not
  scanned), `--since 30d` (recent transcripts and agent histories only). SKILL.md: run the scan in the
  background.
- **Fewer false OpenAI keys, no nested masks.** `sk-` inside a longer word (`…disk-…`, another vendor's
  `ctx7sk-…`) is no longer an OpenAI key; a Context7 key has its own type. A value already partly masked is
  not masked again, so lines no longer read `<REDACTED len=13 …> len=35 …>`.
- **Root-run paths writable only by passwordless sudoers are one INFO note.** When every account that can
  write a root service's script or directory (or a root cron target) already has `NOPASSWD: ALL`, that is no
  escalation path; the paths are listed in one `note (INFO)` line instead of one candidate each.
- **A web-facing app running as root** (gunicorn, uvicorn, node, java, php, … on a public address or behind
  the reverse proxy) is its own candidate: a remote-code-execution bug in it is root on the host.
- **World-readable databases and dumps are one line.** With no one but root and the operator logging in
  (login shells with uid ≥ 1000), it is a `note (LOW)` naming the service accounts that can still read them.
- **Stale sudo rules**: a rule for a user or group that does not exist is reported as LOW ("would grant its
  rights to whoever creates that account later — delete the rule"), no longer as root-equivalent.
- **ufw rules for a Docker bridge subnet** on a host without Docker say so ("Docker is not installed —
  nothing uses this rule, delete it").
- **Partial runs**: `--only firewall` no longer reports every ufw rule as stale (the listener table is now
  collected quietly first); `services`, `cron` and `web` also collect what they depend on.
- **Drift**: one header line that names the baseline (`Changes since <run> (collected …) — N`), instead of a
  header plus a separate baseline line.
- **Container labels and arguments are masked when read.** Traefik's Docker labels and container arguments
  were read unmasked (masking would break their JSON) and parsed as is; every value is now masked right after
  parsing, and Podman's container fields too. A test feeds secret-bearing labels and arguments through the
  Traefik section and checks that none reaches the inventory or the state.
- Labs: a sudo rule for a deleted account (Ubuntu), an offsite log with a missed night (RHEL).

## 0.4.2: Caddy wildcards, .htaccess, CDN caches, steady drift

Released 7 November 2026. From the written feedback of a v0.3.1 audit of a production host.
Its first four points (translation keys and prose read as secrets, `fail=0` read as a failure, a stopped
container reported as publishing a port) were already fixed in 0.3.2.

- **Drift no longer reports the same secret as removed and added.** Candidate texts carried the per-run
  fingerprint, so a secret in process arguments changed on every run. Fingerprints are stripped from the
  state (older baselines are cleaned when read); secrets are compared by key name and length. A stable
  per-host salt was not used on purpose: a key kept next to the fingerprints makes them testable offline
  with guessed passwords.
- **Caddy path patterns with a `*` inside** (new candidate). Tested on Caddy 2.11: such a pattern is a
  glob where every `*` matches one path segment, so `/a/*/b/*` matches `/a/x/b/y` but not `/a/x/b/y/z`. An
  auth rule written that way passes a shallow test and leaves deeper paths open. Patterns that also end in
  `*` are candidates; the REST shape `/items/*/verify` is a note.
- **`.htaccess` under Caddy or nginx** (new candidate): directories a PHP app protects only with
  `.htaccess` deny rules (`Deny from all`, `Require all denied`, `RedirectMatch 403`, `RewriteRule … [F]`)
  are served by Caddy and nginx. Directories the proxy config already names are a note.
- **`probe_external.sh` notices CDN caches**: a URL answered with `cf-cache-status: HIT` (or `x-cache`,
  `age`) gets a note, and for hostnames given with `--cdn` the origin is asked directly, so "the fix does not
  work" and "the CDN still serves the old answer" can be told apart.
- remediation.md: Caddy wildcard rules and `path_regexp`, verify a fix at the origin before purging the CDN
  cache, blocking a PHP app's internal directories in Caddy and nginx.
- Labs: a PHP webmail under nginx with `.htaccess`-only protection (RHEL), a CDN edge stand-in that serves a
  cached 200 (Ubuntu).

## 0.4.1: fixes from a field audit

Released 7 November 2026. Reported after a v0.3.1 audit of a production host, where the agent
had to drop three of the skill's candidates by hand.

- **Backups run through a relative script were missed.** A crontab line such as `cd ~/backup &&
  flock -n /tmp/b.lock python3 backup.py` names no absolute script, so the inventory never read
  `backup.py` (an offsite copy and an alert on failure) and reported "backups exist
  only on this host" and "failures alert nobody". Jobs now resolve scripts the way cron does: after `cd
  DIR`, and in the home of the user the line runs as (`./run.sh`, `~/…`, `$HOME/…`). The same applies to
  "root cron runs a script writable by non-root".
- **Leftover certificates**: Caddy keeps every certificate it ever issued. An expiring or expired one for a
  name no current site config (Caddy, nginx, Traefik) serves is now a note ("a leftover in the store"),
  not a candidate.
- **"Readable by every local user" says who that is**: the accounts that run network services, apps on
  127.0.0.1 behind the reverse proxy included. On a host with one human user these files are still read by
  a hole in any of those services, so the candidate is not noise.
- Lab: the RHEL lab's offsite job runs as `cd /usr/local/sbin && ./shop-offsite.sh`.

## 0.4.0: several servers, Podman, Traefik, HAProxy

Released 7 November 2026.

- **`fleet.py`** compares the runs of several hosts on the operator's machine (it connects nowhere): hosts
  at a glance (OS, end of support, pending security updates, reboot, automatic updates, firewall), hosts
  lagging behind the others, sshd settings that differ, the same SSH key on several hosts, ports open on
  some hosts only, every backup ladder in one table, candidates shared by several hosts.
- **The same secret on several hosts**: `fleet.py key` makes a comparison key for one round;
  `find_secrets.py --fleet-key-stdin` reads it on stdin (never argv, never a file on the host) and adds
  `xfp=` fingerprints that match across hosts, plus the key's id so mixed keys are detected. Delete the
  key after the comparison.
- **Traefik**: routers from the static file, CLI flags (systemd or the container's args), the file provider
  and Docker labels, with paths inside a Traefik container mapped to the host files mounted there. Flags
  `api.insecure`, admin-like routers and the dashboard without an auth middleware (also through chains;
  middlewares defined elsewhere count as unknown, not missing), routers on plain HTTP only.
- **HAProxy**: the runtime API on the network (`stats socket` on an address, `level admin`), stats pages
  without auth (and with `stats admin`), admin-like routes without `http-request auth/deny`, plain-HTTP
  frontends, `insecure-password` in userlists, world-readable configs holding passwords.
- **Podman**: rootful containers (ports on all interfaces, privileged, engine socket and host mounts,
  stopped ones as stopped), the rootful API socket, quadlets rootful and rootless, rootless ports from the
  listener table, users with linger. CI runs it against a real engine.
- **Secrets**: HAProxy `insecure-password` and `stats auth`, `$apr1$` hashes (htpasswd, Traefik basicAuth).
  Private keys are fingerprinted by their body, not their header: before, every key looked like the same
  value in "values found in more than one place". Commented-out weak defaults (`# input_password =
  secret`), config references (`$section::name`) and OpenSSL's CMP demo secret are no longer hits.
- `state.json` has a `_fleet` section (end of support, security updates, reboot, automatic updates),
  skipped by drift so moving counts are no noise.
- Labs: Traefik in `lab/ubuntu`, HAProxy in `lab/rhel`; the end-to-end test compares both labs with
  `fleet.py` and finds a secret planted on both.

## 0.3.2: fixes from a real audit

Released 7 November 2026. Reported by an operator after a full audit of a production host
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
