# Report template

Write the report in the operator's language. Save it next to the inventory as `report.md`
(mode 600). It describes weaknesses of a live system: do not commit it to a public repository,
publish it, or paste it into third-party tools. Before saving or sharing, run
`find_secrets.py report.md` — it must report 0 hits.

```markdown
# Server audit — <hostname> (<public IP>) — <YYYY-MM-DD>

Scope: <this host only | + outside-in from HOST> · Run as: <root|user> · Duration: <…>
Method: read-only inventory, secret scan (<paths>, git history: yes/no, transcripts: yes/no),
DNS/mail check (<zones>), outside-in probe from <host/IP> (<yes/no>, IPv6: <yes/no/no route>).
Nothing on the host was changed during the audit.

## Summary
<3–5 sentences: the most important risk in plain words, what is fine, what needs the operator.>
<The line from reconcile.py, e.g. "7 findings checked by an independent verifier: 5 upheld, 1 downgraded,
0 changed, 1 rejected" — or "checked by the same agent in a separate pass (no subagents)".>

| # | Severity | Finding | Confidence |
|---|---|---|---|
| 1 | HIGH | … | verified-outside |
| 2 | MEDIUM | … | verified-inside |

Confidence: `verified-outside` · `verified-inside` · `verified-partial` (say which part) · `inferred`
(say what would confirm it) · `not-checked`.

Backups: exists ✓/✗ · fresh ✓/✗ · offsite ✓/✗ · encrypted ✓/✗ · restore-tested ✓/? — the last one
only from the operator or a restore test done during the fixes.

## Attack paths
### A. <entry> → <escalation> → <impact> — HIGH
Findings #1, #4, #5. <one or two sentences: who starts where, what each step gives them.>
Cheapest link to break: #<n> (<the fix>).

## Changes since the last audit
<From the inventory's drift section: what changed, which changes are explained (fixes, deployments),
and which are not — unexplained ones are findings. "Baseline run" if there was no earlier audit.>

## Findings

### 1. <Short title> — HIGH
- **What:** <the fact, with evidence: file:line, port, command output — no secret values>
- **Why it matters:** <who can do what, from where; the realistic attack in one sentence>
- **Verified by:** <command / probe and its result>
- **Fix:** <smallest change; reference to remediation step; lockout/restart risk>
- **Effort / risk of fix:** <minutes; needs restart of X; lockout risk yes/no>

## What is fine
<Short list of checks that passed and matter: e.g. "SSH keys only from outside", "no unauthenticated
data endpoints", "backups fresh and non-empty".>
<False positives: every item of findings.json `rejected[]`, with its reason — including the ones an
independent verifier rejected.>

## Not checked / needs the operator
- <yes/no questions: renewal, offsite backup, keys still in use, repo visibility, …>
- <checks skipped and why: not root, no second host for outside-in, consent needed (mail relay)>

## Proposed fix plan
1. <low-risk fixes first> …
n. <lockout-prone fixes last, one at a time>
Waiting for approval — nothing has been changed.
```

`findings.json` next to the report (mode 600, same leak check) is required in a full audit: the
machine-readable twin of `report.md`, with the same ids, severities and statuses. Its contract is
[findings-schema.json](findings-schema.json); check it before the chat summary:
`python3 -I <skill>/scripts/validate_findings.py <run>/findings.json` (exit 0 = valid). No secret
values and no fingerprints (`fp=`, `xfp=`); masked forms such as `<REDACTED>` are fine. A minimal
valid example:

```json
{"host": "web1", "date": "2026-11-10", "skill_version": "0.5.0", "run_dir": "~/.server-audit/web1-2026-11-10",
 "mode": "full", "verification": "independent",
 "findings": [
  {"id": 1, "title": "Redis on a public address without auth", "area": "exposure", "severity": "HIGH",
   "confidence": "verified-outside", "status": "open", "path": "A",
   "reachability": "internet-no-auth", "impact": "data-or-control",
   "evidence": [{"command": "ss -tlnp 'sport = :6379'", "observation": "0.0.0.0:6379 redis-server", "where": "inside"},
                {"command": "probe_external.sh 203.0.113.10", "observation": "6379 open, PING answered", "where": "outside"}],
   "verifier": null},
  {"id": 2, "title": "Docker publishes the Redis port past ufw", "area": "exposure", "severity": "MEDIUM",
   "confidence": "verified-inside", "status": "open", "path": "A",
   "reachability": "internet-one-control", "impact": "data-or-control",
   "evidence": [{"command": "iptables -t nat -S DOCKER", "observation": "DNAT tcp dpt:6379", "where": "inside"}],
   "verifier": null}],
 "rejected": [{"id": 3, "title": "Port 8080 open", "reason": "bound to 127.0.0.1 (ss -tlnp)"}],
 "backup_ladder": {"exists": true, "fresh": true, "offsite": false, "encrypted": null,
                   "deletable_from_host": null, "restore_tested": null},
 "not_checked": ["offsite backup copy (needs the operator)"]}
```

Chat summary (the reply to the operator, not the file): the top findings with severity in one line
each, the questions for the operator, the path to the report, and the question "which fixes should I
apply?". No secret values, no full config dumps.
