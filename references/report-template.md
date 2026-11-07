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

## Not checked / needs the operator
- <yes/no questions: renewal, offsite backup, keys still in use, repo visibility, …>
- <checks skipped and why: not root, no second host for outside-in, consent needed (mail relay)>

## Proposed fix plan
1. <low-risk fixes first> …
n. <lockout-prone fixes last, one at a time>
Waiting for approval — nothing has been changed.
```

Optional `findings.json` next to the report (mode 600, same leak check), for dashboards and for
tracking status across audits — one object per finding, no secret values, no fingerprints:

```json
{"host": "<hostname>", "date": "YYYY-MM-DD", "skill_version": "0.3.1",
 "findings": [{"id": 1, "title": "…", "severity": "HIGH", "confidence": "verified-outside",
               "area": "exposure", "status": "open", "path": "A"}],
 "backup_ladder": {"exists": true, "fresh": true, "offsite": false, "encrypted": null,
                  "deletable_from_host": null, "restore_tested": null}}
```

Chat summary (the reply to the operator, not the file): the top findings with severity in one line
each, the questions for the operator, the path to the report, and the question "which fixes should I
apply?". No secret values, no full config dumps.
