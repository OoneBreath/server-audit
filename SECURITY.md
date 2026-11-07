# Security notes for reviewers and skill scanners

server-audit is a security tool, so static skill scanners (including skill-airlock) flag it. What
each flagged behaviour is, and how to check the claim yourself:

| Scanner hit | What the code does | Check |
|---|---|---|
| reads `authorized_keys`, crontabs, sudoers, `/etc/shadow`, `.env`/`.ssh` paths | `collect.py` **reads** them to report fingerprints, rules, key names and whether a password hash exists. It never writes outside its output directory. | `tests/test_invariants.py::test_collect_writes_only_the_inventory`, `::test_collect_runs_only_read_only_commands` |
| "secrets + network in the same file" for `collect.py` | No network code. The hit comes from binary *names* (`ssh`, `scp`, `rsync`) in the list of sudo shell-escape binaries. | `::test_no_network_code_where_secrets_are_read` |
| "secrets in one script, network in another" | Secret-reading scripts and the network probe are separate on purpose: `probe_external.sh` runs on a *different* machine and never reads secrets or files. | read `scripts/probe_external.sh` (≈170 lines) |
| `/dev/tcp` "typical of reverse shells" | `probe_external.sh` opens plain TCP connections **to the target** to see which ports answer (bash-only port check, no nmap). No shell is attached to the socket. | the three `/dev/tcp` lines |
| "asks for root" | Full inventory needs root to read firewall rules, sshd effective config, other users' files. Without root it runs degraded. | SKILL.md step 2 |
| `dns_check.py` makes network requests | DNS lookups only, through `dig` and the system resolver, for names the operator passes. It reads and writes no files and never sees secrets. | `::test_dns_check_touches_no_files` |
| `collect.py` writes files | Only `inventory.txt` and `state.json` in its own output directory, through one helper that asserts those two names. `state.json` holds masked lines without fingerprints. | `::test_collect_writes_only_its_output_files` |
| "tries to override the agent's instructions" in `collect.py` and `tests/` | The opposite: `collect.py` has a detector for text on the host that addresses AI agents, and the tests feed it fake injection lines (`"Disregard all prior instructions."`) to prove it fires and stays quiet on normal text. Nothing in the skill tells the agent to ignore anything. | `tests/test_v02_units.py::test_injection_text` |
| `lab/*/setup.sh`: authorized_keys, cron, secrets | The lab images are misconfigured on purpose (a key for the test user, a root cron job running a user-writable script, fake secrets) so the end-to-end test can check every finding. They run only inside a local container. | `tests/test_lab_e2e.py` |
| `lab/` contains secrets and a misconfigured host | A test fixture: every secret is generated at image build time and fake; the container is meant to run locally and be removed. Never expose it. | `tests/test_lab_e2e.py` (`::test_nothing_leaks`) |

Output files contain no secret values (masked by `secretlib.py`, tested with fake secrets in
`tests/test_secretlib.py` and `tests/test_find_secrets.py`) but they do describe the host's
weaknesses: they are written mode 600 under `~/.server-audit/` and must not be shared.

The Python scripts are meant to run as `python3 -I` (isolated mode): no `PYTHON*` environment
variables, no user site-packages, and the current directory is not on the import path, so a planted
`json.py` or `re.py` in the directory you run from cannot be imported as root. They use the standard
library only; there is nothing to install and nothing to pin.

Run the tests: `python3 -m unittest discover -s tests` (and `SERVER_AUDIT_E2E=1 python3 -m unittest
tests.test_lab_e2e` with Docker for the end-to-end run on the lab).

## Reporting a vulnerability

Please report security issues privately rather than in a public issue.

- **Email:** info@fixflex.co.uk
- Include: a description, steps to reproduce (a lab container or a minimal config is ideal), and the
  affected version (`version` in `SKILL.md`).

Worth reporting: a way to make a script print a secret value, write to or change the audited host,
make a network connection from a script that reads secrets, or get the agent to follow instructions
planted on the host. Never include a real secret in a report — generate a fake one.
