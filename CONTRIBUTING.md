# Contributing to server-audit

The most useful contributions right now are:

- **Checks from real servers**: a misconfiguration that bit you and that the
  [check catalogue](references/checks.md) does not cover. Describe the evidence (which file or command
  shows it), how to verify it, how bad it is, and the false positives you would expect.
- **Platforms**: distributions, firewalls, proxies or container runtimes that get a partial inventory
  today (Alpine/OpenRC, Podman, Traefik, HAProxy, ...). A lab container that reproduces the setup is
  the best way to add one.
- **Secret formats**: a token format the scanner misses, with a fake example.
- **Design feedback**: open an issue before a PR for anything that changes behaviour.

## Pull request guidelines

1. Branch from `main`; one logical change per PR.
2. No new runtime dependencies: bash and the Python 3 standard library only.
3. **The read-only guarantee is the product.** `collect.py` may only run commands listed in
   `tests/test_invariants.py`; adding one means adding it there, where reviewers see it. Nothing that
   writes, restarts, downloads or sends anything belongs in the audit phase.
4. **Never a real secret**, not even an expired one, in code, tests, fixtures or issues. Generate fake
   values; the lab images generate theirs at build time.
5. New checks come with a unit test, and with a planted case in `lab/` plus an assertion in
   `tests/test_lab_e2e.py` when the check reads the live system. Run
   `python3 -m unittest discover -s tests` and, with Docker,
   `SERVER_AUDIT_E2E=1 python3 -m unittest tests.test_lab_e2e`.
6. Keep `SKILL.md` lean: the agent reads it on every run. Detail goes to `references/`.
7. Update `CHANGELOG.md` for user-visible changes.
8. CI runs the unit tests and the lab end-to-end test on every push to `main` or `dev` and every PR
   (`.github/workflows/test.yml`); a red run doesn't merge.

## Reporting a vulnerability

See [SECURITY.md](SECURITY.md). Please do not open a public issue for a way to make the scripts print
a secret, write to the host, or follow instructions planted on the host.
