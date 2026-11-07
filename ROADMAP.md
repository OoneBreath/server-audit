# Roadmap

Ordered by what makes the audit useful on the most servers soonest. Versions are targets, not promises.

## v0.1: read-only audit ✓

- [x] Masked inventory, secret locator with exposure tags, outside-in probe
- [x] Check catalogue, remediation playbook, report template; read-only and no-network invariants

## v0.2: drift, backups, DNS ✓

- [x] `state.json` per run and the changes since the previous audit at the top of the inventory
- [x] Backup ladder (exists, fresh, offsite, encrypted, restore-tested), offsite credentials on the host,
      failure alerts
- [x] Disk and logs, databases on public addresses, tunnels, Docker hardening, dormant accounts, end of
      OS support, text addressed to AI agents
- [x] `dns_check.py` (SPF, DMARC, DKIM, CAA, DNSSEC, dangling CNAMEs, origin exposure); IPv6 in the probe
- [x] Lab container and end-to-end test

## v0.3: more servers, not just mine ✓

- [x] nginx parsed like Caddy (sites, locations without auth, directory listing, HTTP-only sites);
      Apache directory listing and status pages
- [x] RHEL family: dnf security advisories (local cache only), needs-restarting, dnf-automatic,
      firewalld zones, SELinux, rpm ownership of SUID files, end-of-support dates
- [x] Second lab (AlmaLinux 9 + nginx), CI running both labs
- [x] `diff_state.py --json --exit-code`, `collect.py --fail-on-drift` (nightly drift check without an
      agent), `findings.json` in the report format

## v0.4: several servers ✓

- [x] `fleet.py`: compare the state of several hosts on the operator's machine — the same SSH key or secret
      on several servers (a comparison key the operator holds, passed on stdin, never stored on the
      hosts), sshd and firewall differences, hosts lagging on updates, all backups in one table
- [x] Podman (rootful containers, quadlets rootful and rootless, rootless ports, linger), CI job on a real
      engine
- [x] Traefik (static file, CLI flags, file provider, Docker labels) and HAProxy

## v0.5: next

- [ ] Kubernetes nodes (kubelet, etcd and API exposure from the node)
- [ ] Caddy JSON config and Caddy behind Docker labels
- [ ] A fleet run over SSH from the operator's machine (each host audited in turn, results collected)

## Later

- [ ] Alpine/OpenRC and other non-systemd hosts beyond the partial inventory

## Not planned

- **CVE matching.** Dedicated vulnerability scanners do it well and keep their databases current;
  server-audit reports pending security updates and end of support, and its report can link to a
  scanner's output.
- **Rate-limit or brute-force testing.** Proving a rate limit means sending a flood of requests.
- **Fixing everything in one command.** Every fix is approved, backed up, verified and reversible on
  its own; a wrong firewall or sshd change can lock the operator out.
- **Scanning hosts you do not run.** Outside-in probes target the operator's own addresses only.
