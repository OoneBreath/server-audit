#!/usr/bin/env python3
"""Compare several hosts' audits on the operator's machine: what differs, what is shared, who lags.

    python3 -I fleet.py key [--file PATH]          # a fresh comparison key (mode 600; never printed)
    python3 -I fleet.py key --delete [--file PATH]  # forget it after the comparison
    python3 -I fleet.py compare RUN_DIR... [--json] [--out FILE]

RUN_DIR is a run directory copied from each host (state.json, and secrets.txt if the secret scan ran).
Copy only those two files: they hold no secret values. The comparison reads them and nothing else; it
never connects anywhere.

Secret reuse across hosts needs fingerprints made with the same key on every host. Per-run fingerprints
(fp=) are random per run on purpose, so this script makes a separate key for one comparison:

    python3 -I fleet.py key                         # writes ~/.server-audit/fleet.key (600)
    ssh HOST 'sudo python3 -I find_secrets.py --git-history --fleet-key-stdin --out RUN/secrets.txt' \\
        < ~/.server-audit/fleet.key                 # the key goes over stdin, never on disk or argv there
    python3 -I fleet.py compare host1-run host2-run ...
    python3 -I fleet.py key --delete                # a new key next time

While the key exists, the xfp= values in the copied reports can be tested against guessed passwords:
keep the reports private and delete the key when the comparison is done.

What it reports: hosts at a glance (OS, end of support, pending security updates, reboot, automatic
updates, firewall, candidate count); hosts lagging behind the others; sshd settings that differ; the same
SSH key authorized on several hosts; services listening on all interfaces on some hosts only; the backup
ladder of every host in one table; the same candidate finding on several hosts; the same secret value on
several hosts.
"""

import hashlib
import hmac
import json
import os
import re
import sys
from collections import defaultdict

DEFAULT_KEY = os.path.join(os.path.expanduser("~"), ".server-audit", "fleet.key")
SSH_COMPARE = ["passwordauthentication", "kbdinteractiveauthentication", "permitrootlogin", "pubkeyauthentication",
               "authenticationmethods", "permitemptypasswords", "maxauthtries", "x11forwarding",
               "allowtcpforwarding", "permituserenvironment", "port", "listenaddress"]
SECRET_LINE = re.compile(r"^(?P<tags>\S+)\s+(?P<type>\S+)\s+(?P<where>.+?)\s{2}key=(?P<key>\S+)\s{2}.*?"
                         r"len=\d+ fp=\w+(?: xfp=(?P<xfp>[0-9a-f]{12}))?")


def key_id(key_hex):
    """Short id that shows which comparison key a report was made with (not the key, not reversible)."""
    return hmac.new(bytes.fromhex(key_hex), b"server-audit fleet key id", hashlib.sha256).hexdigest()[:8]


def cmd_key(argv):
    path = DEFAULT_KEY
    if "--file" in argv:
        path = os.path.expanduser(argv[argv.index("--file") + 1])
    if "--delete" in argv:
        if os.path.exists(path):
            os.remove(path)
            print("deleted %s" % path)
        else:
            print("no key at %s" % path)
        return 0
    os.makedirs(os.path.dirname(path), mode=0o700, exist_ok=True)
    k = os.urandom(32).hex()
    fd = os.open(path + ".new", os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(k + "\n")
    os.replace(path + ".new", path)
    print("wrote a new comparison key to %s (mode 600, id %s)" % (path, key_id(k)))
    print("pass it on stdin: ssh HOST 'sudo python3 -I find_secrets.py --fleet-key-stdin --out RUN/secrets.txt' < %s"
          % path)
    return 0


def load_run(path):
    sp = os.path.join(path, "state.json") if os.path.isdir(path) else path
    with open(sp) as f:
        state = json.load(f)
    secrets, kid = [], None
    sec = os.path.join(os.path.dirname(sp), "secrets.txt")
    if os.path.isfile(sec):
        with open(sec, errors="replace") as f:
            for line in f:
                m = re.match(r"^fleet key id: (\w+)", line)
                if m:
                    kid = m.group(1)
                m = SECRET_LINE.match(line.rstrip("\n"))
                if m and "example?" not in m.group("tags"):
                    secrets.append(m.groupdict())
    meta = state.get("_meta", {})
    return {"host": meta.get("host") or os.path.basename(path.rstrip("/")), "collected": meta.get("collected", "?"),
            "root": meta.get("root"), "state": state, "secrets": secrets, "secrets_file": os.path.isfile(sec),
            "key_id": kid}


def _g(state, section, key, default=None):
    return (state.get(section) or {}).get(key, default)


def firewall_of(state):
    fw = state.get("firewall") or {}
    if fw.get("ufw_status") == "active":
        return "ufw"
    if fw.get("firewalld_state") == "running":
        return "firewalld"
    if "ufw_status" in fw or "firewalld_state" in fw:
        return "none active"
    return "?"


def auto_on(v):
    """Automatic security updates on: unattended-upgrades enabled, or a dnf-automatic timer."""
    return bool(v) and ("enabled" in v.split() or "dnf-automatic" in v)


def norm_candidate(text):
    return re.sub(r"\d+(?:\.\d+)?", "#", text)


def compare(runs):
    """Return a list of (section, lines) and a list of findings (one line each)."""
    by_host = {}
    for r in sorted(runs, key=lambda r: r["collected"]):
        by_host[r["host"]] = r  # the newest run of a host wins
    hosts = sorted(by_host)
    out, findings = [], []

    rows = []
    for h in hosts:
        s = by_host[h]["state"]
        f = s.get("_fleet") or {}
        days = f.get("eol_days")
        rows.append([h, _g(s, "host", "os", "?"), _g(s, "host", "kernel", "?"),
                     ("%s (%+d d)" % (f["eol"], days)) if f.get("eol") else "?",
                     str(f.get("security_updates", "?")), str(f.get("reboot_required", "?")),
                     str(f.get("auto_updates", "?")), firewall_of(s), str(len(_g(s, "candidates", "all", []))),
                     by_host[h]["collected"][:16] + ("" if by_host[h]["root"] else " (no root)")])
    out.append(("hosts", table(["host", "os", "kernel", "end of support", "sec. updates", "reboot", "auto updates",
                                "firewall", "candidates", "collected"], rows)))

    # who lags
    lag = []
    sec = {h: (by_host[h]["state"].get("_fleet") or {}).get("security_updates") for h in hosts}
    known = [v for v in sec.values() if isinstance(v, int)]
    for h in hosts:
        f = by_host[h]["state"].get("_fleet") or {}
        if isinstance(sec[h], int) and sec[h] > 0 and known and sec[h] > min(known):
            lag.append("%s: %d security updates pending (fewest on any host: %d)" % (h, sec[h], min(known)))
        if isinstance(f.get("eol_days"), int) and f["eol_days"] < 180:
            lag.append("%s: %s end of standard support %s" % (
                h, "PAST" if f["eol_days"] < 0 else "in %d days:" % f["eol_days"], f.get("eol")))
        if str(f.get("reboot_required", "")).startswith("yes"):
            lag.append("%s: reboot required (%s)" % (h, f["reboot_required"]))
        if "auto_updates" in f and not auto_on(f["auto_updates"]) and any(
                auto_on((by_host[o]["state"].get("_fleet") or {}).get("auto_updates")) for o in hosts if o != h):
            lag.append("%s: automatic security updates are off while other hosts have them" % h)
        if firewall_of(by_host[h]["state"]) == "none active" and any(
                firewall_of(by_host[o]["state"]) in ("ufw", "firewalld") for o in hosts if o != h):
            lag.append("%s: no active host firewall while other hosts have one" % h)
    findings += lag
    out.append(("lagging behind the others", lag or ["none"]))

    # sshd settings that differ
    diff_rows = []
    for k in SSH_COMPARE:
        vals = {h: (_g(by_host[h]["state"], "ssh", "effective") or {}).get(k, "?") for h in hosts}
        seen = {v for v in vals.values() if v != "?"}
        if len(seen) > 1:
            diff_rows.append([k] + [vals[h] for h in hosts])
            if k == "passwordauthentication" and "yes" in seen:
                findings.append("sshd: password login is on for %s and off elsewhere"
                                % ", ".join(h for h in hosts if vals[h] == "yes"))
            if k == "permitrootlogin" and "yes" in seen:
                findings.append("sshd: root may log in with a password on %s"
                                % ", ".join(h for h in hosts if vals[h] == "yes"))
    out.append(("sshd settings that differ", table(["setting"] + hosts, diff_rows) if diff_rows else ["none"]))

    # the same SSH key on several hosts
    keys = defaultdict(set)
    label = {}
    for h in hosts:
        for name, val in (by_host[h]["state"].get("ssh") or {}).items():
            if not name.startswith("keys ") or not isinstance(val, list):
                continue
            m = re.search(r"/home/([^/]+)/|^/(root)/", name[5:])
            user = (m.group(1) or m.group(2)) if m else name[5:]
            for line in val:
                km = re.search(r"(SHA256:[A-Za-z0-9+/=]+)\s*(.*)$", line)
                if km:
                    keys[km.group(1)].add("%s (%s)" % (h, user))
                    label[km.group(1)] = km.group(2).strip()
    shared = []
    for fp, where in sorted(keys.items(), key=lambda kv: -len(kv[1])):
        hs = {w.split(" ")[0] for w in where}
        if len(hs) > 1:
            shared.append("%s %s on %d hosts: %s" % (fp[:20] + "…", label[fp], len(hs), ", ".join(sorted(where))))
    if shared:
        findings.append("%d SSH key(s) authorized on several hosts — one stolen private key opens all of them "
                        "(fine for the operator's own key with a passphrase; not for deploy or CI keys)" % len(shared))
    out.append(("the same SSH key on several hosts", shared or ["none"]))

    # listeners on all interfaces that only some hosts have
    lis = {h: {l for l in _g(by_host[h]["state"], "network", "listeners", []) if " ALL " in l} for h in hosts}
    port_hosts = defaultdict(set)
    for h, ls in lis.items():
        for l in ls:
            parts = l.split()
            port_hosts[(parts[0], parts[2], parts[3] if len(parts) > 3 else "?")].add(h)
    def port_order(kv):
        (proto, p, proc), hs = kv
        return (len(hs), int(p) if p.isdigit() else 0)
    only = ["%s/%s (%s) on all interfaces: only on %s" % (p, proto, proc, ", ".join(sorted(hs)))
            for (proto, p, proc), hs in sorted(port_hosts.items(), key=port_order) if len(hs) < len(hosts)]
    out.append(("listening on all interfaces on some hosts only", only[:60] or ["none"]))

    # backups in one place
    brows = []
    for h in hosts:
        lad = _g(by_host[h]["state"], "backups", "ladder") or {}
        brows.append([h] + [str(lad.get(k, "?")) for k in ("exists", "fresh", "offsite", "encrypted",
                                                           "deletable_from_host", "alerts", "restore_tested")])
        if lad.get("offsite") == "no":
            findings.append("%s: backups exist only on that host" % h)
        if lad.get("deletable_from_host") == "yes":
            findings.append("%s: its offsite backup can be deleted from the host itself" % h)
    out.append(("backups", table(["host", "exists", "fresh", "offsite", "encrypted", "deletable here", "alerts",
                                  "restore tested"], brows)))

    # the same candidate on several hosts
    cand = defaultdict(set)
    text = {}
    for h in hosts:
        for c in _g(by_host[h]["state"], "candidates", "all", []):
            n = norm_candidate(c)
            cand[n].add(h)
            text.setdefault(n, c)
    common = ["%s  — on %s" % (text[n][:180], ", ".join(sorted(hs)))
              for n, hs in sorted(cand.items(), key=lambda kv: -len(kv[1])) if len(hs) > 1]
    out.append(("the same candidate on several hosts (fix once, everywhere)", common or ["none"]))

    # the same secret value on several hosts
    lines = []
    with_secrets = [h for h in hosts if by_host[h]["secrets_file"]]
    kids = {by_host[h]["key_id"] for h in with_secrets}
    xfp_hosts = [h for h in with_secrets if any(s.get("xfp") for s in by_host[h]["secrets"])]
    if len(xfp_hosts) < 2:
        lines.append("not compared: needs secrets.txt from at least two hosts, each made with "
                     "find_secrets.py --fleet-key-stdin and the same key (fleet.py key)")
    elif len(kids) > 1 or None in kids:
        lines.append("not compared: the secrets reports were made with different comparison keys (ids: %s)"
                     % ", ".join(sorted(str(k) for k in kids)))
    else:
        where = defaultdict(list)
        for h in xfp_hosts:
            for s in by_host[h]["secrets"]:
                if s.get("xfp"):
                    where[s["xfp"]].append((h, s["key"], s["where"]))
        for x, places in sorted(where.items(), key=lambda kv: -len(kv[1])):
            hs = sorted({p[0] for p in places})
            if len(hs) > 1:
                names = sorted({p[1] for p in places})
                lines.append("xfp=%s under %s on %d hosts:" % (x, ", ".join(names), len(hs)))
                lines += ["    %s  %s" % (p[0], p[2]) for p in sorted(set(places))[:12]]
        if any(not l.startswith("    ") for l in lines):
            findings.append("%d secret value(s) are the same on several hosts — one leak opens all of them; rotate "
                            "and give each host its own" % sum(1 for l in lines if not l.startswith("    ")))
        else:
            lines.append("none: no secret value appears on more than one host (key id %s)" % next(iter(kids)))
    out.append(("the same secret on several hosts", lines))
    return hosts, out, findings


def table(head, rows):
    rows = [[str(c) for c in r] for r in rows]
    w = [max(len(head[i]), *(len(r[i]) for r in rows)) if rows else len(head[i]) for i in range(len(head))]
    fmt = "  ".join("%%-%ds" % x for x in w)
    return [fmt % tuple(head), fmt % tuple("-" * x for x in w)] + [fmt % tuple(r) for r in rows]


def cmd_compare(argv):
    as_json = "--json" in argv
    out_file = argv[argv.index("--out") + 1] if "--out" in argv else None
    paths = [a for i, a in enumerate(argv) if not a.startswith("--") and (i == 0 or argv[i - 1] != "--out")]
    if len(paths) < 2:
        print("compare needs the run directories of at least two hosts")
        return 2
    runs = [load_run(p) for p in paths]
    hosts, sections, findings = compare(runs)
    if len(hosts) < 2:
        print("all runs are from one host (%s): nothing to compare" % hosts[0])
        return 2
    if as_json:
        text = json.dumps({"hosts": hosts, "findings": findings, "sections": dict(sections)}, indent=1) + "\n"
    else:
        lines = ["server-audit fleet comparison — SENSITIVE (weaknesses of %d hosts). Do not share or commit."
                 % len(hosts), "", "Findings across hosts: %d" % len(findings)]
        lines += ["  !! " + f for f in findings]
        for name, body in sections:
            lines += ["", "== " + name] + ["  " + l for l in body]
        text = "\n".join(lines) + "\n"
    if out_file:
        fd = os.open(out_file, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(text)
        print(out_file)
    else:
        sys.stdout.write(text)
    return 0


def main(argv):
    if len(argv) < 2 or argv[1] not in ("key", "compare"):
        print(__doc__.strip().splitlines()[2].strip())
        print(__doc__.strip().splitlines()[3].strip())
        print(__doc__.strip().splitlines()[4].strip())
        return 2
    os.umask(0o077)
    return cmd_key(argv[2:]) if argv[1] == "key" else cmd_compare(argv[2:])


if __name__ == "__main__":
    sys.exit(main(sys.argv))
