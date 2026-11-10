#!/usr/bin/env python3
"""coverage.py — what an audit covered, per area of references/checks.md.

    python3 -I coverage.py seed RUN_DIR      # write RUN_DIR/coverage.json (600) for the agent to fill in
    python3 -I coverage.py gaps HOST [--dir ~/.server-audit] [--not RUN_DIR]
                                             # what the previous run of HOST did not cover

coverage.json is one entry per area: {"area", "status", "reason"}, status one of
checked | degraded (no root, a tool missing, a section failed) | skipped-by-operator | not-checked |
needs-operator. `seed` starts every area as not-checked, marks the areas whose inventory sections
were skipped or partial as degraded (from collect.py's own markers), and the operator-only area as
needs-operator; the agent then sets what it actually checked at step 6. Validate it with
`validate_findings.py <run>/findings.json --coverage <run>/coverage.json`.

Stdlib only, no network. `seed` writes only RUN_DIR/coverage.json and never overwrites it.
"""
import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import validate_findings as vf  # noqa: E402

STATUSES = ["checked", "degraded", "skipped-by-operator", "not-checked", "needs-operator"]
# inventory.txt section headers (collect.py header()) -> area
HEADER_AREA = [("HOST", "updates"), ("NETWORK", "exposure"), ("FIREWALL", "exposure"), ("DOCKER", "exposure"),
               ("PODMAN", "exposure"), ("SSH", "ssh"), ("USERS", "users"), ("SERVICES", "services"),
               ("CRON", "services"), ("WEB", "proxy"), ("TLS", "tls"), ("SENSITIVE FILES", "secrets"),
               ("GIT", "secrets"), ("PROCESSES", "secrets"), ("BACKUPS", "backups"), ("DISK", "disk"),
               ("HARDENING", "detection"), ("TEXT ADDRESSED TO AI", "ai-agents")]
DEGRADED = re.compile(r"\(skipped: needs root|\(section \w+ failed|\(not root[:)]|\(NOT root")


def area_of(header):
    for prefix, area in HEADER_AREA:
        if header.upper().startswith(prefix):
            return area
    return None


def seed_from_inventory(text):
    """{area: [reasons]} for areas whose inventory sections carry a skip / partial marker."""
    degraded, area = {}, None
    for line in text.splitlines():
        if line.startswith("== "):
            area = area_of(line[3:].strip())
            continue
        m = DEGRADED.search(line)
        if m and area:
            reason = line.strip()[:120]
            degraded.setdefault(area, [])
            if reason not in degraded[area]:
                degraded[area].append(reason)
    return degraded


def seed(run_dir):
    inv = os.path.join(run_dir, "inventory.txt")
    text = ""
    if os.path.isfile(inv):
        with open(inv, encoding="utf-8", errors="replace") as fh:
            text = fh.read()
    degraded = seed_from_inventory(text)
    entries = []
    for area in vf.AREAS:
        if area in degraded:
            entries.append({"area": area, "status": "degraded", "reason": "; ".join(degraded[area][:3])})
        elif area == "operator":
            entries.append({"area": area, "status": "needs-operator",
                            "reason": "renewals, offsite copies, provider 2FA: only the operator can answer"})
        else:
            entries.append({"area": area, "status": "not-checked", "reason": "not reviewed yet"})
    return {"run": os.path.basename(os.path.abspath(run_dir)), "areas": entries}


def validate(cov, findings=None):
    """Problems as 'path: message'. With findings.json, every not-checked / needs-operator area must be
    named in its not_checked[] list (by area id or checks.md title)."""
    p = vf.Problems()
    if not isinstance(cov, dict) or not isinstance(cov.get("areas"), list):
        p.add("$", "coverage.json must be an object with a list 'areas'")
        return p
    seen = {}
    for i, e in enumerate(cov["areas"]):
        path = "$.areas[%d]" % i
        if not isinstance(e, dict):
            p.add(path, "must be an object")
            continue
        a = vf._enum(p, path, e, "area", vf.AREAS)
        st = vf._enum(p, path, e, "status", STATUSES)
        if a:
            seen[a] = seen.get(a, 0) + 1
        if st and st != "checked" and not (isinstance(e.get("reason"), str) and e["reason"].strip()):
            p.add(path, "status %s needs a reason" % st)
    for a in vf.AREAS:
        if seen.get(a, 0) != 1:
            p.add("$.areas", "area %s appears %d times (exactly once)" % (a, seen.get(a, 0)))
    if findings is not None:
        listed = " ".join(x for x in findings.get("not_checked", []) if isinstance(x, str)).lower()
        titles = _titles()
        for e in cov["areas"]:
            if isinstance(e, dict) and e.get("status") in ("not-checked", "needs-operator"):
                names = {e["area"], e["area"].replace("-", " "), titles.get(e["area"], "").lower()}
                if not any(n and n in listed for n in names):
                    p.add("$.areas", "%s is %s but the report's Not checked list (findings.json not_checked) "
                                     "doesn't name it" % (e["area"], e["status"]))
    vf.leak_check(p, "$", cov)
    return p


def _titles():
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "references", "checks.md")
    try:
        with open(path, encoding="utf-8") as fh:
            heads = [l[3:].strip() for l in fh if l.startswith("## ") and l[3:4].isdigit()]
    except OSError:
        return {}
    out = {}
    for area, head in zip(vf.AREAS, heads):
        out[area] = re.sub(r"^\d+\.\s*", "", head).split(" — ")[0]
    return out


def gaps(host, base, exclude=None):
    """(run name, [(area, status, reason)]) of the newest earlier run of HOST that has coverage.json."""
    if not os.path.isdir(base):
        return None, []
    runs = sorted((d for d in os.listdir(base) if d.startswith(host + "-")), reverse=True)
    for d in runs:
        full = os.path.join(base, d)
        if exclude and os.path.realpath(full) == os.path.realpath(exclude):
            continue
        cov = os.path.join(full, "coverage.json")
        if os.path.isfile(cov):
            try:
                with open(cov, encoding="utf-8") as fh:
                    data = json.load(fh)
            except (OSError, ValueError):
                continue
            items = [(e.get("area"), e.get("status"), e.get("reason", "")) for e in data.get("areas", [])
                     if isinstance(e, dict) and e.get("status") != "checked"]
            order = {s: i for i, s in enumerate(["degraded", "not-checked", "needs-operator", "skipped-by-operator"])}
            return d, sorted(items, key=lambda t: (order.get(t[1], 9), str(t[0])))
    return None, []


def main(argv):
    if len(argv) >= 2 and argv[0] == "seed":
        run = argv[1]
        out = os.path.join(run, "coverage.json")
        if os.path.exists(out):
            print("%s exists; not overwriting it" % out, file=sys.stderr)
            return 1
        data = seed(run)
        fd = os.open(out, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=1)
            fh.write("\n")
        deg = [e["area"] for e in data["areas"] if e["status"] == "degraded"]
        print("%s: %d areas, degraded: %s" % (out, len(data["areas"]), ", ".join(deg) or "none"))
        return 0
    if len(argv) >= 2 and argv[0] == "gaps":
        host = argv[1]
        base = argv[argv.index("--dir") + 1] if "--dir" in argv else os.path.join(os.path.expanduser("~"), ".server-audit")
        excl = argv[argv.index("--not") + 1] if "--not" in argv else None
        run, items = gaps(host, base, excl)
        if not run:
            print("no earlier run of %s with coverage.json under %s" % (host, base))
            return 0
        print("Not covered by the previous audit (%s) — give these priority:" % run)
        for area, status, reason in items:
            print("  %-10s %-20s %s" % (area, status, reason))
        if not items:
            print("  (everything was checked)")
        return 0
    print(__doc__.strip().split("\n\n")[1], file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
