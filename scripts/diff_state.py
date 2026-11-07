#!/usr/bin/env python3
"""Compare two server-audit state files: what changed on the host between two audits.

    python3 -I diff_state.py OLD NEW [--json] [--exit-code]   # state.json files or their run directories

--json prints the changes as a JSON list; --exit-code exits 1 when anything changed (for cron/CI).

collect.py writes state.json next to the inventory: value-free facts per section (listeners, firewall
rules, sshd settings, authorized key fingerprints, sudo rules, cron lines, containers, services,
candidate findings, ...). Secrets never appear in it: config lines are masked and the per-run
fingerprints are stripped, so the same file compares equal across runs.

collect.py runs this comparison itself against the previous run for the same host and puts the
result at the top of the inventory. Use this script directly to compare any two runs.
"""

import json
import os
import re
import sys

# Sections whose changes are worth a look even when nothing was flagged (new port, new key, ...).
SECURITY_RELEVANT = {"network", "firewall", "docker", "ssh", "users", "services", "cron", "web", "tunnels",
                     "files", "candidates"}


def _norm_candidate(text):
    # candidate texts carry counts and ages ("12 security updates", "3.0 days old"): compare without them
    return re.sub(r"\d+(?:\.\d+)?", "#", text)


def load(path):
    if os.path.isdir(path):
        path = os.path.join(path, "state.json")
    with open(path) as f:
        return json.load(f)


def diff(old, new):
    """Return [(kind, section, key, detail)], kind in added/removed/changed.

    Only sections present in both states are compared (a run with --only has fewer sections).
    """
    out = []
    for section in sorted(set(old) & set(new)):
        if section.startswith("_"):
            continue
        o, n = old[section], new[section]
        if not isinstance(o, dict) or not isinstance(n, dict):
            continue
        for key in sorted(set(o) | set(n)):
            if key not in n:
                out.append(("removed", section, key, _short(o[key])))
                continue
            if key not in o:
                out.append(("added", section, key, _short(n[key])))
                continue
            ov, nv = o[key], n[key]
            if isinstance(ov, list) and isinstance(nv, list):
                if section == "candidates":
                    on = {_norm_candidate(x): x for x in ov}
                    nn = {_norm_candidate(x): x for x in nv}
                    for k in sorted(set(nn) - set(on)):
                        out.append(("added", section, key, nn[k]))
                    for k in sorted(set(on) - set(nn)):
                        out.append(("removed", section, key, on[k]))
                    continue
                for x in sorted(set(map(str, nv)) - set(map(str, ov))):
                    out.append(("added", section, key, x))
                for x in sorted(set(map(str, ov)) - set(map(str, nv))):
                    out.append(("removed", section, key, x))
            elif isinstance(ov, dict) and isinstance(nv, dict):
                for k in sorted(set(ov) | set(nv)):
                    if k not in nv:
                        out.append(("removed", section, "%s.%s" % (key, k), _short(ov[k])))
                    elif k not in ov:
                        out.append(("added", section, "%s.%s" % (key, k), _short(nv[k])))
                    elif ov[k] != nv[k]:
                        out.append(("changed", section, "%s.%s" % (key, k), "%s -> %s" % (_short(ov[k]), _short(nv[k]))))
            elif ov != nv:
                out.append(("changed", section, key, "%s -> %s" % (_short(ov), _short(nv))))
    return out


def _short(v, n=160):
    s = v if isinstance(v, str) else json.dumps(v, sort_keys=True)
    return s if len(s) <= n else s[:n] + "…"


def format_diff(changes, old_meta=None):
    lines = []
    if old_meta:
        lines.append("compared with %s (collected %s)" % (old_meta.get("run", "?"), old_meta.get("collected", "?")))
    if not changes:
        lines.append("no changes in the compared sections")
        return lines
    sym = {"added": "+", "removed": "-", "changed": "~"}
    for kind, section, key, detail in changes:
        lines.append("%s %-10s %-22s %s" % (sym[kind], section, key, detail))
    return lines


def main(argv):
    flags = {a for a in argv[1:] if a.startswith("--")}
    args = [a for a in argv[1:] if not a.startswith("--")]
    if len(args) != 2 or flags - {"--json", "--exit-code"}:
        print(__doc__.strip().splitlines()[2].strip())
        return 2
    old, new = load(args[0]), load(args[1])
    changes = diff(old, new)
    if "--json" in flags:
        print(json.dumps({"old": old.get("_meta"), "new": new.get("_meta"),
                          "changes": [dict(zip(("kind", "section", "key", "detail"), c)) for c in changes]},
                         indent=1))
    else:
        for line in format_diff(changes, old.get("_meta")):
            print(line)
    return 1 if changes and "--exit-code" in flags else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
