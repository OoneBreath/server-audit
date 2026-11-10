#!/usr/bin/env python3
"""validate_findings.py — check a run's findings.json against the contract (references/findings-schema.json).

    python3 -I validate_findings.py <run>/findings.json [--quiet]

Exit 0 = valid, 1 = invalid (each problem printed as `path: message`), 2 = unreadable input.
Stdlib only. No network, and it writes nothing but stdout/stderr.

What it checks, beyond the shape:
- severity agrees with the reachability × impact table in SKILL.md; one level up or down only with an
  `adjust_reason`; a hardening gap that needs root already is INFO and nothing else;
- `confirm_by` is present when confidence is `inferred` or `verified-partial`;
- ids are unique; an attack path letter links at least two findings;
- the backup ladder says restore_tested=true only if some finding or evidence mentions a restore;
- no string carries a secret (secretlib) or a fingerprint (fp=, xfp=). Masked forms (<REDACTED …>,
  ***, …) are fine as long as they carry no fingerprint.
"""
import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import secretlib  # noqa: E402

SEVERITIES = ["INFO", "LOW", "MEDIUM", "HIGH"]            # ordered, low to high
CONFIDENCE = ["verified-outside", "verified-inside", "verified-partial", "inferred", "not-checked"]
STATUS = ["open", "fixed", "accepted", "needs-operator"]
REACHABILITY = ["internet-no-auth", "internet-one-control", "local-users", "needs-root"]
IMPACT = ["data-or-control", "availability", "hardening"]
WHERE = ["inside", "outside"]
VERIFIER_VERDICTS = ["upheld", "downgraded", "rejected", "changed", "error"]
VERIFICATION = ["independent", "same-agent-fallback", "none"]
MODES = ["full", "focused"]
# The areas of references/checks.md (section → area id).
AREAS = ["exposure", "proxy", "ssh", "users", "secrets", "services", "updates", "tls", "backups", "detection",
         "ai-agents", "operator", "disk", "dns-mail", "drift", "fleet"]
LADDER = ["exists", "fresh", "offsite", "encrypted", "deletable_from_host", "restore_tested"]

# SKILL.md, step 6: severity = reachability × impact. A cell can allow two levels (MEDIUM–HIGH).
TABLE = {
    "data-or-control": {"internet-no-auth": {"HIGH"}, "internet-one-control": {"MEDIUM", "HIGH"},
                        "local-users": {"MEDIUM"}, "needs-root": {"INFO"}},
    "availability": {"internet-no-auth": {"HIGH"}, "internet-one-control": {"MEDIUM"},
                     "local-users": {"MEDIUM"}, "needs-root": {"LOW"}},
    "hardening": {"internet-no-auth": {"LOW"}, "internet-one-control": {"LOW"},
                  "local-users": {"LOW"}, "needs-root": {"INFO"}},
}
STRICT_CELLS = {("hardening", "needs-root")}              # INFO only, no adjustment

FINGERPRINT = re.compile(r"\bx?fp=")
MASKED = re.compile(r"<REDACTED[^>]*>|<redacted>|<masked>|\[redacted\]|\*{3,}|…")
RESTORE = re.compile(r"\brestor", re.I)
DATE = re.compile(r"^\d{4}-\d{2}-\d{2}$")


class Problems(list):
    def add(self, path, message):
        self.append("%s: %s" % (path, message))


def _str(p, path, obj, key, required=True, allow_empty=False):
    if key not in obj:
        if required:
            p.add(path, "missing field %r" % key)
        return None
    v = obj[key]
    if not isinstance(v, str) or (not allow_empty and not v.strip()):
        p.add("%s.%s" % (path, key), "must be a non-empty string")
        return None
    return v


def _enum(p, path, obj, key, values, required=True, nullable=False):
    if key not in obj:
        if required:
            p.add(path, "missing field %r" % key)
        return None
    v = obj[key]
    if v is None and nullable:
        return None
    if v not in values:
        p.add("%s.%s" % (path, key), "%r is not one of: %s" % (v, ", ".join(values)))
        return None
    return v


def check_severity(p, path, f):
    sev, reach, imp = f.get("severity"), f.get("reachability"), f.get("impact")
    if sev not in SEVERITIES or reach not in REACHABILITY or imp not in IMPACT:
        return
    allowed = TABLE[imp][reach]
    if sev in allowed:
        return
    if (imp, reach) in STRICT_CELLS:
        p.add(path + ".severity", "%s with impact=%s and reachability=%s must be INFO" % (sev, imp, reach))
        return
    dist = min(abs(SEVERITIES.index(sev) - SEVERITIES.index(a)) for a in allowed)
    if dist >= 2:
        p.add(path + ".severity", "%s is %d levels from the table (%s × %s = %s); only one level of adjustment "
                                  "is allowed" % (sev, dist, imp, reach, "/".join(sorted(allowed))))
    elif not (isinstance(f.get("adjust_reason"), str) and f["adjust_reason"].strip()):
        p.add(path + ".severity", "%s differs from the table (%s × %s = %s): give adjust_reason"
              % (sev, imp, reach, "/".join(sorted(allowed))))


def leak_check(p, path, value):
    if isinstance(value, dict):
        for k, v in value.items():
            leak_check(p, "%s.%s" % (path, k), v)
    elif isinstance(value, list):
        for i, v in enumerate(value):
            leak_check(p, "%s[%d]" % (path, i), v)
    elif isinstance(value, str):
        if FINGERPRINT.search(value):
            p.add(path, "contains a fingerprint (fp=/xfp=); remove it")
            return
        neutral = MASKED.sub("<redacted>", value)   # secretlib reads <redacted> as a placeholder, whatever follows
        for line in neutral.splitlines() or [""]:
            if secretlib.scan_line(line, lenient=True, prose=True)[1]:
                p.add(path, "looks like it contains a secret value; mask it (<REDACTED>) and drop any fingerprint")
                return


def validate(doc):
    p = Problems()
    if not isinstance(doc, dict):
        p.add("$", "the top level must be a JSON object")
        return p
    _str(p, "$", doc, "host")
    d = _str(p, "$", doc, "date")
    if d and not DATE.match(d):
        p.add("$.date", "must be YYYY-MM-DD")
    _str(p, "$", doc, "skill_version")
    _str(p, "$", doc, "run_dir")
    _enum(p, "$", doc, "mode", MODES)
    _enum(p, "$", doc, "verification", VERIFICATION)

    findings = doc.get("findings")
    if not isinstance(findings, list):
        p.add("$", "missing list 'findings'")
        findings = []
    rejected = doc.get("rejected")
    if not isinstance(rejected, list):
        p.add("$", "missing list 'rejected' (use [] when nothing was dropped)")
        rejected = []
    nc = doc.get("not_checked")
    if not isinstance(nc, list) or not all(isinstance(x, str) for x in nc):
        p.add("$", "missing list of strings 'not_checked' (use [] when everything was checked)")

    ids, paths, restore_mentioned = set(), {}, False
    for i, f in enumerate(findings):
        path = "$.findings[%d]" % i
        if not isinstance(f, dict):
            p.add(path, "must be an object")
            continue
        fid = f.get("id")
        if not isinstance(fid, int) or isinstance(fid, bool):
            p.add(path, "id must be an integer")
        elif fid in ids:
            p.add(path + ".id", "duplicate id %d" % fid)
        else:
            ids.add(fid)
        title = _str(p, path, f, "title")
        _enum(p, path, f, "area", AREAS)
        _enum(p, path, f, "severity", SEVERITIES)
        conf = _enum(p, path, f, "confidence", CONFIDENCE)
        _enum(p, path, f, "status", STATUS)
        _enum(p, path, f, "reachability", REACHABILITY)
        _enum(p, path, f, "impact", IMPACT)
        letter = f.get("path", None) if "path" in f else p.add(path, "missing field 'path' (null if not on an attack path)")
        if "path" in f and letter is not None:
            if not (isinstance(letter, str) and re.fullmatch(r"[A-Z]", letter)):
                p.add(path + ".path", "must be one capital letter or null")
            else:
                paths.setdefault(letter, []).append(fid)
        ev = f.get("evidence")
        if not isinstance(ev, list) or not ev:
            p.add(path, "evidence must be a non-empty list")
            ev = []
        for j, e in enumerate(ev):
            ep = "%s.evidence[%d]" % (path, j)
            if not isinstance(e, dict):
                p.add(ep, "must be an object")
                continue
            _str(p, ep, e, "command")
            _str(p, ep, e, "observation")
            _enum(p, ep, e, "where", WHERE)
            if RESTORE.search(str(e.get("command", "")) + " " + str(e.get("observation", ""))):
                restore_mentioned = True
        if title and RESTORE.search(title):
            restore_mentioned = True
        if conf in ("inferred", "verified-partial") and not (isinstance(f.get("confirm_by"), str) and f["confirm_by"].strip()):
            p.add(path, "confidence %s needs confirm_by (what would confirm it)" % conf)
        v = f.get("verifier", None)
        if "verifier" not in f:
            p.add(path, "missing field 'verifier' (null until a verifier has looked at it)")
        elif v is not None:
            if not isinstance(v, dict):
                p.add(path + ".verifier", "must be null or an object")
            else:
                _enum(p, path + ".verifier", v, "verdict", VERIFIER_VERDICTS)
                _str(p, path + ".verifier", v, "note")
        check_severity(p, path, f)

    for i, r in enumerate(rejected):
        rp = "$.rejected[%d]" % i
        if not isinstance(r, dict):
            p.add(rp, "must be an object")
            continue
        rid = r.get("id")
        if not isinstance(rid, int) or isinstance(rid, bool):
            p.add(rp, "id must be an integer")
        elif rid in ids:
            p.add(rp + ".id", "duplicate id %d (ids are unique across findings and rejected)" % rid)
        else:
            ids.add(rid)
        _str(p, rp, r, "title")
        _str(p, rp, r, "reason")

    for letter, members in sorted(paths.items()):
        if len(members) < 2:
            p.add("$.findings", "attack path %s links only one finding (#%s); a path joins two or more, "
                                "otherwise set path to null" % (letter, members[0]))

    ladder = doc.get("backup_ladder")
    if not isinstance(ladder, dict):
        p.add("$", "missing object 'backup_ladder'")
    else:
        for k in LADDER:
            if k not in ladder:
                p.add("$.backup_ladder", "missing field %r (true, false or null)" % k)
            elif ladder[k] not in (True, False, None):
                p.add("$.backup_ladder.%s" % k, "must be true, false or null")
        if ladder.get("restore_tested") is True and not restore_mentioned:
            p.add("$.backup_ladder.restore_tested", "true, but no finding or evidence mentions a restore")

    leak_check(p, "$", doc)
    return p


def main(argv):
    args = [a for a in argv if not a.startswith("-")]
    quiet = "--quiet" in argv
    if len(args) != 1:
        print("usage: validate_findings.py <findings.json> [--quiet]", file=sys.stderr)
        return 2
    try:
        with open(args[0], encoding="utf-8") as fh:
            doc = json.load(fh)
    except (OSError, ValueError) as e:
        print("%s: unreadable (%s)" % (args[0], type(e).__name__), file=sys.stderr)
        return 2
    problems = validate(doc)
    if problems:
        for line in problems:
            print(line)
        if not quiet:
            print("\n%d problem(s); findings.json is not valid." % len(problems), file=sys.stderr)
        return 1
    if not quiet:
        print("findings.json is valid (%d finding(s), %d rejected)." % (len(doc["findings"]), len(doc["rejected"])))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
