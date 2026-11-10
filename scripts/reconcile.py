#!/usr/bin/env python3
"""reconcile.py — apply independent verifiers' verdicts to a draft findings.json.

    python3 -I reconcile.py DRAFT.json VERIFIER.jsonl [VERIFIER2.jsonl …] --out findings.json
        [--second SECOND.jsonl] [--keep ID="why"] [--same-agent]

Each verifier reply is one JSON object per line (references/verification.md):
    {"id": N, "verdict": "upheld|downgraded|rejected|changed", "severity": "…", "confidence": "…",
     "note": "one sentence", "evidence": [...], "reachability": "…"?, "impact": "…"?}

- upheld: kept; verifier verdict and note recorded, its evidence added.
- downgraded / changed: the verifier's severity / confidence / reachability / impact replace the
  draft's. A material change (severity moves 2+ levels, or the reachability class changes) is listed
  as needing a SECOND verifier; pass its reply with --second, and that verdict is final.
- rejected: moved to rejected[] with the verifier's reason, unless --keep ID="why": then it stays, at
  best verified-partial, with both reasons in the note.
- anything malformed (not JSON, unknown keys, bad values, a secret or a fingerprint) fails closed: the
  finding stays as it was, marked verifier.verdict = "error".

Prints the report's summary line and what still needs the auditor. Writes only --out (mode 600).
Exit 0 = the result passes validate_findings, 1 = it doesn't (see the problems printed),
2 = unreadable input. Stdlib only, no network.
"""
import copy
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import validate_findings as vf  # noqa: E402

KEYS = {"id", "verdict", "severity", "confidence", "note", "evidence", "reachability", "impact"}
VERDICTS = ["upheld", "downgraded", "rejected", "changed"]
NOTE_CAP = 400
WEAKER_THAN_PARTIAL = {"inferred", "not-checked"}


def parse_line(raw, ids):
    """-> (id or None, verdict dict or None, error text or None). Never echoes the line's content."""
    try:
        v = json.loads(raw)
    except ValueError:
        return None, None, "a line that is not JSON"
    if not isinstance(v, dict):
        return None, None, "a line that is not a JSON object"
    fid = v.get("id")
    if not isinstance(fid, int) or isinstance(fid, bool) or fid not in ids:
        return None, None, "a line whose id is not a finding of the draft"
    problems = []
    if set(v) - KEYS:
        problems.append("unknown keys %s" % sorted(set(v) - KEYS))
    if v.get("verdict") not in VERDICTS:
        problems.append("verdict must be one of %s" % ", ".join(VERDICTS))
    if not isinstance(v.get("note"), str) or not v["note"].strip() or len(v["note"]) > NOTE_CAP:
        problems.append("note must be one sentence (1–%d characters)" % NOTE_CAP)
    if v.get("verdict") != "rejected":
        if v.get("severity") not in vf.SEVERITIES:
            problems.append("severity missing or invalid")
        if v.get("confidence") not in vf.CONFIDENCE:
            problems.append("confidence missing or invalid")
    for key, values in (("reachability", vf.REACHABILITY), ("impact", vf.IMPACT)):
        if key in v and v[key] not in values:
            problems.append("%s invalid" % key)
    ev = v.get("evidence", [])
    if not isinstance(ev, list) or not all(
            isinstance(e, dict) and set(e) == {"command", "observation", "where"} and e["where"] in vf.WHERE
            and isinstance(e["command"], str) and isinstance(e["observation"], str) for e in ev):
        problems.append("evidence must be a list of {command, observation, where: inside|outside}")
    leaks = vf.Problems()
    vf.leak_check(leaks, "verifier", v)
    if leaks:
        problems.append("it contains a secret-looking value or a fingerprint")
    if problems:
        return fid, None, "; ".join(problems)
    return fid, v, None


def read_verdicts(paths, ids, notes):
    out, errors = {}, {}
    for path in paths:
        with open(path, encoding="utf-8") as fh:
            lines = [l for l in fh.read().splitlines() if l.strip()]
        for n, raw in enumerate(lines, 1):
            fid, v, err = parse_line(raw, ids)
            if fid is None:
                notes.append("%s line %d ignored: %s" % (os.path.basename(path), n, err))
                continue
            if fid in out or fid in errors:
                errors[fid] = "more than one verdict for it"
                out.pop(fid, None)
                continue
            if err:
                errors[fid] = err
            else:
                out[fid] = v
    return out, errors


def material(before, v):
    sev_jump = abs(vf.SEVERITIES.index(v["severity"]) - vf.SEVERITIES.index(before["severity"])) >= 2 \
        if before.get("severity") in vf.SEVERITIES else False
    reach_change = "reachability" in v and v["reachability"] != before.get("reachability")
    return sev_jump or reach_change


def off_table(f):
    allowed = vf.TABLE.get(f.get("impact"), {}).get(f.get("reachability"))
    if not allowed or f.get("severity") not in vf.SEVERITIES:
        return 0
    return min(abs(vf.SEVERITIES.index(f["severity"]) - vf.SEVERITIES.index(a)) for a in allowed)


def apply(f, v):
    note = v["note"].strip()
    f["verifier"] = {"verdict": v["verdict"], "note": note}
    f["evidence"] = list(f.get("evidence") or []) + list(v.get("evidence") or [])
    if v["verdict"] in ("downgraded", "changed"):
        for key in ("severity", "confidence", "reachability", "impact"):
            if key in v:
                f[key] = v[key]
        if off_table(f) == 1 and not f.get("adjust_reason"):
            f["adjust_reason"] = "verifier: " + note
        if f["confidence"] in ("inferred", "verified-partial") and not f.get("confirm_by"):
            f["confirm_by"] = "verifier: " + note


def reconcile(draft, first, second=None, keep=None, same_agent=False):
    """-> (result, summary dict). Pure function; see the module docstring."""
    doc = copy.deepcopy(draft)
    keep = keep or {}
    findings = doc.get("findings", [])
    ids = {f.get("id") for f in findings}
    notes = []
    v1, e1 = read_verdicts(first, ids, notes)
    v2, e2 = read_verdicts(second or [], ids, notes)
    counts = {"upheld": 0, "downgraded": 0, "changed": 0, "rejected": 0, "error": 0}
    needs_second, kept, moved = [], [], []
    for f in findings:
        fid = f.get("id")
        err = e2.get(fid) or (e1.get(fid) if fid not in v2 else None)
        if err:   # fail closed: the finding stays as in the draft
            f["verifier"] = {"verdict": "error", "note": "verifier output unusable: " + err}
            counts["error"] += 1
            continue
        v = v2.get(fid) or v1.get(fid)
        if not v:
            continue
        final = fid in v2
        if v["verdict"] == "rejected":
            if fid in keep:
                f["verifier"] = {"verdict": "rejected", "note": v["note"].strip() + " | auditor keeps it: " + keep[fid]}
                if f.get("confidence") not in WEAKER_THAN_PARTIAL:
                    f["confidence"] = "verified-partial"
                if not f.get("confirm_by"):
                    f["confirm_by"] = "an independent verifier rejected it: " + v["note"].strip()
                kept.append(fid)
            else:
                moved.append(fid)
            counts["rejected"] += 1
            continue
        if v["verdict"] in ("downgraded", "changed") and not final and material(f, v):
            needs_second.append(fid)
        apply(f, v)
        counts[v["verdict"]] += 1
    doc["rejected"] = list(doc.get("rejected") or []) + [
        {"id": f["id"], "title": f["title"], "reason": "independent verifier: " + v["note"].strip()}
        for f in findings if f.get("id") in moved for v in [v2.get(f["id"]) or v1[f["id"]]]]
    doc["findings"] = [f for f in findings if f.get("id") not in moved]
    members = {}
    for f in doc["findings"]:
        if f.get("path"):
            members.setdefault(f["path"], []).append(f)
    for letter, fs in sorted(members.items()):
        if len(fs) == 1:
            fs[0]["path"] = None
            notes.append("attack path %s now links only #%s, so its path was cleared: re-rate it" % (letter, fs[0]["id"]))
    checked = sum(counts.values())
    doc["verification"] = ("same-agent-fallback" if same_agent else "independent") if checked else \
        draft.get("verification", "none")
    summary = {"checked": checked, "counts": counts, "needs_second": needs_second, "kept": kept,
               "moved": moved, "notes": notes}
    return doc, summary


def summary_line(s):
    c = s["counts"]
    line = "%d finding(s) checked by an independent verifier: %d upheld, %d downgraded, %d changed, %d rejected" % (
        s["checked"], c["upheld"], c["downgraded"], c["changed"], c["rejected"])
    return line + (", %d verifier error(s)" % c["error"] if c["error"] else "")


def main(argv):
    args, firsts, second, keep, out, same = list(argv), [], [], {}, None, False
    i = 0
    while i < len(args):
        a = args[i]
        if a == "--out" and i + 1 < len(args):
            out, i = args[i + 1], i + 2
        elif a == "--second" and i + 1 < len(args):
            second.append(args[i + 1])
            i += 2
        elif a == "--keep" and i + 1 < len(args) and "=" in args[i + 1]:
            k, _, why = args[i + 1].partition("=")
            try:
                keep[int(k.lstrip("#"))] = why.strip() or "auditor disagrees"
            except ValueError:
                print("--keep needs ID=\"why\"", file=sys.stderr)
                return 2
            i += 2
        elif a == "--same-agent":
            same, i = True, i + 1
        elif a.startswith("-"):
            print("unknown option %s" % a, file=sys.stderr)
            return 2
        else:
            firsts.append(a)
            i += 1
    if len(firsts) < 2 or not out:
        print(__doc__.strip().split("\n\n")[1], file=sys.stderr)
        return 2
    draft_path, verifier_paths = firsts[0], firsts[1:]
    try:
        with open(draft_path, encoding="utf-8") as fh:
            draft = json.load(fh)
        result, s = reconcile(draft, verifier_paths, second, keep, same)
    except (OSError, ValueError) as e:
        print("unreadable input (%s)" % type(e).__name__, file=sys.stderr)
        return 2
    fd = os.open(out, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        json.dump(result, fh, indent=1, ensure_ascii=False)
        fh.write("\n")
    os.chmod(out, 0o600)
    print(summary_line(s) + ("" if not same else " (same-agent fallback, no subagents)"))
    for fid in s["needs_second"]:
        print("SECOND VERIFIER NEEDED: #%d (material change); reply via --second" % fid)
    for fid in s["kept"]:
        print("KEPT against the verifier: #%d (confidence capped at verified-partial)" % fid)
    for n in s["notes"]:
        print("note: " + n)
    problems = vf.validate(result)
    for p in problems:
        print("validate: " + p)
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
