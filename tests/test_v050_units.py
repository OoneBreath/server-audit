"""v0.5.0: findings.json is a validated contract (scripts/validate_findings.py). All secret-looking
values below are fake and built at run time."""

import copy
import json
import os
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
SCRIPTS = os.path.join(HERE, "..", "scripts")
sys.path.insert(0, SCRIPTS)

import validate_findings as vf  # noqa: E402

FAKE_STRIPE = "sk_live_" + "51Hx" * 6


def finding(fid, **kw):
    f = {"id": fid, "title": "Redis on a public address without auth", "area": "exposure", "severity": "HIGH",
         "confidence": "verified-outside", "status": "open", "path": None, "reachability": "internet-no-auth",
         "impact": "data-or-control",
         "evidence": [{"command": "ss -tlnp 'sport = :6379'", "observation": "0.0.0.0:6379 redis-server",
                       "where": "inside"},
                      {"command": "probe_external.sh 203.0.113.10", "observation": "6379 open, PING answered",
                       "where": "outside"}],
         "verifier": None}
    f.update(kw)
    return f


VALID = {
    "host": "web1", "date": "2026-11-10", "skill_version": "0.5.0", "run_dir": "~/.server-audit/web1-2026-11-10",
    "mode": "full", "verification": "independent",
    "findings": [
        finding(1, path="A"),
        finding(2, title="Docker publishes the Redis port past ufw", area="exposure", severity="MEDIUM",
                reachability="internet-one-control", path="A"),
        finding(3, title="DB_PASSWORD=<REDACTED> in /srv/app/.env, world-readable", area="secrets",
                severity="MEDIUM", reachability="local-users", confidence="inferred",
                confirm_by="ls -l /srv/app/.env on the host",
                evidence=[{"command": "find_secrets.py /srv/app", "observation": "DB_PASSWORD=*** (masked)",
                           "where": "inside"}]),
        finding(4, title="No HSTS header", area="tls", severity="LOW", reachability="internet-no-auth",
                impact="hardening", verifier={"verdict": "upheld", "note": "curl -sI shows no HSTS"}),
    ],
    "rejected": [{"id": 5, "title": "Port 8080 open", "reason": "bound to 127.0.0.1 (ss -tlnp)"}],
    "backup_ladder": {"exists": True, "fresh": True, "offsite": False, "encrypted": None,
                      "deletable_from_host": None, "restore_tested": None},
    "not_checked": ["offsite backup copy (needs the operator)"],
}


def problems(doc):
    return list(vf.validate(doc))


def mutate(fn):
    doc = copy.deepcopy(VALID)
    fn(doc)
    return problems(doc)


class Validator(unittest.TestCase):
    def test_valid_document(self):
        self.assertEqual(problems(VALID), [])

    def test_missing_field(self):
        p = mutate(lambda d: d["findings"][0].pop("impact"))
        self.assertTrue(any("$.findings[0]: missing field 'impact'" == x for x in p), p)
        self.assertTrue(mutate(lambda d: d.pop("rejected")))
        self.assertTrue(mutate(lambda d: d["backup_ladder"].pop("offsite")))

    def test_bad_enum(self):
        p = mutate(lambda d: d["findings"][0].update(severity="CRITICAL"))
        self.assertTrue(any(".severity" in x and "not one of" in x for x in p), p)
        self.assertTrue(mutate(lambda d: d["findings"][0].update(area="network")))
        self.assertTrue(mutate(lambda d: d.update(mode="quick")))

    def test_severity_outside_the_table_needs_adjust_reason(self):
        p = mutate(lambda d: d["findings"][3].update(severity="MEDIUM"))   # hardening × internet = LOW
        self.assertTrue(any("give adjust_reason" in x for x in p), p)
        self.assertEqual(mutate(lambda d: d["findings"][3].update(severity="MEDIUM",
                                                                  adjust_reason="customer data on the host")), [])

    def test_two_levels_off_is_never_valid(self):
        p = mutate(lambda d: d["findings"][3].update(severity="HIGH", adjust_reason="feels bad"))
        self.assertTrue(any("2 levels" in x for x in p), p)

    def test_medium_high_cell_accepts_both(self):
        self.assertEqual(mutate(lambda d: d["findings"][1].update(severity="HIGH")), [])

    def test_hardening_that_needs_root_is_info_only(self):
        p = mutate(lambda d: d["findings"][3].update(reachability="needs-root", severity="LOW",
                                                     adjust_reason="x"))
        self.assertTrue(any("must be INFO" in x for x in p), p)
        self.assertEqual(mutate(lambda d: d["findings"][3].update(reachability="needs-root", severity="INFO")), [])

    def test_inferred_without_confirm_by(self):
        p = mutate(lambda d: d["findings"][2].pop("confirm_by"))
        self.assertTrue(any("needs confirm_by" in x for x in p), p)

    def test_duplicate_id(self):
        p = mutate(lambda d: d["rejected"][0].update(id=1))
        self.assertTrue(any("duplicate id 1" in x for x in p), p)
        self.assertTrue(mutate(lambda d: d["findings"][1].update(id=1)))

    def test_a_path_joins_two_findings(self):
        p = mutate(lambda d: d["findings"][1].update(path=None))
        self.assertTrue(any("attack path A links only one finding" in x for x in p), p)

    def test_restore_tested_needs_a_restore(self):
        p = mutate(lambda d: d["backup_ladder"].update(restore_tested=True))
        self.assertTrue(any("restore_tested" in x for x in p), p)
        def with_restore(d):
            d["backup_ladder"]["restore_tested"] = True
            d["findings"][0]["evidence"].append({"command": "restic restore latest --target /tmp/r",
                                                 "observation": "restored 2 GB", "where": "inside"})
        self.assertEqual(mutate(with_restore), [])

    def test_a_secret_in_a_title_fails(self):
        p = mutate(lambda d: d["findings"][0].update(title="Stripe key " + FAKE_STRIPE + " in app.js"))
        self.assertTrue(any("secret value" in x for x in p), p)
        self.assertNotIn(FAKE_STRIPE, "\n".join(p))           # the problem never repeats the value

    def test_a_fingerprint_in_a_note_fails(self):
        p = mutate(lambda d: d["findings"][3].update(verifier={"verdict": "upheld", "note": "same key, fp=1a2b3c4d"}))
        self.assertTrue(any("fingerprint" in x for x in p), p)
        p = mutate(lambda d: d["findings"][2]["evidence"][0].update(observation="<REDACTED len=43 fp=07d6ac7e>"))
        self.assertTrue(any("fingerprint" in x for x in p), p)

    def test_masked_values_pass(self):
        for masked in ("PASSWORD=<REDACTED len=14>", "token ***", "key sk_live_…", "api_key = <redacted>"):
            self.assertEqual(mutate(lambda d: d["findings"][2]["evidence"][0].update(observation=masked)), [], masked)


class Cli(unittest.TestCase):
    def run_cli(self, doc=None, raw=None, *flags):
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as fh:
            fh.write(raw if raw is not None else json.dumps(doc))
        try:
            return subprocess.run([sys.executable, "-I", os.path.join(SCRIPTS, "validate_findings.py"), fh.name, *flags],
                                  capture_output=True, text=True)
        finally:
            os.unlink(fh.name)

    def test_exit_codes(self):
        self.assertEqual(self.run_cli(VALID).returncode, 0)
        bad = copy.deepcopy(VALID)
        bad["findings"][0]["severity"] = "CRITICAL"
        r = self.run_cli(bad)
        self.assertEqual(r.returncode, 1)
        self.assertRegex(r.stdout, r"^\$\.findings\[0\]\.severity: ")
        self.assertEqual(self.run_cli(raw="{not json").returncode, 2)

    def test_quiet(self):
        r = self.run_cli(VALID, None, "--quiet")
        self.assertEqual((r.returncode, r.stdout, r.stderr), (0, "", ""))


class SchemaAndDocs(unittest.TestCase):
    def test_schema_enums_match_the_validator(self):
        with open(os.path.join(HERE, "..", "references", "findings-schema.json")) as fh:
            schema = json.load(fh)
        props = schema["properties"]["findings"]["items"]["properties"]
        self.assertEqual(props["area"]["enum"], vf.AREAS)
        self.assertEqual(set(props["severity"]["enum"]), set(vf.SEVERITIES))
        self.assertEqual(props["confidence"]["enum"], vf.CONFIDENCE)
        self.assertEqual(props["reachability"]["enum"], vf.REACHABILITY)
        self.assertEqual(props["impact"]["enum"], vf.IMPACT)
        self.assertEqual(set(schema["required"]), {"host", "date", "skill_version", "run_dir", "mode", "verification",
                                                   "findings", "rejected", "backup_ladder", "not_checked"})

    def test_one_area_per_checks_md_section(self):
        with open(os.path.join(HERE, "..", "references", "checks.md")) as fh:
            sections = [l for l in fh if l.startswith("## ") and l[3:4].isdigit()]
        self.assertEqual(len(sections), len(vf.AREAS))

    def test_the_template_example_is_valid(self):
        with open(os.path.join(HERE, "..", "references", "report-template.md")) as fh:
            text = fh.read()
        block = text.split("```json", 1)[1].split("```", 1)[0]
        self.assertEqual(problems(json.loads(block)), [])


if __name__ == "__main__":
    unittest.main()


import reconcile as rc  # noqa: E402


def draft():
    d = copy.deepcopy(VALID)
    d["verification"] = "none"
    for f in d["findings"]:
        f["verifier"] = None
    return d


class Reconcile(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()

    def tearDown(self):
        import shutil
        shutil.rmtree(self.dir)

    def jsonl(self, name, *lines):
        path = os.path.join(self.dir, name)
        with open(path, "w") as fh:
            fh.write("\n".join(l if isinstance(l, str) else json.dumps(l) for l in lines) + "\n")
        return path

    def run_rc(self, lines, second=None, keep=None, same=False):
        first = [self.jsonl("v1.jsonl", *lines)]
        sec = [self.jsonl("v2.jsonl", *second)] if second else None
        return rc.reconcile(draft(), first, sec, keep, same)

    def by_id(self, doc, fid):
        return next(f for f in doc["findings"] if f["id"] == fid)

    def test_upheld_records_the_verdict_and_adds_evidence(self):
        ev = {"command": "ss -tlnp 'sport = :6379'", "observation": "0.0.0.0:6379", "where": "inside"}
        doc, s = self.run_rc([{"id": 1, "verdict": "upheld", "severity": "HIGH", "confidence": "verified-outside",
                               "note": "still listening on all interfaces", "evidence": [ev]}])
        f = self.by_id(doc, 1)
        self.assertEqual(f["verifier"], {"verdict": "upheld", "note": "still listening on all interfaces"})
        self.assertEqual(f["evidence"][-1], ev)
        self.assertEqual((s["checked"], s["counts"]["upheld"], doc["verification"]), (1, 1, "independent"))
        self.assertEqual(list(vf.validate(doc)), [])

    def test_downgrade_applies_and_one_level_off_table_gets_adjust_reason(self):
        doc, s = self.run_rc([{"id": 1, "verdict": "downgraded", "severity": "MEDIUM", "confidence": "verified-inside",
                               "note": "a CDN-only firewall rule limits it"}])
        f = self.by_id(doc, 1)
        self.assertEqual((f["severity"], f["confidence"]), ("MEDIUM", "verified-inside"))
        self.assertEqual(f["adjust_reason"], "verifier: a CDN-only firewall rule limits it")
        self.assertEqual(s["needs_second"], [])
        self.assertEqual(list(vf.validate(doc)), [])

    def test_material_change_needs_a_second_verifier_whose_verdict_is_final(self):
        drop = {"id": 1, "verdict": "downgraded", "severity": "LOW", "confidence": "verified-inside",
                "note": "redis requires a password"}
        _, s = self.run_rc([drop])
        self.assertEqual(s["needs_second"], [1])
        moved = {"id": 2, "verdict": "changed", "severity": "MEDIUM", "confidence": "verified-inside",
                 "reachability": "local-users", "note": "the port is not published"}
        _, s = self.run_rc([moved])
        self.assertEqual(s["needs_second"], [2])                      # reachability class changed
        second = {"id": 1, "verdict": "upheld", "severity": "HIGH", "confidence": "verified-outside",
                  "note": "no password: PING answers without AUTH"}
        doc, s = self.run_rc([drop], second=[second])
        self.assertEqual(s["needs_second"], [])
        self.assertEqual(self.by_id(doc, 1)["severity"], "HIGH")
        self.assertEqual(self.by_id(doc, 1)["verifier"]["verdict"], "upheld")

    def test_rejected_moves_to_rejected_and_a_lone_path_is_cleared(self):
        doc, s = self.run_rc([{"id": 2, "verdict": "rejected", "note": "DOCKER-USER drops it before DNAT"}])
        self.assertNotIn(2, [f["id"] for f in doc["findings"]])
        self.assertIn({"id": 2, "title": "Docker publishes the Redis port past ufw",
                       "reason": "independent verifier: DOCKER-USER drops it before DNAT"}, doc["rejected"])
        self.assertIsNone(self.by_id(doc, 1)["path"])                  # path A had #1 and #2
        self.assertTrue(any("attack path A" in n for n in s["notes"]))
        self.assertEqual(list(vf.validate(doc)), [])

    def test_keep_disputes_a_rejection_and_caps_confidence(self):
        doc, s = self.run_rc([{"id": 1, "verdict": "rejected", "note": "bound to 127.0.0.1"}],
                             keep={1: "outside-in probe answered PING"})
        f = self.by_id(doc, 1)
        self.assertEqual(f["confidence"], "verified-partial")
        self.assertIn("auditor keeps it: outside-in probe answered PING", f["verifier"]["note"])
        self.assertTrue(f["confirm_by"])
        self.assertEqual(s["kept"], [1])
        self.assertEqual(list(vf.validate(doc)), [])

    def test_malformed_verifier_output_fails_closed(self):
        before = self.by_id(draft(), 4)
        bad = [
            "not json at all",
            {"id": 4, "verdict": "fine", "severity": "LOW", "confidence": "verified-inside", "note": "x"},
        ]
        doc, s = self.run_rc(bad)
        f = self.by_id(doc, 4)
        self.assertEqual(f["verifier"]["verdict"], "error")
        self.assertEqual({k: f[k] for k in ("severity", "confidence", "evidence")},
                         {k: before[k] for k in ("severity", "confidence", "evidence")})
        self.assertTrue(any("not JSON" in n for n in s["notes"]))
        for line in ({"id": 4, "verdict": "upheld", "severity": "LOW", "confidence": "verified-inside",
                      "note": "key is " + FAKE_STRIPE},                                   # a secret
                     {"id": 4, "verdict": "upheld", "severity": "LOW", "confidence": "verified-inside",
                      "note": "same key fp=1a2b3c4d"},                                     # a fingerprint
                     {"id": 4, "verdict": "upheld", "severity": "LOW", "confidence": "verified-inside",
                      "note": "ok", "extra": 1}):                                          # unknown key
            doc, _ = self.run_rc([line])
            self.assertEqual(self.by_id(doc, 4)["verifier"]["verdict"], "error", line)
            self.assertNotIn(FAKE_STRIPE, json.dumps(doc))
        ok = {"id": 4, "verdict": "upheld", "severity": "LOW", "confidence": "verified-inside", "note": "ok"}
        doc, _ = self.run_rc([ok, ok])                                                     # duplicate verdicts
        self.assertEqual(self.by_id(doc, 4)["verifier"]["verdict"], "error")

    def test_cli_writes_only_out_with_mode_600_and_prints_the_summary(self):
        d = os.path.join(self.dir, "draft.json")
        with open(d, "w") as fh:
            json.dump(draft(), fh)
        v = self.jsonl("v.jsonl", {"id": 1, "verdict": "upheld", "severity": "HIGH", "confidence": "verified-outside",
                                   "note": "confirmed"},
                       {"id": 2, "verdict": "rejected", "note": "not published"})
        out = os.path.join(self.dir, "findings.json")
        r = subprocess.run([sys.executable, "-I", os.path.join(SCRIPTS, "reconcile.py"), d, v, "--out", out,
                            "--same-agent"], capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("2 finding(s) checked by an independent verifier: 1 upheld, 0 downgraded, 0 changed, 1 rejected",
                      r.stdout)
        self.assertEqual(oct(os.stat(out).st_mode & 0o777), "0o600")
        with open(out) as fh:
            self.assertEqual(json.load(fh)["verification"], "same-agent-fallback")
        self.assertEqual(sorted(os.listdir(self.dir)), ["draft.json", "findings.json", "v.jsonl"])


class Modes(unittest.TestCase):
    def test_mode_table_names_real_sections_and_checks(self):
        import re
        root = os.path.join(HERE, "..")
        with open(os.path.join(root, "SKILL.md")) as fh:
            skill = fh.read()
        modes = skill.split("## Modes", 1)[1].split("\n## ", 1)[0]
        rows = [l for l in modes.splitlines() if l.startswith("| ") and not l.startswith("| Question") and "---" not in l]
        self.assertGreaterEqual(len(rows), 10)
        with open(os.path.join(SCRIPTS, "collect.py")) as fh:
            collect = fh.read()
        sections = set(re.findall(r"\bsec_(\w+)", collect.split("SECTIONS = [", 1)[1].split("]", 1)[0]))
        with open(os.path.join(root, "references", "checks.md")) as fh:
            headings = [l[3:].strip() for l in fh if l.startswith("## ") and l[3:4].isdigit()]
        for row in rows:
            cells = [c.strip() for c in row.strip("|").split("|")]
            self.assertEqual(len(cells), 4, row)
            for name in re.findall(r"[a-z]+", cells[1].split("(")[0]):
                self.assertIn(name, sections, "%s: not a collect.py section" % name)
            for entry in cells[2].split(";"):
                entry = entry.strip()
                self.assertTrue(any(h.startswith(entry) for h in headings), "%r is not a checks.md section" % entry)
            self.assertIn("HIGH", cells[3])

    def test_description_mentions_both_uses_and_stays_short(self):
        with open(os.path.join(HERE, "..", "SKILL.md")) as fh:
            desc = next(l for l in fh if l.startswith("description: "))
        self.assertIn("full audit", desc)
        self.assertIn("focused question", desc)
        self.assertLess(len(desc), 1200)


class SeverityAnchors(unittest.TestCase):
    # (anchor from SKILL.md, impact, reachability, severity): each must be allowed by the validator's table
    ANCHORS = [
        ("Redis/Postgres on a public address without auth", "data-or-control", "internet-no-auth", "HIGH"),
        (".env or .git served over HTTP by the proxy", "data-or-control", "internet-no-auth", "HIGH"),
        ("admin panel open to the internet without a login", "data-or-control", "internet-no-auth", "HIGH"),
        ("Docker socket in an internet-facing container", "data-or-control", "internet-one-control", "HIGH"),
        ("a leaked secret that still works", "data-or-control", "internet-no-auth", "HIGH"),
        ("sudo rule that is root in disguise for a login account", "data-or-control", "local-users", "MEDIUM"),
        ("admin route behind basic auth alone, over HTTP", "data-or-control", "internet-one-control", "MEDIUM"),
        ("backups that are not offsite", "availability", "internet-one-control", "MEDIUM"),
        ("ufw allow rule with nothing listening", "hardening", "internet-no-auth", "LOW"),
        ("missing HSTS header", "hardening", "internet-no-auth", "LOW"),
        ("password auth offered, only key accounts", "hardening", "internet-no-auth", "LOW"),
        ("anything only root can reach", "data-or-control", "needs-root", "INFO"),
    ]

    def test_anchors_agree_with_the_table(self):
        for name, impact, reach, sev in self.ANCHORS:
            self.assertIn(sev, vf.TABLE[impact][reach], name)

    def test_skill_md_carries_the_anchors_and_the_rules(self):
        with open(os.path.join(HERE, "..", "SKILL.md")) as fh:
            skill = fh.read()
        for phrase in ("Anchors on Linux hosts", "without guessing a password", "in one sentence",
                       "Docker socket", "missing HSTS header", "only root can reach"):
            self.assertIn(phrase, skill)


import coverage as cov  # noqa: E402

INVENTORY = """server-audit inventory
==============================================================================
== HOST
==============================================================================
user: ops (NOT root — partial)
==============================================================================
== SSH
==============================================================================
(skipped: needs root — rerun with sudo for this section)
==============================================================================
== BACKUPS
==============================================================================
(section backups failed: OSError: x)
==============================================================================
== FIREWALL
==============================================================================
ufw not installed
"""


def full_coverage(status="checked"):
    return {"run": "web1-x", "areas": [{"area": a, "status": status, "reason": "" if status == "checked" else "r"}
                                       for a in vf.AREAS]}


class Coverage(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()

    def tearDown(self):
        import shutil
        shutil.rmtree(self.dir)

    def test_valid_coverage(self):
        self.assertEqual(list(cov.validate(full_coverage(), VALID)), [])

    def test_every_area_exactly_once_and_reasons(self):
        c = full_coverage()
        c["areas"].pop()
        c["areas"].append(dict(c["areas"][0]))
        p = list(cov.validate(c))
        self.assertTrue(any("appears 0 times" in x for x in p), p)
        self.assertTrue(any("appears 2 times" in x for x in p), p)
        c = full_coverage()
        c["areas"][3] = {"area": c["areas"][3]["area"], "status": "degraded", "reason": ""}
        self.assertTrue(any("needs a reason" in x for x in cov.validate(c)))
        c["areas"][3]["status"] = "half-done"
        self.assertTrue(any("not one of" in x for x in cov.validate(c)))

    def test_not_checked_areas_must_be_in_the_reports_list(self):
        c = full_coverage()
        c["areas"][[e["area"] for e in c["areas"]].index("backups")] = {"area": "backups", "status": "not-checked",
                                                                       "reason": "no access to the backup host"}
        doc = copy.deepcopy(VALID)
        doc["not_checked"] = ["DNS records (no zone access)"]
        self.assertTrue(any("backups is not-checked" in x for x in cov.validate(c, doc)))
        doc["not_checked"] = ["Backups & recovery: no access to the backup host"]
        self.assertEqual(list(cov.validate(c, doc)), [])

    def test_seed_marks_skipped_and_partial_sections_degraded(self):
        with open(os.path.join(self.dir, "inventory.txt"), "w") as fh:
            fh.write(INVENTORY)
        data = cov.seed(self.dir)
        st = {e["area"]: e["status"] for e in data["areas"]}
        self.assertEqual(sorted(a for a, s in st.items() if s == "degraded"), ["backups", "ssh", "updates"])
        self.assertEqual(st["exposure"], "not-checked")          # "ufw not installed" is a fact, not a gap
        self.assertEqual(st["operator"], "needs-operator")
        self.assertEqual(len(data["areas"]), len(vf.AREAS))

    def test_seed_cli_writes_600_and_never_overwrites(self):
        with open(os.path.join(self.dir, "inventory.txt"), "w") as fh:
            fh.write(INVENTORY)
        script = os.path.join(SCRIPTS, "coverage.py")
        r = subprocess.run([sys.executable, "-I", script, "seed", self.dir], capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr)
        out = os.path.join(self.dir, "coverage.json")
        self.assertEqual(oct(os.stat(out).st_mode & 0o777), "0o600")
        r = subprocess.run([sys.executable, "-I", script, "seed", self.dir], capture_output=True, text=True)
        self.assertEqual(r.returncode, 1)

    def test_gaps_reads_the_previous_run(self):
        base = os.path.join(self.dir, "audits")
        for run, status in (("web1-20261001-0900", "not-checked"), ("web1-20261101-0900", "degraded"),
                            ("web1-20261110-0900", None), ("db1-20261105-0900", "degraded")):
            os.makedirs(os.path.join(base, run))
            if status:
                c = full_coverage()
                c["areas"][0] = {"area": "exposure", "status": status, "reason": "no root"}
                with open(os.path.join(base, run, "coverage.json"), "w") as fh:
                    json.dump(c, fh)
        run, items = cov.gaps("web1", base, exclude=os.path.join(base, "web1-20261110-0900"))
        self.assertEqual(run, "web1-20261101-0900")              # newest earlier run with coverage, same host
        self.assertEqual(items, [("exposure", "degraded", "no root")])
        self.assertEqual(cov.gaps("mail1", base), (None, []))

    def test_validate_findings_cli_with_coverage(self):
        f = os.path.join(self.dir, "findings.json")
        c = os.path.join(self.dir, "coverage.json")
        with open(f, "w") as fh:
            json.dump(VALID, fh)
        bad = full_coverage()
        bad["areas"].pop()
        with open(c, "w") as fh:
            json.dump(bad, fh)
        r = subprocess.run([sys.executable, "-I", os.path.join(SCRIPTS, "validate_findings.py"), f, "--coverage", c],
                           capture_output=True, text=True)
        self.assertEqual(r.returncode, 1)
        self.assertIn("coverage.json $.areas: area fleet appears 0 times", r.stdout)

    def test_fleet_compare_shows_coverage_per_host(self):
        import fleet
        runs = []
        for host, status in (("web1", "checked"), ("db1", "degraded")):
            runs.append({"host": host, "collected": "2026-11-10", "root": True, "secrets": [], "secrets_file": False,
                         "key_id": None, "state": {"_meta": {"host": host}}, "coverage": full_coverage(status)["areas"]})
        _, sections, _ = fleet.compare(runs)
        body = dict(sections).get("coverage per host")
        self.assertTrue(body, [n for n, _ in sections])
        self.assertTrue(any(l.startswith("db1") and "exposure" in l for l in body), body)
