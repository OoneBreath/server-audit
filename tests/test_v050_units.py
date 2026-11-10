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
    "mode": "full",
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
        self.assertEqual(set(schema["required"]), {"host", "date", "skill_version", "run_dir", "mode", "findings",
                                                   "rejected", "backup_ladder", "not_checked"})

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
