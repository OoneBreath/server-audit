"""fleet.py: the comparison key, cross-host fingerprints and the comparison itself. All values are fake."""
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
SCRIPTS = os.path.join(HERE, "..", "scripts")
sys.path.insert(0, SCRIPTS)
import fleet  # noqa: E402

SECRET = "Fl33t-Sh4red-Pa55word-x9"


def state(host, ssh_pw="no", sec=0, eol_days=900, offsite="rclone", key_fp="SHA256:" + "A" * 43, extra_listener=None,
          candidates=()):
    listeners = ["tcp ALL 22 sshd", "tcp ALL 443 caddy"] + ([extra_listener] if extra_listener else [])
    return {
        "_meta": {"host": host, "collected": "2026-11-07 10:00:00", "root": True},
        "_fleet": {"eol": "2029-05-31", "eol_days": eol_days, "security_updates": sec, "reboot_required": "no",
                   "auto_updates": "unattended-upgrades enabled"},
        "host": {"os": "Ubuntu 24.04.5 LTS", "kernel": "6.8.0-147-generic"},
        "firewall": {"ufw_status": "active"},
        "ssh": {"effective": {"passwordauthentication": ssh_pw, "permitrootlogin": "no"},
                "keys /home/ops/.ssh/authorized_keys": ["256 %s ops@laptop (ED25519)" % key_fp]},
        "network": {"listeners": listeners},
        "backups": {"ladder": {"exists": "yes", "fresh": "yes", "offsite": offsite, "encrypted": "yes",
                               "deletable_from_host": "yes" if offsite != "no" else "n/a (no offsite copy)",
                               "alerts": "configured", "restore_tested": "unknown (ask)"}},
        "candidates": {"all": list(candidates)},
    }


class FleetKeyAndScan(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def keyfile(self):
        path = os.path.join(self.tmp, "fleet.key")
        self.assertEqual(fleet.main(["fleet.py", "key", "--file", path]), 0)
        return path

    def scan(self, root, keyfile=None):
        out = os.path.join(root, "secrets.txt")
        cmd = [sys.executable, "-I", os.path.join(SCRIPTS, "find_secrets.py"), "--out", out, root]
        if keyfile:
            cmd.insert(3, "--fleet-key-stdin")
        with open(keyfile) if keyfile else open(os.devnull) as stdin:
            subprocess.run(cmd, stdin=stdin, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
        return open(out).read()

    def host_dir(self, name, line):
        d = os.path.join(self.tmp, name)
        os.makedirs(d)
        with open(os.path.join(d, "app.env"), "w") as f:
            f.write(line + "\n")
        return d

    def test_key_file_is_private_and_never_printed(self):
        path = self.keyfile()
        self.assertEqual(stat.S_IMODE(os.stat(path).st_mode), 0o600)
        k = open(path).read().strip()
        self.assertRegex(k, r"^[0-9a-f]{64}$")
        fleet.main(["fleet.py", "key", "--delete", "--file", path])
        self.assertFalse(os.path.exists(path))

    def test_same_value_same_xfp_across_hosts_only_with_the_key(self):
        path = self.keyfile()
        a = self.scan(self.host_dir("a", "DB_PASSWORD=" + SECRET), path)
        b = self.scan(self.host_dir("b", "SMTP_PASSWORD=" + SECRET), path)
        key = open(path).read().strip()
        for rep in (a, b):
            self.assertNotIn(SECRET, rep)
            self.assertNotIn(key, rep)
            self.assertIn("fleet key id: %s" % fleet.key_id(key), rep)
        xa = [l.split("xfp=")[1].split()[0] for l in a.splitlines() if "xfp=" in l and "key=" in l]
        xb = [l.split("xfp=")[1].split()[0] for l in b.splitlines() if "xfp=" in l and "key=" in l]
        self.assertEqual(xa, xb)
        fa = [l.split(" fp=")[1].split()[0] for l in a.splitlines() if " fp=" in l and "key=" in l]
        fb = [l.split(" fp=")[1].split()[0] for l in b.splitlines() if " fp=" in l and "key=" in l]
        self.assertNotEqual(fa, fb)  # per-run fingerprints stay incomparable
        self.assertNotIn("xfp=", self.scan(self.host_dir("c", "DB_PASSWORD=" + SECRET)))

    def test_bad_key_on_stdin_is_refused(self):
        d = self.host_dir("d", "DB_PASSWORD=" + SECRET)
        p = subprocess.run([sys.executable, "-I", os.path.join(SCRIPTS, "find_secrets.py"), "--fleet-key-stdin", d],
                           input="not-hex\n", text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.assertNotEqual(p.returncode, 0)

    def test_compare_end_to_end(self):
        path = self.keyfile()
        runs = []
        for name, line, st in (
                ("web-01", "DB_PASSWORD=" + SECRET, state("web-01", candidates=["[ssh] PasswordAuthentication yes"])),
                ("web-02", "SMTP_PASSWORD=" + SECRET,
                 state("web-02", ssh_pw="yes", sec=7, offsite="no", extra_listener="tcp ALL 6379 redis-server",
                       candidates=["[ssh] PasswordAuthentication yes"])),
                ("db-01", "OTHER_TOKEN=Unrelated-Value-123456", state("db-01", key_fp="SHA256:" + "B" * 43))):
            d = self.host_dir(name, line)
            self.scan(d, path)
            with open(os.path.join(d, "state.json"), "w") as f:
                json.dump(st, f)
            runs.append(d)
        out = os.path.join(self.tmp, "fleet.txt")
        self.assertEqual(fleet.main(["fleet.py", "compare"] + runs + ["--out", out]), 0)
        self.assertEqual(stat.S_IMODE(os.stat(out).st_mode), 0o600)
        rep = open(out).read()
        self.assertNotIn(SECRET, rep)
        self.assertIn("web-02: 7 security updates pending", rep)
        self.assertIn("sshd: password login is on for web-02", rep)
        self.assertIn("1 SSH key(s) authorized on several hosts", rep)
        self.assertIn("web-01 (ops), web-02 (ops)", rep)
        self.assertIn("6379/tcp (redis-server) on all interfaces: only on web-02", rep)
        self.assertIn("web-02: backups exist only on that host", rep)
        self.assertIn("1 secret value(s) are the same on several hosts", rep)
        self.assertRegex(rep, r"under DB_PASSWORD, SMTP_PASSWORD on 2 hosts")
        self.assertIn("PasswordAuthentication yes  — on web-01, web-02", rep)
        js = os.path.join(self.tmp, "fleet.json")
        fleet.main(["fleet.py", "compare"] + runs + ["--json", "--out", js])
        self.assertEqual(json.load(open(js))["hosts"], ["db-01", "web-01", "web-02"])

    def test_reports_from_different_keys_are_not_compared(self):
        runs = []
        for name in ("a1", "a2"):
            path = self.keyfile()  # a new key each time
            d = self.host_dir(name, "DB_PASSWORD=" + SECRET)
            self.scan(d, path)
            json.dump(state(name), open(os.path.join(d, "state.json"), "w"))
            runs.append(d)
        hosts, sections, findings = fleet.compare([fleet.load_run(r) for r in runs])
        self.assertIn("different comparison keys", "\n".join(dict(sections)["the same secret on several hosts"]))


if __name__ == "__main__":
    unittest.main()
