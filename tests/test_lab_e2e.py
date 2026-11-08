"""End to end on the lab containers: every planted problem is found, nothing leaks, drift sees a change.

    SERVER_AUDIT_E2E=1 python3 -m unittest tests.test_lab_e2e      # needs Docker, ~1-3 min (image builds)

lab/ubuntu (Ubuntu 24.04) and lab/rhel (AlmaLinux 9 + nginx) are deliberately misconfigured containers
with FAKE secrets generated at build time. The scripts are copied in and run as root inside them; the
outside-in probe runs from this machine against the container's address (a different host from the
container's point of view).
"""
import atexit
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ENABLED = os.environ.get("SERVER_AUDIT_E2E") == "1" and shutil.which("docker")
sys.path.insert(0, os.path.join(REPO, "scripts"))
import fleet  # noqa: E402

# one comparison key and one FAKE secret planted on every lab host: fleet.py must find the reuse
FLEET_DIR = tempfile.mkdtemp(prefix="sa-e2e-fleet-") if ENABLED else None
FLEET_KEY = os.path.join(FLEET_DIR, "fleet.key") if FLEET_DIR else None
if FLEET_DIR:
    atexit.register(shutil.rmtree, FLEET_DIR, True)
SHARED_FLEET_SECRET = "Fl33t-" + os.urandom(9).hex()
LAB_RUNS = {}


def sh(*cmd, check=True, timeout=900):
    p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=timeout)
    if check and p.returncode != 0:
        raise AssertionError("%s failed (%d):\n%s" % (" ".join(cmd), p.returncode, p.stdout[-3000:]))
    return p.stdout


class Lab:
    """Build the lab image, audit it twice (with a change in between), scan secrets, probe from outside."""
    lab = None
    hostname = None
    secret_files = ()

    @classmethod
    def setUpClass(cls):
        cls.name = "sa-e2e-%s-%d" % (cls.lab, os.getpid())
        cls.out = tempfile.mkdtemp(prefix="sa-e2e-")
        image = "server-audit-lab-%s:e2e" % cls.lab
        sh("docker", "build", "-q", "-t", image, os.path.join(REPO, "lab", cls.lab))
        sh("docker", "run", "-d", "--name", cls.name, "--hostname", cls.hostname, image)
        x = ["docker", "exec", cls.name]
        sh(*x, "sleep", "2")
        sh(*x, "mkdir", "-p", "/usr/local/lib/server-audit")
        sh("docker", "cp", os.path.join(REPO, "scripts") + "/.", cls.name + ":/usr/local/lib/server-audit/")
        cls.run1 = sh(*x, "python3", "-I", "/usr/local/lib/server-audit/collect.py")
        sh(*x, "useradd", "-m", "-s", "/bin/bash", "intruder")
        sh(*x, "sh", "-c", "cd /tmp && nohup python3 -m http.server 9999 >/dev/null 2>&1 &")
        sh(*x, "sleep", "2")
        cls.run2 = sh(*x, "python3", "-I", "/usr/local/lib/server-audit/collect.py")
        cls.secrets_out = sh(*x, "python3", "-I", "/usr/local/lib/server-audit/find_secrets.py", "--git-history",
                             "--out", "/root/secrets.txt", "/srv", "/etc", "/home", "/root", "/opt")
        sh("docker", "cp", cls.name + ":/root/.server-audit", cls.out)
        sh("docker", "cp", cls.name + ":/root/secrets.txt", cls.out)
        cls.fake = []
        for f in cls.secret_files:
            body = sh(*x, "cat", f)
            if f.endswith(".env") or "/etc/" in f:
                cls.fake += [l.split("=", 1)[1] for l in body.splitlines() if "=" in l and not l.startswith("APP_ENV")]
            cls.fake += re.findall(r'"auth": "([^"]+)"', body)
            cls.fake += re.findall(r'"access_token":"([^"]+)"', body)
            cls.fake += re.findall(r"(?m)^password = (\S+)$", body)
            cls.fake += re.findall(r'"admin:(\$apr1\$[^"]+)"', body)
            cls.fake += re.findall(r"insecure-password (\S+)", body)
        cls.fake.append(SHARED_FLEET_SECRET)
        cls.ip = sh("docker", "inspect", "-f", "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}",
                    cls.name).strip()
        cls.probe = cls.run_probe()
        cls.fleet_scan(x)
        runs = sorted(os.listdir(os.path.join(cls.out, ".server-audit")))
        cls.inv1, cls.inv2 = [open(os.path.join(cls.out, ".server-audit", r, "inventory.txt")).read() for r in runs]
        cls.state2 = json.load(open(os.path.join(cls.out, ".server-audit", runs[1], "state.json")))
        cls.secrets = open(os.path.join(cls.out, "secrets.txt")).read()

    @classmethod
    def run_probe(cls):
        return ""

    @classmethod
    def fleet_scan(cls, x):
        """Plant the shared FAKE secret, scan with the comparison key on stdin, keep state + report for fleet.py."""
        if not os.path.exists(FLEET_KEY):
            fleet.main(["fleet.py", "key", "--file", FLEET_KEY])
        sh(*x, "sh", "-c", "mkdir -p /srv/fleet && echo SHARED_SERVICE_TOKEN=%s > /srv/fleet/app.env"
           % SHARED_FLEET_SECRET)
        with open(FLEET_KEY) as k:
            p = subprocess.run(["docker", "exec", "-i", cls.name, "python3", "-I",
                                "/usr/local/lib/server-audit/find_secrets.py", "--fleet-key-stdin", "--out",
                                "/root/fleet-secrets.txt", "/srv/fleet", "/etc"], stdin=k,
                               stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=600)
        assert p.returncode == 0, p.stdout[-2000:]
        cls.fleet_out = p.stdout
        d = os.path.join(FLEET_DIR, cls.hostname)
        os.makedirs(d, exist_ok=True)
        runs = sorted(os.listdir(os.path.join(cls.out, ".server-audit")))
        shutil.copy(os.path.join(cls.out, ".server-audit", runs[-1], "state.json"), os.path.join(d, "state.json"))
        sh("docker", "cp", cls.name + ":/root/fleet-secrets.txt", os.path.join(d, "secrets.txt"))
        LAB_RUNS[cls.hostname] = d

    @classmethod
    def tearDownClass(cls):
        subprocess.run(["docker", "rm", "-f", cls.name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        shutil.rmtree(cls.out, ignore_errors=True)

    def candidates(self):
        return self.inv1.split("\nChanges since")[0]

    def assert_candidates(self, needles):
        c = self.candidates()
        for needle in needles:
            with self.subTest(needle=needle):
                self.assertIn(needle, c)

    def test_drift_sees_the_change(self):
        self.assertIn("this run is the baseline", self.inv1)
        self.assertEqual(self.inv2.count("\nChanges since "), 1)  # one header line, naming the baseline
        drift = self.inv2.split("\nChanges since ")[1].split("\n\n")[0]
        self.assertIn("intruder", drift)
        self.assertIn("9999", drift)
        self.assertTrue(drift.startswith(self.hostname + "-"), drift.splitlines()[0])

    def test_nothing_leaks(self):
        self.assertTrue(self.fake)
        blobs = [self.inv1, self.inv2, json.dumps(self.state2), self.secrets, self.run1, self.run2,
                 self.secrets_out, self.probe, self.fleet_out,
                 open(os.path.join(LAB_RUNS[self.hostname], "secrets.txt")).read()]
        for value in self.fake:
            if len(value) < 12:
                continue
            for b in blobs:
                self.assertNotIn(value, b, "a fake secret value leaked into an output")

    def test_no_section_crashed(self):
        self.assertNotRegex(self.inv1 + self.inv2, r"\(section \w+ failed")


@unittest.skipUnless(ENABLED, "set SERVER_AUDIT_E2E=1 (needs Docker)")
class UbuntuLab(Lab, unittest.TestCase):
    lab, hostname = "ubuntu", "staging-01"
    secret_files = ("/srv/shop/.env", "/home/deploy/.docker/config.json", "/etc/traefik/dynamic/routers.yml")

    @classmethod
    def run_probe(cls):
        urls = os.path.join(cls.out, "urls.txt")
        with open(urls, "w") as f:
            f.write("http://%s:8080/ 2xx\nhttp://%s:8080/.env 401|403\nhttp://%s:8082/admin/ 401|403\n"
                    % (cls.ip, cls.ip, cls.ip))
        return sh("bash", os.path.join(REPO, "scripts", "probe_external.sh"), cls.ip, "--ports", "22,6379,8080",
                  "--delay", "0", "--urls", urls)

    def test_planted_problems_are_candidates(self):
        self.assert_candidates([
            "PasswordAuthentication yes",
            "lets deploy run `/usr/bin/less /var/log/shop/*`",
            "stale sudo rule for a non-existent user ghost (ghost)",
            "root cron runs /home/deploy/sync.sh which is writable by non-root",
            "readable by every local user: /srv/shop/.env",
            "/srv/shop/.git exists inside a web root",
            "port 6379) listens on ALL interfaces",
            "Cloudflare Tunnel publishes staging-admin.example.com -> http://localhost:8080",
            "/home/deploy/.docker/config.json stores registry credentials",
            "/etc/cron.d/shop look addressed to an AI agent",
            "/var/log/auth.log look addressed to an AI agent",
            "account deploy can log in (password) but has never logged in",
            "backups exist only on this host",
            "backup failures alert nobody",
            "last status line in /var/log/shop/backup.log reports a problem",
            "Traefik API and dashboard are served without auth (api.insecure=true)",
            "traefik router grafana (grafana.staging.example.com) looks like an admin site and has no auth middleware",
            "traefik router grafana (grafana.staging.example.com) is served over plain HTTP only",
        ])
        self.assertNotIn("router dashboard", self.candidates())  # behind basicAuth

    def test_state_has_the_sections(self):
        for section in ("host", "network", "ssh", "users", "cron", "backups", "candidates", "_meta"):
            self.assertIn(section, self.state2)
        self.assertEqual(self.state2["backups"]["ladder"]["offsite"], "no")
        self.assertEqual(self.state2["backups"]["ladder"]["deletable_from_host"], "n/a (no offsite copy)")

    def test_secret_scan(self):
        s = self.secrets
        self.assertIn("stripe-live-key", s)
        self.assertIn("GIT-HISTORY", s)
        self.assertRegex(s, r"WORLD-READABLE.*/etc/shop/backup.conf")
        self.assertIn("key=PGPASSWORD", s)
        self.assertIn("/home/deploy/.docker/config.json", s)
        self.assertRegex(s, r"apr1-hash.*/etc/traefik/dynamic/routers.yml")
        reuse = s.split("values found in more than one place")[1]
        self.assertRegex(reuse, r"fp=\w+.*\n(?:.*\n){2,}")

    def test_fleet_of_labs(self):
        """Runs last (classes run in name order): compares this lab with the RHEL lab when both ran."""
        if len(LAB_RUNS) < 2:
            self.skipTest("needs both labs in one run")
        out = os.path.join(FLEET_DIR, "fleet.txt")
        self.assertEqual(fleet.main(["fleet.py", "compare"] + sorted(LAB_RUNS.values()) + ["--out", out]), 0)
        rep = open(out).read()
        self.assertNotIn(SHARED_FLEET_SECRET, rep)
        self.assertIn("1 secret value(s) are the same on several hosts", rep)
        self.assertRegex(rep, r"under SHARED_SERVICE_TOKEN on 2 hosts")
        self.assertIn("staging-01", rep)
        self.assertIn("web-01", rep)
        self.assertIn("web-01: its offsite backup can be deleted from the host itself", rep)
        self.assertIn("staging-01: backups exist only on that host", rep)
        fleet.main(["fleet.py", "key", "--delete", "--file", FLEET_KEY])
        self.assertFalse(os.path.exists(FLEET_KEY))

    def test_probe_from_outside(self):
        self.assertRegex(self.probe, r"8080 open")
        self.assertRegex(self.probe, r"6379 open")
        self.assertIn("SSH offers password", self.probe)
        self.assertIn("MISMATCH got 200 expected 401|403  http://%s:8080/.env" % self.ip, self.probe)
        self.assertIn("MISMATCH got 200 expected 401|403  http://%s:8082/admin/" % self.ip, self.probe)
        self.assertIn("^ answered from a cache (CF-Cache-Status: HIT Age: 120)", self.probe)
        self.assertNotIn("from a cache", self.probe.split("8082/admin/")[0])  # the plain app is not a cache


@unittest.skipUnless(ENABLED, "set SERVER_AUDIT_E2E=1 (needs Docker)")
class RhelLab(Lab, unittest.TestCase):
    lab, hostname = "rhel", "web-01"
    secret_files = ("/opt/shop/.env", "/root/.config/rclone/rclone.conf", "/etc/haproxy/haproxy.cfg")

    @classmethod
    def run_probe(cls):
        urls = os.path.join(cls.out, "urls.txt")
        with open(urls, "w") as f:
            f.write("http://%s/admin/ 401|403\n" % cls.ip)
        return sh("bash", os.path.join(REPO, "scripts", "probe_external.sh"), cls.ip, "--ports", "22,80,8080",
                  "--delay", "0", "--urls", urls)

    def test_planted_problems_are_candidates(self):
        self.assert_candidates([
            "PermitRootLogin yes",
            "a missed backup run went unnoticed: /var/log/shop/cron.log and /var/log/shop/offsite.log show no "
            "success between",
            "nginx shop.example.com: location /admin/ serves http://127.0.0.1:8080 without auth",
            "nginx webmail.example.com serves /srv/webmail, but nginx ignores .htaccess: 2 are protected only "
            "there (/config/, /logs/)",
            "nginx shop.example.com: autoindex on at /files/",
            "nginx grafana.example.com looks like an admin site",
            "nginx shop.example.com is served over plain HTTP only",
            "firewalld is installed but not running",
            "SELinux is Disabled on a RHEL-family host",
            "SUID/SGID binary not from a package: /usr/local/bin/findx",
            "readable by every local user: /opt/shop/.env",
            "the offsite backup can be deleted from this host: rclone remote gcrypt over gdrive (drive)",
            "rclone sync mirrors deletions to the offsite copy",
            "HAProxy runtime API on the network (stats socket ipv4@0.0.0.0:9999 level admin)",
            "HAProxy userlist staff stores a plain-text password",
            "HAProxy stats page in listen stats (bind *:8404, uri /stats) has no auth and allows admin actions",
            "HAProxy frontend public routes admin-like paths/hosts to backend app without auth",
            "/etc/haproxy/haproxy.cfg is readable by every local user and holds HAProxy passwords",
        ])
        self.assertNotIn("/private/", self.candidates())  # protected by auth_basic

    def test_rhel_facts(self):
        self.assertRegex(self.inv1, r"os: AlmaLinux 9")
        self.assertIn("end of standard support: 2032-05-31", self.inv1)
        self.assertIn("dnf: no usable local metadata cache", self.inv1)
        self.assertIn("nginx_sites", self.state2.get("web", {}))
        ladder = self.state2["backups"]["ladder"]
        self.assertEqual((ladder["offsite"], ladder["encrypted"], ladder["deletable_from_host"]),
                         ("rclone", "yes", "yes"))

    def test_one_missed_run_one_candidate(self):
        missed = [c for c in self.state2["candidates"]["all"] if "a missed backup run went unnoticed" in c]
        self.assertEqual(len(missed), 1, missed)

    def test_only_backups_still_sees_cron_jobs(self):
        x = ["docker", "exec", self.name]
        sh(*x, "python3", "-I", "/usr/local/lib/server-audit/collect.py", "--only", "backups", "--out", "/root/only")
        inv = sh(*x, "cat", "/root/only/inventory.txt")
        self.assertIn("offsite=rclone", inv)
        self.assertIn("the offsite backup can be deleted from this host", inv)
        self.assertNotIn("== CRON & TIMERS", inv)

    def test_probe_from_outside(self):
        self.assertRegex(self.probe, r"80 open")
        self.assertIn("MISMATCH", self.probe)


if __name__ == "__main__":
    unittest.main()
