"""v0.4.4: one missed backup run in two logs is one finding; a root web app names what ufw lets reach it."""

import datetime as dt
import os
import shutil
import sys
import tempfile
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "scripts"))

import collect  # noqa: E402

NOW = dt.datetime(2026, 11, 10, 9, 0)


def reset():
    collect.FLAGS.clear()
    collect.OUT.clear()
    collect.STATE.clear()


def nightly_log(skip=(), days=10, minute=0, word="backup finished OK"):
    """One good run at 03:MM every night, except the nights in skip (days ago)."""
    lines = []
    for ago in range(days, 0, -1):
        if ago not in skip:
            t = NOW.replace(hour=3, minute=minute) - dt.timedelta(days=ago)
            lines.append("%s nightly-backup: %s" % (t.strftime("%Y-%m-%dT%H:%M:%S+00:00"), word))
    return "\n".join(lines) + "\n"


class MissedRunInSeveralLogs(unittest.TestCase):
    def setUp(self):
        reset()
        self.d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.d)
        p = mock.patch.object(collect, "downtimes", return_value=[])
        p.start()
        self.addCleanup(p.stop)

    def log(self, name, text):
        lg = os.path.join(self.d, name)
        with open(lg, "w") as f:
            f.write(text)
        return (lg, os.stat(lg))

    def test_same_hole_in_two_logs_is_one_finding(self):
        # the job writes its own log and cron redirects its stdout to a second one, a few seconds later
        logs = [self.log("nightly-backup.log", nightly_log(skip=(7,))),
                self.log("cron.log", nightly_log(skip=(7,), minute=1, word="done"))]
        collect.missed_run_report(logs, NOW)
        self.assertEqual(len(collect.FLAGS), 1, collect.FLAGS)
        f = collect.FLAGS[0]
        self.assertIn("%s and %s show no success between" % (logs[1][0], logs[0][0]), f)  # sorted by name
        self.assertIn("1 run(s) missed", f)
        # the hole both logs agree on: the later "last success" and the earlier "next success"
        self.assertIn("between 2026-11-02 03:01 and 2026-11-04 03:00", f)

    def test_different_holes_stay_separate(self):
        logs = [self.log("db.log", nightly_log(skip=(7,))), self.log("files.log", nightly_log(skip=(3,)))]
        collect.missed_run_report(logs, NOW)
        self.assertEqual(len(collect.FLAGS), 2)
        self.assertTrue(all(" shows no success between" in f for f in collect.FLAGS))

    def test_a_log_without_a_hole_adds_nothing(self):
        logs = [self.log("nightly-backup.log", nightly_log(skip=(7,))), self.log("other.log", nightly_log())]
        collect.missed_run_report(logs, NOW)
        self.assertEqual(len(collect.FLAGS), 1)
        self.assertIn("nightly-backup.log shows no success", collect.FLAGS[0])
        self.assertNotIn("other.log", collect.FLAGS[0])

    def test_unreadable_log(self):
        collect.missed_run_report([(os.path.join(self.d, "gone.log"), os.stat(self.d))], NOW)
        self.assertEqual(collect.FLAGS, [])


UFW_OUT = """Status: active
Logging: on (low)
Default: deny (incoming), allow (outgoing), disabled (routed)
New profiles: skip

To                         Action      From
--                         ------      ----
22/tcp (OpenSSH)           ALLOW IN    Anywhere
80,443/tcp (Nginx Full)    ALLOW IN    Anywhere
8500/tcp                   ALLOW IN    203.0.113.7                # admin laptop
8000:8100/tcp on wg0       ALLOW IN    Anywhere
9000/tcp                   DENY IN     Anywhere
Anywhere                   ALLOW IN    198.51.100.0/24
22/tcp (OpenSSH (v6))      ALLOW IN    Anywhere (v6)
8500/tcp (v6)              ALLOW IN    2001:db8::7
8500/tcp                   ALLOW IN    2001:db8:1::/64            # a v6 source has no (v6) tag
"""


class UfwSources(unittest.TestCase):
    def setUp(self):
        collect.ufw_load(UFW_OUT)
        self.addCleanup(collect.UFW.clear)

    def test_load(self):
        self.assertTrue(collect.UFW["active"])
        self.assertEqual(collect.UFW["default_in"], "deny")
        self.assertEqual(len(collect.UFW["rules"]), 9)
        self.assertEqual(collect.UFW["rules"][2], ("8500/tcp", "ALLOW", "IN", "203.0.113.7"))

    def test_covers(self):
        self.assertTrue(collect.ufw_covers("80,443/tcp (Nginx Full)", "443"))
        self.assertTrue(collect.ufw_covers("8000:8100/tcp on wg0", "8042"))
        self.assertFalse(collect.ufw_covers("8000:8100/tcp on wg0", "8101"))
        self.assertFalse(collect.ufw_covers("53/udp", "53"))
        self.assertTrue(collect.ufw_covers("Anywhere", "6379"))
        self.assertTrue(collect.ufw_covers("203.0.113.5 8500/tcp", "8500"))
        self.assertFalse(collect.ufw_covers("OpenSSH", "8500"))  # unexpanded profile: unknown, not counted

    def test_sources_per_address_family(self):
        # a v4-only bind ignores the v6 rule; the all-ports source counts; the deny rule does not
        self.assertEqual(collect.ufw_sources("8500", "0.0.0.0"), ["203.0.113.7", "198.51.100.0/24"])
        self.assertEqual(collect.ufw_sources("8500", "[::]"),
                         ["203.0.113.7", "198.51.100.0/24", "2001:db8::7", "2001:db8:1::/64"])
        self.assertEqual(collect.ufw_sources("8500", "2001:db8::10"), ["2001:db8::7", "2001:db8:1::/64"])
        self.assertEqual(collect.ufw_sources("8050", "0.0.0.0"), ["Anywhere on wg0", "198.51.100.0/24"])
        self.assertIn("Anywhere", collect.ufw_sources("443", "*"))

    def test_not_filtering(self):
        collect.ufw_load(UFW_OUT.replace("Default: deny (incoming)", "Default: allow (incoming)"))
        self.assertIsNone(collect.ufw_sources("8500"))
        collect.ufw_load("Status: inactive\n")
        self.assertIsNone(collect.ufw_sources("8500"))
        collect.UFW.clear()  # firewall section not run (not root)
        self.assertIsNone(collect.ufw_sources("8500"))

    def test_no_rule_for_the_port(self):
        collect.ufw_load(UFW_OUT.replace("Anywhere                   ALLOW IN    198.51.100.0/24\n", ""))
        self.assertEqual(collect.ufw_sources("7000", "0.0.0.0"), [])


class RootWebAppBehindTheFirewall(unittest.TestCase):
    def setUp(self):
        reset()
        self.listen = list(collect.LISTEN)
        self.ports = set(collect.PROXY_UPSTREAM_PORTS)
        self.addCleanup(self.restore)
        collect.ufw_load(UFW_OUT.replace("Anywhere                   ALLOW IN    198.51.100.0/24\n", ""))
        p = mock.patch.object(collect, "proc_uid", return_value=0)
        p.start()
        self.addCleanup(p.stop)

    def restore(self):
        collect.LISTEN[:] = self.listen
        collect.PROXY_UPSTREAM_PORTS.clear()
        collect.PROXY_UPSTREAM_PORTS.update(self.ports)
        collect.UFW.clear()

    def run_check(self, *listen, proxied=()):
        collect.LISTEN[:] = list(listen)
        collect.PROXY_UPSTREAM_PORTS.clear()
        collect.PROXY_UPSTREAM_PORTS.update(proxied)
        collect.root_web_services()
        self.assertEqual(len(collect.FLAGS), 1, collect.FLAGS)
        return collect.FLAGS[0]

    def test_one_source(self):
        f = self.run_check(("tcp", "0.0.0.0", "8500", "gunicorn", "201", "ALL"))
        self.assertIn("gunicorn (pid 201) runs as root and takes web traffic (0.0.0.0:8500)", f)
        self.assertTrue(f.endswith("; ufw admits port 8500 only from 203.0.113.7, not from the whole internet "
                                   "(verify outside-in)"), f)

    def test_no_allow_rule(self):
        f = self.run_check(("tcp", "0.0.0.0", "7000", "uvicorn", "202", "ALL"))
        self.assertIn("ufw admits no traffic to port 7000 from outside, so only local users and processes", f)

    def test_open_to_anywhere_adds_nothing(self):
        collect.ufw_load(UFW_OUT.replace("203.0.113.7    ", "Anywhere       "))
        f = self.run_check(("tcp", "0.0.0.0", "8500", "gunicorn", "203", "ALL"))
        self.assertTrue(f.endswith("run it as its own user"), f)

    def test_the_proxy_bypasses_the_port_rule(self):
        f = self.run_check(("tcp", "0.0.0.0", "8500", "gunicorn", "204", "ALL"), proxied=("8500",))
        self.assertIn("(0.0.0.0:8500, the reverse proxy's upstream)", f)
        self.assertIn("ufw narrows the port, but the reverse proxy forwards internet traffic to it anyway", f)
        self.assertNotIn("203.0.113.7", f)

    def test_loopback_upstream_unchanged(self):
        f = self.run_check(("tcp", "127.0.0.1", "8000", "gunicorn", "205", "loopback"), proxied=("8000",))
        self.assertTrue(f.endswith("(127.0.0.1:8000, the reverse proxy's upstream) — a remote-code-execution bug "
                                   "in that app is root on the host; run it as its own user"), f)


class WebNeedsTheFirewall(unittest.TestCase):
    def test_only_web_reads_ufw_quietly(self):
        self.assertIn("firewall", collect.NEEDS["web"])


if __name__ == "__main__":
    unittest.main()
