"""v0.4.3: missed backup runs and outside shutdowns, quieter secret scan, less noise from sudoers and
single-operator hosts, stale sudo rules, Docker-subnet ufw rules, one drift header, masked container labels."""

import datetime as dt
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
SCRIPTS = os.path.join(HERE, "..", "scripts")
sys.path.insert(0, SCRIPTS)

import collect  # noqa: E402
import find_secrets  # noqa: E402
import secretlib  # noqa: E402

NOW = dt.datetime(2026, 11, 10, 9, 0)


def reset():
    collect.FLAGS.clear()
    collect.OUT.clear()
    collect.STATE.clear()
    collect.SUDO_ROOT.clear()
    del collect.ROOT_PATHS_BY_SUDOERS[:]


def nightly_log(skip=(), days=10, fmt="%Y-%m-%dT%H:%M:%S+00:00"):
    """A backup log: one good run at 03:00 every night, except the nights in skip (days ago)."""
    lines = []
    for ago in range(days, 0, -1):
        if ago in skip:
            continue
        t = NOW.replace(hour=3) - dt.timedelta(days=ago)
        lines.append("%s nightly-backup: archive written" % t.strftime(fmt))
        lines.append("%s nightly-backup: offsite copy OK" % (t + dt.timedelta(minutes=4)).strftime(fmt))
    return "\n".join(lines) + "\n"


class MissedRuns(unittest.TestCase):
    def test_line_time_formats(self):
        self.assertEqual(collect.line_time("2026-11-02T03:00:01+00:00 ok", NOW), dt.datetime(2026, 11, 2, 3, 0, 1))
        self.assertEqual(collect.line_time("[2026-11-02 03:00] done", NOW), dt.datetime(2026, 11, 2, 3, 0))
        self.assertEqual(collect.line_time("Nov  2 03:00:01 host backup: OK", NOW), dt.datetime(2026, 11, 2, 3, 0, 1))
        self.assertEqual(collect.line_time("Mon Nov  2 03:00:01 UTC 2026 finished", NOW),
                         dt.datetime(2026, 11, 2, 3, 0, 1))
        # syslog without a year in early January: last December, not next one
        self.assertEqual(collect.line_time("Dec 31 03:00:01 x ok", dt.datetime(2027, 1, 2)).year, 2026)
        self.assertIsNone(collect.line_time("no time here", NOW))

    def test_one_run_logs_several_success_lines(self):
        runs = collect.success_runs(nightly_log(), NOW)
        self.assertEqual(len(runs), 10)

    def test_failed_lines_are_not_successes(self):
        text = "2026-11-01T03:00:00 upload done\n2026-11-02T03:00:00 upload failed: done=0\n"
        self.assertEqual(len(collect.success_runs(text, NOW)), 1)

    def test_a_missed_night_is_a_gap(self):
        gaps, usual = collect.missed_runs(collect.success_runs(nightly_log(skip=(7,)), NOW), NOW)
        self.assertEqual(round(usual / 3600), 24)
        self.assertEqual(len(gaps), 1)
        a, b, n = gaps[0]
        self.assertEqual((b - a).days, 2)
        self.assertEqual(n, 1)

    def test_regular_runs_have_no_gap(self):
        self.assertEqual(collect.missed_runs(collect.success_runs(nightly_log(), NOW), NOW)[0], [])
        # too few runs to know the interval
        self.assertEqual(collect.missed_runs(collect.success_runs(nightly_log(days=3), NOW), NOW), ([], None))

    def test_old_gaps_are_history(self):
        gaps, _ = collect.missed_runs(collect.success_runs(nightly_log(skip=(70,), days=80), NOW), NOW)
        self.assertEqual(gaps, [])

    LAST_X = (
        "reboot   system boot  6.8.0-100-generic Mon Nov  2 20:43:10 2026   still running\n"
        "shutdown system down  6.8.0-100-generic Mon Nov  2 07:46:01 2026 - Mon Nov  2 20:43:10 2026 (12:57)\n"
        "ops      pts/0        192.0.2.10        Mon Nov  2 07:00:00 2026 - down                      (00:46)\n"
        "reboot   system boot  6.8.0-100-generic Sun Oct 25 10:00:00 2026 - Mon Nov  2 07:46:01 2026 (8+21:46)\n")

    def test_parse_downtimes(self):
        self.assertEqual(collect.parse_downtimes(self.LAST_X),
                         [(dt.datetime(2026, 11, 2, 7, 46, 1), dt.datetime(2026, 11, 2, 20, 43, 10))])

    def test_outside_shutdowns(self):
        log = ("2026-11-02T07:45:38+00:00 web-01 systemd-logind[953]: System is powering down (hypervisor initiated "
               "shutdown).\n"
               "2026-11-02T07:45:38+00:00 web-01 systemd-logind[953]: System is powering down (hypervisor initiated "
               "shutdown).\n"
               "2026-11-02T07:45:38+00:00 web-01 qemu-ga[3302]: info: guest-shutdown called, mode: powerdown\n"
               "2026-10-01T10:00:00+00:00 web-01 systemd-logind[953]: System is rebooting.\n")
        got = collect.outside_shutdowns(log)
        self.assertEqual(len(got), 1)  # the same event logged three times
        self.assertEqual(got[0][0], dt.datetime(2026, 11, 2, 7, 45, 38))

    def test_missed_run_report_names_the_downtime(self):
        reset()
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d)
        lg = os.path.join(d, "offsite.log")
        with open(lg, "w") as f:
            f.write(nightly_log(skip=(7,)))
        down = (NOW.replace(hour=1) - dt.timedelta(days=7), NOW.replace(hour=18) - dt.timedelta(days=7))
        with mock.patch.object(collect, "downtimes", return_value=[down]):
            collect.missed_run_report(lg, os.stat(lg), NOW)
        self.assertEqual(len(collect.FLAGS), 1)
        f = collect.FLAGS[0]
        self.assertIn("a missed backup run went unnoticed", f)
        self.assertIn("usually every 24 h; 1 run(s) missed", f)
        self.assertIn("the host was down", f)
        self.assertIn("(17.0 h)", f)


def mkfile(root, rel, text="x"):
    p = os.path.join(root, rel)
    os.makedirs(os.path.dirname(p), exist_ok=True)
    with open(p, "w") as f:
        f.write(text)
    return p


FAKE = "Zq8" + "rT2vLm9" * 3  # assignment-shaped fake secret
TOKEN = "ghp_" + "A1b2C3d4E5" * 4


class SecretScanCaches(unittest.TestCase):
    def setUp(self):
        self.home = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.home)
        h = self.home
        mkfile(h, ".pub-cache/hosted/pub.dev/pkg-1.0/lib/demo.dart", 'const apiKey = "%s";\n' % FAKE)
        mkfile(h, ".pub-cache/credentials.json", '{"accessToken": "%s"}\n' % TOKEN)
        mkfile(h, ".gradle/caches/x/y.properties", "password=%s\n" % FAKE)
        mkfile(h, ".gradle/gradle.properties", "signingPassword=%s\n" % FAKE)
        mkfile(h, ".windsurf-server/ext/a.js", 'token = "%s"\n' % TOKEN)
        mkfile(h, "sdk/flutter/bin/flutter", "#!/bin/sh\n")
        mkfile(h, "sdk/flutter/packages/flutter_tools/lib/x.dart", 'password: "%s"\n' % FAKE)
        mkfile(h, "android-sdk/platform-tools/conf.ini", "secret=%s\n" % FAKE)
        mkfile(h, "projects/flutter/.env", "API_TOKEN=%s\n" % FAKE)  # a project called flutter: scanned

    def scan(self, *args):
        p = subprocess.run([sys.executable, "-I", os.path.join(SCRIPTS, "find_secrets.py")] + list(args),
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=120)
        return p.stdout, p.stderr

    def test_caches_skipped_credentials_beside_them_kept(self):
        out, err = self.scan(self.home)
        for rel in (".pub-cache/credentials.json", ".gradle/gradle.properties", "projects/flutter/.env"):
            self.assertIn(os.path.join(self.home, rel), out)
        for rel in (".pub-cache/hosted", ".gradle/caches", ".windsurf-server", "sdk/flutter/packages",
                    "android-sdk/platform-tools"):
            self.assertNotIn(os.path.join(self.home, rel) + "/", out.split("skipped:")[-1].split("\n", 1)[1])
        self.assertIn("package caches / SDKs / editor servers skipped: 5", out)
        self.assertIn("scanning %s (1/1)" % self.home, err)
        self.assertIn("done in", err)

    def test_include_caches(self):
        out, _ = self.scan(self.home, "--include-caches")
        self.assertIn(os.path.join(self.home, ".windsurf-server/ext/a.js"), out)
        self.assertNotIn("skipped: 5", out)

    def test_a_cache_named_explicitly_is_scanned(self):
        out, _ = self.scan(os.path.join(self.home, ".gradle"))
        self.assertIn(os.path.join(self.home, ".gradle/caches/x/y.properties"), out)

    def test_quiet(self):
        _, err = self.scan(self.home, "--quiet")
        self.assertEqual(err, "")

    def test_max_seconds_gives_a_partial_report(self):
        out, _ = self.scan(self.home, "/etc", "--max-seconds", "0")
        self.assertIn("INCOMPLETE: stopped after", out)
        self.assertIn("not scanned: /etc", out)

    def test_since_skips_old_transcripts(self):
        old = mkfile(self.home, ".claude/projects/p/old.jsonl", '{"t": "%s"}\n' % TOKEN)
        new = mkfile(self.home, ".claude/projects/p/new.jsonl", '{"t": "%s"}\n' % TOKEN)
        t = time.time() - 40 * 86400
        os.utime(old, (t, t))
        out, _ = self.scan(os.path.join(self.home, ".claude"), "--transcripts", "--since", "30d")
        self.assertIn(new, out)
        self.assertNotIn(old, out)
        self.assertIn("transcripts older than --since skipped: 1", out)

    def test_parse_age(self):
        self.assertEqual(find_secrets.parse_age("30d"), 30 * 86400)
        self.assertEqual(find_secrets.parse_age("12h"), 12 * 3600)
        self.assertEqual(find_secrets.parse_age("2w"), 14 * 86400)
        self.assertEqual(find_secrets.parse_age("7"), 7 * 86400)

    def test_repo_lookup_is_cached_per_directory(self):
        s = find_secrets.Scanner(1 << 20, False)
        d = os.path.join(self.home, "projects", "flutter")
        with mock.patch("os.path.exists", wraps=os.path.exists) as ex:
            for i in range(50):
                s.in_repo(os.path.join(d, "f%d" % i))
            self.assertLess(ex.call_count, 20)


class DoubleMasking(unittest.TestCase):
    KEY = "ctx7sk-" + "a1b2c3d4" * 4

    def test_context7_key_masked_once(self):
        for line in ("node index.js --api-key " + self.KEY, "CONTEXT7_API_KEY=" + self.KEY,
                     '{"CONTEXT7_API_KEY": "%s"}' % self.KEY):
            m = secretlib.mask(line)
            self.assertEqual(m.count("<REDACTED"), 1, m)
            self.assertNotIn(self.KEY[7:15], m)
            self.assertIn("len=39", m)
            self.assertEqual([f["type"] for f in secretlib.scan_line(line)[1]], ["context7-key"])

    def test_sk_inside_another_word_is_not_an_openai_key(self):
        self.assertEqual(secretlib.scan_line("xsk-" + "a" * 40)[1], [])
        self.assertEqual([f["type"] for f in secretlib.scan_line("OPENAI_API_KEY=sk-proj-" + "b" * 40)[1]],
                         ["openai-key"])

    def test_long_json_lines_scan_in_linear_time(self):
        # a quoted value that never meets its closing quote made the old assignment pattern backtrack
        # quadratically (seconds per line, minutes for one large transcript)
        # e.g. an image pasted into a transcript: base64 in quotes, cut at 20000 characters before its quote
        line = '{"type":"image","data":"' + "iVBORw0KGgoAAAANSUhEUg+/" * 830
        t = time.time()
        secretlib.scan_line(line[:20000], lenient=True)
        self.assertLess(time.time() - t, 0.5)
        self.assertEqual(secretlib.scan_line('{"api_token": "%s", "n": 1}' % FAKE)[1][0]["key"], "api_token")

    def test_mask_is_idempotent(self):
        corpus = ["--api-key " + self.KEY, "--token=" + TOKEN, "https://u:%s@db.example/x" % FAKE,
                  "PASSWORD=%s" % FAKE, "Authorization: Bearer " + TOKEN, "mysql -p%s db" % FAKE,
                  "stats auth admin:%s" % FAKE, "x --token prefix" + TOKEN]
        for line in corpus:
            once = secretlib.mask(line)
            self.assertEqual(secretlib.mask(once), once, line)
            self.assertNotRegex(once, r"<REDACTED[^>]*<REDACTED|> len=\d+ fp=", line)


class SudoNoise(unittest.TestCase):
    def setUp(self):
        reset()
        self.d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.d)
        self.script = mkfile(self.d, "job.py", "print(1)\n")

    def test_writable_only_by_a_passwordless_sudoer_is_one_note(self):
        with mock.patch.object(collect, "path_writers", return_value={"ops"}):
            collect.SUDO_ROOT.add("ops")
            for unit in ("a.service", "b.service", "c.service"):
                collect.root_path_writable(unit, self.script, "services", "%s runs as root but ..." % unit)
            collect.root_path_writable("a.service", self.script, "services", "dup")
            collect.root_paths_note()
        self.assertEqual(collect.FLAGS, [])
        notes = [l for l in collect.OUT if "note (INFO)" in l]
        self.assertEqual(len(notes), 1)
        self.assertIn("3 root-run path(s) are writable only by ops", notes[0])
        self.assertIn("not an escalation path", notes[0])

    def test_other_writers_still_flag(self):
        with mock.patch.object(collect, "path_writers", return_value={"deploy"}):
            collect.SUDO_ROOT.add("ops")
            collect.root_path_writable("a.service", self.script, "services", "a.service runs as root but X")
        self.assertEqual(collect.FLAGS, ["[services] a.service runs as root but X"])
        reset()
        with mock.patch.object(collect, "path_writers", return_value={"*"}):
            collect.SUDO_ROOT.add("ops")
            collect.root_path_writable("a.service", self.script, "services", "world-writable")
        self.assertEqual(len(collect.FLAGS), 1)

    def test_path_writers(self):
        os.chmod(self.script, 0o666)
        self.assertEqual(collect.path_writers(self.script), {"*"})
        os.chmod(self.script, 0o644)
        me = __import__("pwd").getpwuid(os.getuid()).pw_name
        self.assertIn(me, collect.path_writers(self.script) if os.getuid() else {me})

    def test_nopasswd_all_fills_sudo_root(self):
        me = __import__("pwd").getpwuid(os.getuid()).pw_name
        collect.check_sudo_rule("90-init", "%s ALL=(ALL) NOPASSWD:ALL" % me)
        self.assertIn(me, collect.SUDO_ROOT)
        reset()
        collect.check_sudo_rule("90-init", "%s ALL=(ALL) ALL" % me)  # needs the password: not "already root"
        self.assertNotIn(me, collect.SUDO_ROOT)

    def test_stale_rule_for_a_missing_user(self):
        collect.check_sudo_rule("legacy", "ghost-user-x1 ALL=(ALL) NOPASSWD:ALL")
        self.assertEqual(len(collect.FLAGS), 1)
        self.assertIn("stale sudo rule for a non-existent user ghost-user-x1 (legacy)", collect.FLAGS[0])
        self.assertNotIn("root-equivalent", collect.FLAGS[0])
        self.assertNotIn("passwordless full sudo", collect.FLAGS[0])
        reset()
        collect.check_sudo_rule("legacy", "%nogroup-x1 ALL=(ALL) ALL")
        self.assertIn("non-existent group %nogroup-x1", collect.FLAGS[0])

    def test_sudo_subjects(self):
        me = __import__("pwd").getpwuid(os.getuid()).pw_name
        self.assertEqual(collect.sudo_subjects("%s,ghost-user-x1,OPS_ALIAS" % me),
                         [(me, "user", True), ("ghost-user-x1", "user", False)])


class RootWebServices(unittest.TestCase):
    def setUp(self):
        reset()
        self.listen = list(collect.LISTEN)
        self.ports = set(collect.PROXY_UPSTREAM_PORTS)
        self.addCleanup(self.restore)

    def restore(self):
        collect.LISTEN[:] = self.listen
        collect.PROXY_UPSTREAM_PORTS.clear()
        collect.PROXY_UPSTREAM_PORTS.update(self.ports)

    def test_upstream_port(self):
        self.assertEqual(collect.upstream_port("127.0.0.1:8000"), "8000")
        self.assertEqual(collect.upstream_port("http://localhost:3000/api"), "3000")
        self.assertEqual(collect.upstream_port(":8080"), "8080")
        self.assertIsNone(collect.upstream_port("10.0.0.5:8000"))
        self.assertIsNone(collect.upstream_port("unix:/run/app.sock"))

    def test_root_app_behind_the_proxy(self):
        collect.LISTEN[:] = [("tcp", "127.0.0.1", "8000", "gunicorn", "101", "loopback"),
                             ("tcp", "127.0.0.1", "9000", "python3", "102", "loopback"),   # not proxied
                             ("tcp", "0.0.0.0", "22", "sshd", "103", "ALL"),               # a daemon, not an app
                             ("tcp", "0.0.0.0", "3000", "node", "104", "ALL")]             # not root
        collect.PROXY_UPSTREAM_PORTS.add("8000")
        with mock.patch.object(collect, "proc_uid", side_effect=lambda pid: 1000 if pid == "104" else 0):
            collect.root_web_services()
        self.assertEqual(len(collect.FLAGS), 1)
        self.assertIn("gunicorn (pid 101) runs as root and takes web traffic (127.0.0.1:8000, the reverse "
                      "proxy's upstream)", collect.FLAGS[0])


class SingleOperatorData(unittest.TestCase):
    PATHS = ["/srv/app/data%d.db" % i for i in range(7)]

    def setUp(self):
        reset()
        collect._READERS[:] = [""]
        self.addCleanup(collect._READERS.clear)

    def test_one_note_when_only_the_operator_logs_in(self):
        with mock.patch.object(collect, "human_logins", return_value=["ops"]), \
                mock.patch.dict(os.environ, {"SUDO_USER": "ops"}):
            collect.world_data_report(self.PATHS)
        self.assertEqual(collect.FLAGS, [])
        notes = [l for l in collect.OUT if "note (LOW)" in l]
        self.assertEqual(len(notes), 1)
        self.assertIn("7 database/dump file(s) readable by every local user", notes[0])
        self.assertIn("no one but root and ops logs in here", notes[0])

    def test_one_candidate_with_other_people(self):
        with mock.patch.object(collect, "human_logins", return_value=["ops", "contractor"]), \
                mock.patch.dict(os.environ, {"SUDO_USER": "ops"}):
            collect.world_data_report(self.PATHS)
        self.assertEqual(len(collect.FLAGS), 1)
        self.assertIn("7 database/dump file(s)", collect.FLAGS[0])
        self.assertIn("login accounts: ops, contractor", collect.FLAGS[0])


class DockerSubnetRule(unittest.TestCase):
    def test_docker_missing(self):
        with mock.patch.object(collect, "docker_installed", return_value=False):
            n = collect.docker_subnet_note("172.20.0.0/16")
        self.assertIn("Docker is not installed", n)
        self.assertIn("delete it", n)

    def test_docker_present_or_other_source(self):
        with mock.patch.object(collect, "docker_installed", return_value=True):
            self.assertEqual(collect.docker_subnet_note("172.17.0.0/16"), " (the source is a Docker bridge subnet)")
        self.assertEqual(collect.docker_subnet_note("Anywhere"), "")
        self.assertEqual(collect.docker_subnet_note("192.0.2.10"), "")


class DriftHeader(unittest.TestCase):
    def test_one_header_naming_the_baseline(self):
        head = collect.inventory_head(["[x] a"], ["web-01-20261101-030000 (collected 2026-11-01 03:00:00)",
                                                  "+ users      login_shell            intruder:1001"], 1)
        text = "\n".join(head)
        self.assertEqual(text.count("Changes since"), 1)
        self.assertIn("Changes since web-01-20261101-030000 (collected 2026-11-01 03:00:00) — 1 (drift;", text)
        self.assertEqual(text.count("web-01-20261101-030000"), 1)

    def test_baseline_run(self):
        text = "\n".join(collect.inventory_head([], ["no previous audit of this host found — this run is the "
                                                     "baseline"], None))
        self.assertEqual(text.count("Changes since"), 1)
        self.assertIn("this run is the baseline", text)


class ContainerLabelsMasked(unittest.TestCase):
    HASH = "$apr1$" + "Ab3dE6gH" + "$" + "q" * 22
    API = "lbl" + "Xy7Kp2Qw9Rt" * 2

    def fake_run(self, cmd, timeout=30, mask=True):
        if cmd[:2] == ["docker", "ps"]:
            return 0, "proxy\napp"
        if cmd[:2] == ["docker", "inspect"]:
            labels = {"traefik.enable": "true",
                      "traefik.http.routers.admin.rule": "Host(`admin.example.com`)",
                      "traefik.http.middlewares.auth.basicauth.users": "admin:" + self.HASH,
                      "com.example.api_token": self.API}
            rows = ["/app\texample/app:1\t%s\t[]\t" % json.dumps(labels),
                    "/proxy\ttraefik:v3\t{}\t%s\t/srv/traefik=/etc/traefik;" % json.dumps(
                        ["--api.insecure=true", "--providers.http.endpoint=https://u:%s@cfg.example/x" % FAKE,
                         "--pilot.token=" + TOKEN])]
            return 0, "\n".join(rows)
        if cmd[:2] == ["systemctl", "show"]:
            return 0, "ExecStart="
        return 1, ""

    def test_no_label_or_arg_value_reaches_the_outputs(self):
        reset()
        with mock.patch.object(collect, "run", side_effect=self.fake_run), \
                mock.patch.object(collect, "have", side_effect=lambda c: c == "docker"):
            collect.sec_traefik()
        blob = "\n".join(collect.OUT + collect.FLAGS) + json.dumps(collect.STATE)
        self.assertIn("traefik", blob)  # the section did run
        for secret in (self.HASH, self.API, FAKE, TOKEN, self.HASH[6:14]):
            self.assertNotIn(secret, blob)

    def test_masked_value(self):
        self.assertNotIn(self.API, collect.masked_value("com.example.api_token", self.API))
        self.assertEqual(collect.masked_value("traefik.http.routers.a.rule", "Host(`a.example`)"), "Host(`a.example`)")

    def test_podman_fields_masked(self):
        js = json.dumps([{"Names": ["app"], "Image": "registry.example/app:1", "State": "running",
                          "Status": "Up --token=" + TOKEN, "Labels": {"api_token": self.API},
                          "Command": ["--password", FAKE], "Ports": []}])
        blob = json.dumps(collect.podman_containers(js))
        for secret in (TOKEN, self.API, FAKE):
            self.assertNotIn(secret, blob)


if __name__ == "__main__":
    unittest.main()
