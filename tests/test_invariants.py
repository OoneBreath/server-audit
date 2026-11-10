"""Guarantees the skill makes, enforced on the source code.

1. The scripts that read secrets or host state (collect.py, find_secrets.py, secretlib.py, diff_state.py,
   validate_findings.py) contain no network code. dns_check.py does DNS lookups only and reads/writes no files.
2. collect.py only runs commands from an explicit read-only allowlist. Adding a command means adding
   it here on purpose, where a reviewer sees it.
3. collect.py writes only inventory.txt and state.json in its own output directory (one write helper);
   find_secrets.py writes only --out.
"""
import os
import re
import unittest

SCRIPTS = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "scripts")


def src(name):
    with open(os.path.join(SCRIPTS, name)) as f:
        return f.read()


NETWORK = re.compile(
    r"\bimport\s+(urllib|http|requests|httpx|aiohttp|ftplib|smtplib|telnetlib|paramiko|ssl)\b|"
    r"\bfrom\s+(urllib|http|requests|httpx|aiohttp|ftplib|smtplib|telnetlib|paramiko|ssl)\b|"
    r"socket\.(socket|create_connection|getaddrinfo)\b|urlopen|"
    r"""\[\s*["'](curl|wget|nc|ncat|netcat|ssh|scp|sftp|rsync|telnet|socat)["']"""
)

# (command, first argument or None) pairs collect.py may run. All read-only.
READ_ONLY = {
    ("apt", "list"), ("systemctl", "is-enabled"), ("systemctl", "is-active"), ("systemctl", "list-units"),
    ("systemctl", "show"), ("systemctl", "--failed"), ("systemctl", "list-timers"), ("timedatectl", "show"),
    ("ip", "-br"), ("ip", "-6"), ("ss", "-H"), ("ufw", "status"), ("iptables", "-S"), ("iptables", "-t"),
    ("ip6tables", "-S"), ("nft", "list"), ("docker", "ps"), ("docker", "inspect"), ("sshd", "-T"),
    ("/usr/sbin/sshd", "-T"), ("ssh-keygen", "-lf"), ("last", "-n"), ("journalctl", "-u"), ("caddy", "version"),
    ("nginx", "-T"), ("apache2ctl", "-S"), ("openssl", "x509"), ("find", None), ("dpkg", "-S"),
    ("fail2ban-client", "status"), ("cscli", "bouncers"), ("aa-status", None), ("sysctl", None), ("ps", "-eo"),
    ("ip", "-o"), ("docker", "image"), ("lastlog", None), ("df", None), ("journalctl", "--disk-usage"),
    ("du", "-sxk"), ("apachectl", "-S"), ("dnf", "-C"), ("needs-restarting", "-r"), ("firewall-cmd", "--state"),
    ("firewall-cmd", "--get-active-zones"), ("firewall-cmd", "--list-all"), ("getenforce", None), ("rpm", "-qf"), ("podman", "ps"), ("podman", "inspect"),
    ("last", "-x"), ("journalctl", "-t"),
}
GIT_READ_ONLY = {"remote", "rev-parse", "ls-files"}


class Invariants(unittest.TestCase):
    def test_no_network_code_where_secrets_are_read(self):
        for name in ("collect.py", "find_secrets.py", "secretlib.py", "diff_state.py", "validate_findings.py"):
            for i, line in enumerate(src(name).splitlines(), 1):
                self.assertIsNone(NETWORK.search(line), "%s:%d has network code: %s" % (name, i, line.strip()))

    def test_collect_runs_only_read_only_commands(self):
        s = src("collect.py")
        calls = re.findall(r"""\b(?:run|show)\(\s*\[\s*"([^"]+)"(?:\s*,\s*"([^"]*)")?""", s)
        self.assertGreater(len(calls), 20)
        for cmd, arg in calls:
            ok = (cmd, arg) in READ_ONLY or (cmd, None) in READ_ONLY
            self.assertTrue(ok, "collect.py runs a command not on the read-only list: %s %s" % (cmd, arg))
        # sysctl: never with -w or key=value
        for m in re.finditer(r'run\(\["sysctl"\][^)]*\)', s):
            self.assertNotIn("-w", m.group(0))
        # git subcommands go through g + [...]
        for sub in re.findall(r'g \+ \["([^"]+)"', s):
            self.assertIn(sub, GIT_READ_ONLY, "git %s is not read-only-listed" % sub)
        # find must never delete or exec
        self.assertNotRegex(s, r'"-delete"|"-exec"|"-execdir"|"-ok"')
        # docker image: inspect only
        for m in re.finditer(r'\["docker",\s*"image",\s*"([^"]+)"', s):
            self.assertEqual(m.group(1), "inspect")

    def test_collect_writes_only_its_output_files(self):
        s = src("collect.py")
        writes = re.findall(r"open\([^)]*,\s*\"[wa]", s)
        self.assertEqual(len(writes), 1, writes)
        self.assertIn('assert os.path.basename(path) in ("inventory.txt", "state.json")', s)
        for bad in ("os.remove", "os.unlink", "shutil.rmtree", "os.rename", "shutil.move", "os.replace"):
            self.assertNotIn(bad, s)

    def test_find_secrets_writes_only_out(self):
        s = src("find_secrets.py")
        self.assertEqual(len(re.findall(r"open\([^)]*,\s*\"[wa]", s)), 1)
        self.assertIn("with open(args.out, \"w\")", s)

    def test_dns_check_touches_no_files(self):
        s = src("dns_check.py")
        self.assertNotRegex(s, r"\bopen\(|os\.(remove|unlink|rename)|shutil\.(copy|move|rmtree)|\.write\(")
        cmds = re.findall(r'subprocess\.run\(\s*\[\s*"([^"]+)"', s)
        self.assertTrue(cmds)
        self.assertEqual(set(cmds), {"dig"})

    def test_diff_state_writes_nothing(self):
        self.assertNotRegex(src("diff_state.py"), r"open\([^)]*,\s*[\"'][wa]")

    def test_reconcile_writes_only_out_and_runs_nothing(self):
        s = src("reconcile.py")
        self.assertIsNone(NETWORK.search(s))
        self.assertEqual(len(re.findall(r"\bos\.open\(", s)), 1)                     # the one write: --out, 0600
        self.assertNotRegex(s, r"(?<!fd)open\([^)]*,\s*[\"'][wa]")              # no other file opened for writing
        self.assertIn("fd = os.open(out,", s)
        self.assertNotRegex(s, r"os\.(remove|unlink|rename|replace)|shutil\.|subprocess")

    def test_validate_findings_writes_nothing_and_runs_nothing(self):
        s = src("validate_findings.py")
        self.assertNotRegex(s, r"open\([^)]*,\s*[\"'][wa]|os\.(remove|unlink|rename|replace)|shutil\.|subprocess")

    def test_probe_refuses_self(self):
        s = src("probe_external.sh")
        self.assertIn("REFUSED", s)
        self.assertNotRegex(s, r"api\.ipify|ifconfig\.me|icanhazip|ipinfo\.io")  # no third-party calls


if __name__ == "__main__":
    unittest.main()
