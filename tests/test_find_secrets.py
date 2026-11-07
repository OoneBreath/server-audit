"""End-to-end: find_secrets.py finds fake secrets, tags exposure, and never prints a value."""
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
SCRIPT = os.path.join(HERE, "..", "scripts", "find_secrets.py")

STRIPE = "sk_live_" + "51HxFAKEfake" * 3
PG = "pgFakeS3cretValue"
SHARED = "SharedFake99"
HIST_TOKEN = "ghp_" + "Fk9" * 12
OLD_KEY = "sk-ant-api03-" + "FAKEfake0123456789" * 3


def git(repo, *a):
    subprocess.run(["git", "-C", repo, "-c", "user.email=t@t", "-c", "user.name=t"] + list(a),
                   check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


class FindSecretsTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.root = tempfile.mkdtemp(prefix="sa-test-")
        r = cls.root
        os.chmod(r, 0o755)                       # traversable: app/.env 0644 is readable by everyone
        os.makedirs(os.path.join(r, "app"))
        os.chmod(os.path.join(r, "app"), 0o755)
        os.makedirs(os.path.join(r, "private"))  # 0700 dir: a 0644 file inside is NOT world-readable
        os.chmod(os.path.join(r, "private"), 0o700)
        with open(os.path.join(r, "private", ".env"), "w") as f:
            f.write("PRIVATE_API_TOKEN=Tok3nInsidePrivateDir99\n")
        os.chmod(os.path.join(r, "private", ".env"), 0o644)
        with open(os.path.join(r, "app", ".env"), "w") as f:
            f.write("STRIPE_SECRET_KEY=%s\nPOSTGRES_PASSWORD=change_me\nPANEL_PASSWORD=%s\n" % (STRIPE, SHARED))
        os.chmod(os.path.join(r, "app", ".env"), 0o644)
        with open(os.path.join(r, "app", ".env.example"), "w") as f:
            f.write("STRIPE_SECRET_KEY=sk_live_" + "EXAMPLEexample" * 2 + "\n")
        with open(os.path.join(r, "unit.service"), "w") as f:
            f.write('[Service]\nEnvironment="ADMIN_BASIC_AUTH_PASS=%s"\n' % SHARED)
        with open(os.path.join(r, ".bash_history"), "w") as f:
            f.write("ls\ngit clone https://x:%s@github.com/a/b\nexport DB_URL=postgres://u:%s@h/db\n" % (HIST_TOKEN, PG))
        os.chmod(os.path.join(r, ".bash_history"), 0o600)
        os.makedirs(os.path.join(r, ".claude"))
        with open(os.path.join(r, ".claude", "history.jsonl"), "w") as f:
            f.write('{"display":"use key %s please"}\n' % STRIPE)
        repo = os.path.join(r, "repo")
        os.makedirs(repo)
        subprocess.run(["git", "init", "-q", repo], check=True)
        subprocess.run(["git", "-C", repo, "config", "user.email", "t@t"], check=True)
        # a clone of someone else's project: commits by an identity that is not ours
        other = os.path.join(r, "thirdparty")
        os.makedirs(other)
        subprocess.run(["git", "init", "-q", other], check=True)
        subprocess.run(["git", "-C", other, "config", "user.email", "me@here"], check=True)
        with open(os.path.join(other, "settings.cfg"), "w") as f:
            f.write("UPSTREAM_TOKEN=Upstr3amHistoryToken77\n")
        subprocess.run(["git", "-C", other, "-c", "user.email=upstream@else", "-c", "user.name=u", "add", "."],
                       check=True)
        subprocess.run(["git", "-C", other, "-c", "user.email=upstream@else", "-c", "user.name=u", "commit", "-qm",
                        "x"], check=True, stdout=subprocess.DEVNULL)
        os.remove(os.path.join(other, "settings.cfg"))
        with open(os.path.join(repo, "config.py"), "w") as f:
            f.write('ANTHROPIC_API_KEY = "%s"\n' % OLD_KEY)
        git(repo, "add", "config.py")
        git(repo, "commit", "-qm", "add")
        with open(os.path.join(repo, "config.py"), "w") as f:
            f.write('ANTHROPIC_API_KEY = os.environ["ANTHROPIC_API_KEY"]\n')
        git(repo, "commit", "-qam", "remove")
        p = subprocess.run([sys.executable, "-I", SCRIPT, "--git-history", r], stdout=subprocess.PIPE,
                           stderr=subprocess.STDOUT, text=True)
        cls.out = p.stdout
        cls.rc = p.returncode

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.root, ignore_errors=True)

    def test_runs(self):
        self.assertEqual(self.rc, 0, self.out)

    def test_never_prints_values(self):
        for v in (STRIPE, PG, SHARED, HIST_TOKEN, OLD_KEY, "change_me", "51HxFAKE", "Fk9Fk9", "FAKEfake0123"):
            self.assertNotIn(v, self.out, "value leaked: %s" % v[:6])

    def test_exposure_tags(self):
        lines = self.out.splitlines()
        env = [l for l in lines if "/app/.env:" in l]
        self.assertTrue(any("WORLD-READABLE" in l and "stripe-live-key" in l for l in env), env)
        self.assertTrue(any("POSTGRES_PASSWORD" in l and "WEAK" in l for l in env), env)
        hist = [l for l in lines if ".bash_history" in l]
        self.assertTrue(any("SHELL-HISTORY" in l and "github-token" in l for l in hist), hist)
        self.assertTrue(any("url-credentials" in l for l in hist), hist)
        self.assertTrue(any("GIT-HISTORY" in l and "anthropic-key" in l for l in lines), self.out)

    def test_world_readable_means_effective_access(self):
        priv = [l for l in self.out.splitlines() if "/private/.env:" in l]
        self.assertTrue(priv, self.out)
        self.assertFalse(any("WORLD-READABLE" in l for l in priv), priv)
        self.assertNotIn("Tok3nInsidePrivateDir99", self.out)

    def test_prompt_history_is_transcript(self):
        hist = [l for l in self.out.splitlines() if ".claude/history.jsonl:" in l and "key=" in l]
        self.assertTrue(hist and all("TRANSCRIPT" in l for l in hist), hist)

    def test_third_party_history_skipped(self):
        self.assertIn("git history NOT scanned", self.out)
        self.assertIn("/thirdparty", self.out.split("git history NOT scanned")[1].splitlines()[0])
        self.assertFalse(any("thirdparty@" in l for l in self.out.splitlines()))

    def test_examples_hidden_by_default(self):
        self.assertNotIn(".env.example:", self.out)

    def test_shared_value_detected(self):
        self.assertIn("SAME VALUE UNDER DIFFERENT NAMES", self.out)
        self.assertIn("PANEL_PASSWORD", self.out.split("values found in more than one place")[1])



class OwnOutputsAndProse(unittest.TestCase):
    def test_own_reports_skipped_while_walking_but_scanned_when_named(self):
        root = tempfile.mkdtemp(prefix="sa-own-")
        try:
            run = os.path.join(root, ".server-audit", "host-20261107")
            os.makedirs(run)
            report = os.path.join(run, "report.md")
            with open(report, "w") as f:
                f.write("- SSH brute force: the guessed password = root never worked\n"
                        "DB_PASSWORD=Real1y-S3cret-v4lue-leaked\n")
            walked = subprocess.run([sys.executable, "-I", SCRIPT, root], stdout=subprocess.PIPE, text=True).stdout
            self.assertIn("hits: 0", walked)
            named = subprocess.run([sys.executable, "-I", SCRIPT, report], stdout=subprocess.PIPE, text=True).stdout
            self.assertIn("hits: 1", named)  # the leak check before a report leaves the host still works
            self.assertIn("key=DB_PASSWORD", named)
            self.assertNotIn("Real1y-S3cret", named)
        finally:
            shutil.rmtree(root, ignore_errors=True)

if __name__ == "__main__":
    unittest.main()
