"""End to end against a real Podman engine (CI runner; needs root and network to pull a small image).

    sudo SERVER_AUDIT_PODMAN_E2E=1 python3 -m unittest tests.test_podman_e2e

Starts a privileged rootful container with a published port, creates a stopped one, writes a rootful and a
rootless quadlet, audits with `collect.py --only podman`, and removes everything again.
"""
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ENABLED = (os.environ.get("SERVER_AUDIT_PODMAN_E2E") == "1" and shutil.which("podman") and os.geteuid() == 0)
IMAGE = "docker.io/library/alpine:3.20"
ROOTFUL_Q = "/etc/containers/systemd/sa-grafana.container"
HOME = os.environ.get("SUDO_HOME") or "/home/" + (os.environ.get("SUDO_USER") or "runner")
ROOTLESS_Q = os.path.join(HOME, ".config/containers/systemd/sa-rootless.container")


def sh(*cmd):
    p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=600)
    if p.returncode != 0:
        raise AssertionError("%s failed:\n%s" % (" ".join(cmd), p.stdout[-2000:]))
    return p.stdout


@unittest.skipUnless(ENABLED, "set SERVER_AUDIT_PODMAN_E2E=1 and run as root with podman installed")
class PodmanE2E(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.out = tempfile.mkdtemp(prefix="sa-podman-")
        sh("podman", "pull", "-q", IMAGE)
        sh("podman", "run", "-d", "--name", "sa-pm-web", "-p", "18080:80", "--privileged", IMAGE, "sleep", "600")
        sh("podman", "create", "--name", "sa-pm-old", "-p", "15432:5432", IMAGE, "true")
        os.makedirs(os.path.dirname(ROOTFUL_Q), exist_ok=True)
        with open(ROOTFUL_Q, "w") as f:
            f.write("[Container]\nImage=docker.io/grafana/grafana:latest\nContainerName=sa-grafana\n"
                    "PublishPort=13000:3000\nPodmanArgs=--privileged\n")
        os.makedirs(os.path.dirname(ROOTLESS_Q), exist_ok=True)
        with open(ROOTLESS_Q, "w") as f:
            f.write("[Container]\nImage=docker.io/library/nginx:1.27\nPublishPort=13001:80\nVolume=/etc:/x\n")
        sh(sys.executable, "-I", os.path.join(REPO, "scripts", "collect.py"), "--only", "podman", "--out", cls.out)
        cls.inv = open(os.path.join(cls.out, "inventory.txt")).read()

    @classmethod
    def tearDownClass(cls):
        subprocess.run(["podman", "rm", "-f", "sa-pm-web", "sa-pm-old"], stdout=subprocess.DEVNULL,
                       stderr=subprocess.DEVNULL)
        for p in (ROOTFUL_Q, ROOTLESS_Q):
            if os.path.exists(p):
                os.remove(p)
        shutil.rmtree(cls.out, ignore_errors=True)

    def candidates(self):
        return self.inv.split("\nChanges since")[0]

    def test_rootful_containers(self):
        c = self.candidates()
        self.assertIn("rootful Podman container sa-pm-web publishes host port 18080/tcp on ALL interfaces", c)
        self.assertIn("rootful Podman container sa-pm-web runs --privileged", c)
        self.assertIn("stopped rootful Podman container sa-pm-old (", c)
        self.assertNotIn("(section podman failed", self.inv)

    def test_quadlets(self):
        c = self.candidates()
        self.assertIn("rootful Podman quadlet sa-grafana (%s) publishes host port 13000" % ROOTFUL_Q, c)
        self.assertIn("rootful Podman quadlet sa-grafana (%s) runs --privileged" % ROOTFUL_Q, c)
        self.assertIn("rootless Podman quadlet sa-rootless (%s) publishes host port 13001" % ROOTLESS_Q, c)
        self.assertIn("rootless Podman quadlet sa-rootless (%s) mounts /etc -> /x rw" % ROOTLESS_Q, c)

    def test_state_and_no_section_crash(self):
        self.assertIn("rootful containers: 2", self.inv)
        self.assertIn("container details (no env vars shown):", self.inv)


if __name__ == "__main__":
    unittest.main()
