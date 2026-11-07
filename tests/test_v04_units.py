"""Unit tests for the v0.4 parsers: mini YAML, Traefik, HAProxy, Podman (no root, no network, no engines)."""
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "scripts"))
import collect  # noqa: E402

TRAEFIK_STATIC = """
# static config
entryPoints:
  web:
    address: ":80"
  websecure:
    address: ":443"
  traefik:
    address: ":8080"
api:
  dashboard: true
  insecure: true      # the dashboard on :8080 without auth
providers:
  docker: {}
  file:
    directory: /etc/traefik/dynamic
    watch: true
"""

TRAEFIK_DYNAMIC = """
http:
  routers:
    grafana:
      rule: "Host(`grafana.example.com`)"
      entryPoints: [web]
      service: grafana
    dashboard:
      rule: Host(`traefik.example.com`) && PathPrefix(`/api`, `/dashboard`)
      entryPoints:
        - websecure
      service: api@internal
      middlewares:
        - auth
      tls:
        certResolver: le
    admin:
      rule: "Host(`shop.example.com`) && PathPrefix(`/admin`)"
      entryPoints: ["websecure"]
      middlewares: ["office@file"]
      service: shop
      tls: {}
    shop:
      rule: "Host(`shop.example.com`)"
      entryPoints:
      - websecure
      service: shop
      tls: {}
  middlewares:
    auth:
      basicAuth:
        users:
          - "admin:$apr1$FAKE$fakefakefakefakefakefa"
    office:
      chain:
        middlewares:
          - lan-only
    lan-only:
      ipAllowList:
        sourceRange: ["192.0.2.0/24"]
    long-text: |
      this block is skipped
      key: not a key
"""


def flags_from(fn, *args):
    before = len(collect.FLAGS)
    n_out = len(collect.OUT)
    fn(*args)
    got = collect.FLAGS[before:]
    del collect.FLAGS[before:]
    del collect.OUT[n_out:]
    return got


class MiniYaml(unittest.TestCase):
    def test_nested_lists_flow_and_comments(self):
        d = collect.mini_yaml(TRAEFIK_STATIC)
        self.assertEqual(d["entryPoints"]["web"]["address"], ":80")
        self.assertEqual(d["api"]["insecure"], "true")
        self.assertEqual(d["providers"]["docker"], {})
        y = collect.mini_yaml(TRAEFIK_DYNAMIC)
        r = y["http"]["routers"]
        self.assertEqual(r["grafana"]["entryPoints"], ["web"])
        self.assertEqual(r["dashboard"]["middlewares"], ["auth"])
        self.assertEqual(r["shop"]["entryPoints"], ["websecure"])  # list at the same indent as its key
        self.assertEqual(r["shop"]["service"], "shop")              # ...and the key after it
        self.assertEqual(r["admin"]["rule"], "Host(`shop.example.com`) && PathPrefix(`/admin`)")
        self.assertEqual(y["http"]["middlewares"]["auth"]["basicAuth"]["users"][0][:6], "admin:")
        self.assertNotIn("key", str(y["http"]["middlewares"].get("long-text")))

    def test_list_of_maps(self):
        d = collect.mini_yaml("ingress:\n  - hostname: a.example\n    service: http://x:1\n  - service: http_status:404\n")
        self.assertEqual(d["ingress"], [{"hostname": "a.example", "service": "http://x:1"},
                                        {"service": "http_status:404"}])

    def test_flatten_and_cli(self):
        f = collect.flatten(collect.mini_yaml(TRAEFIK_STATIC))
        self.assertEqual(f["entrypoints.web.address"], ":80")
        self.assertEqual(f["providers.file.directory"], "/etc/traefik/dynamic")
        self.assertEqual(collect.cli_flags(["traefik", "--api.insecure", "--entryPoints.web.address=:80"]),
                         {"api.insecure": "true", "entrypoints.web.address": ":80"})


class Traefik(unittest.TestCase):
    def test_model_and_auth_resolution(self):
        routers, mws = collect.traefik_model([("file", collect.flatten(collect.mini_yaml(TRAEFIK_DYNAMIC)))])
        self.assertEqual(sorted(routers), ["admin", "dashboard", "grafana", "shop"])
        self.assertTrue(collect._mw_protects("auth", mws))
        self.assertTrue(collect._mw_protects("office@file", mws))   # chain -> ipAllowList
        self.assertIsNone(collect._mw_protects("sso@docker", mws))  # defined elsewhere: unknown, not flagged
        self.assertTrue(routers["dashboard"]["tls"])
        self.assertTrue(routers["admin"]["tls"])   # tls: {}
        self.assertEqual(routers["shop"]["service"], "shop")

    def test_report_flags(self):
        static = collect.flatten(collect.mini_yaml(TRAEFIK_STATIC))
        flats = [("file", collect.flatten(collect.mini_yaml(TRAEFIK_DYNAMIC)))]
        got = "\n".join(flags_from(collect.traefik_report, static, flats))
        self.assertIn("api.insecure=true", got)
        self.assertIn("traefik router grafana (grafana.example.com) looks like an admin site and has no auth", got)
        self.assertIn("traefik router grafana (grafana.example.com) is served over plain HTTP only", got)
        self.assertNotIn("router dashboard", got)
        self.assertNotIn("router admin", got)
        self.assertNotIn("router shop", got)
        self.assertNotIn("$apr1$", "\n".join(collect.OUT))

    def test_docker_labels(self):
        labels = {"http.routers.portainer.rule": "Host(`portainer.example.com`)",
                  "http.routers.portainer.entrypoints": "websecure",
                  "http.routers.portainer.tls.certresolver": "le",
                  "http.routers.portainer.middlewares": "sso@file"}
        static = {"entrypoints.websecure.address": ":443"}
        # middleware defined in a file this host does not show: unknown, so no flag
        self.assertEqual(flags_from(collect.traefik_report, static, [("docker portainer", labels)]), [])
        labels.pop("http.routers.portainer.middlewares")
        got = flags_from(collect.traefik_report, static, [("docker portainer", labels)])
        self.assertEqual(len(got), 1)
        self.assertIn("portainer (portainer.example.com) looks like an admin site", got[0])


HAPROXY = """
global
    log /dev/log local0
    stats socket ipv4@0.0.0.0:9999 level admin
    stats socket /var/lib/haproxy/stats mode 600 level admin
defaults
    mode http
    timeout connect 5s
userlist staff
    user admin insecure-password Fake-Pa55-value
frontend public
    bind *:80
    acl is_admin path_beg /admin
    use_backend app if is_admin
    default_backend app
frontend tls
    bind *:443 ssl crt /etc/haproxy/site.pem
    http-request auth realm staff if { path_beg /admin }
    use_backend app if { path_beg /admin }
listen stats
    bind *:8404
    stats enable
    stats uri /stats
    stats admin if TRUE
listen local-stats
    bind 127.0.0.1:8405
    stats enable
    stats auth ops:Fake-Pa55-value
frontend pg
    mode tcp
    bind *:5433
    default_backend db
backend app
    server a1 127.0.0.1:8080
"""


class HAProxy(unittest.TestCase):
    def test_report_flags(self):
        got = "\n".join(flags_from(collect.haproxy_report, HAPROXY, "/etc/haproxy/haproxy.cfg", 0o644))
        self.assertIn("HAProxy runtime API on the network (stats socket ipv4@0.0.0.0:9999 level admin)", got)
        self.assertNotIn("/var/lib/haproxy/stats", got)
        self.assertIn("HAProxy userlist staff stores a plain-text password", got)
        self.assertIn("HAProxy stats page in listen stats (bind *:8404, uri /stats) has no auth and allows admin", got)
        self.assertNotIn("listen local-stats", got)                  # loopback, with stats auth
        self.assertIn("HAProxy frontend public routes admin-like paths/hosts to backend app without auth", got)
        self.assertNotIn("frontend tls routes", got)                 # http-request auth guards it
        self.assertIn("HAProxy frontend public serves plain HTTP only on *:80", got)
        self.assertNotIn("frontend pg", got)                         # tcp mode: no HTTP checks
        self.assertIn("readable by every local user and holds HAProxy passwords", got)
        self.assertNotIn("Fake-Pa55-value", got + "\n".join(collect.OUT))

    def test_private_config_not_flagged_for_mode(self):
        got = "\n".join(flags_from(collect.haproxy_report, HAPROXY, "/etc/haproxy/haproxy.cfg", 0o640))
        self.assertNotIn("readable by every local user", got)



PODMAN_PS = """[{"Id": "a1b2c3d4e5f6", "Names": ["web"], "Image": "docker.io/library/nginx:1.27", "State": "running",
  "Status": "Up 2 hours", "Command": ["nginx", "--token=never-printed"], "Labels": {"secret": "x"},
  "Ports": [{"host_ip": "", "container_port": 80, "host_port": 8080, "range": 1, "protocol": "tcp"},
            {"host_ip": "127.0.0.1", "container_port": 9090, "host_port": 9090, "range": 1, "protocol": "tcp"}]},
 {"Id": "f6e5d4c3b2a1", "Names": ["old-db"], "Image": "docker.io/library/postgres:16", "State": "exited",
  "Status": "Exited (0) 4 months ago", "Ports": [{"host_ip": "0.0.0.0", "container_port": 5432, "host_port": 5432,
  "range": 1, "protocol": "tcp"}]}]"""

QUADLET = """# ~/.config/containers/systemd/grafana.container
[Unit]
Description=Grafana

[Container]
Image=docker.io/grafana/grafana:latest
ContainerName=grafana
PublishPort=3000:3000
PublishPort=127.0.0.1:9100:9100
Volume=/etc:/host/etc
Volume=grafana-data:/var/lib/grafana
Volume=%t/podman/podman.sock:/run/podman/podman.sock
PodmanArgs=--privileged
AddCapability=NET_ADMIN SYS_TIME

[Install]
WantedBy=default.target
"""


class Podman(unittest.TestCase):
    def test_ps_json(self):
        cs = collect.podman_containers(PODMAN_PS)
        self.assertEqual([(c["name"], c["running"]) for c in cs], [("web", True), ("old-db", False)])
        self.assertEqual(cs[0]["ports"], [("", "8080", "80", "tcp"), ("127.0.0.1", "9090", "9090", "tcp")])
        self.assertNotIn("never-printed", repr(cs))
        self.assertEqual(collect.podman_containers("not json"), [])

    def test_quadlet(self):
        q = collect.quadlet_parse(QUADLET)
        self.assertEqual(q["PublishPort"], ["3000:3000", "127.0.0.1:9100:9100"])
        kinds = collect.quadlet_issues(q)
        self.assertIn(("publish", "3000"), kinds)
        self.assertNotIn(("publish", "9100"), kinds)
        self.assertIn(("privileged", ""), kinds)
        self.assertIn(("mount", "/etc -> /host/etc rw"), kinds)
        self.assertTrue(any(k == "socket" for k, _ in kinds))
        self.assertIn(("cap", "NET_ADMIN"), kinds)
        self.assertIn(("unpinned", "docker.io/grafana/grafana:latest"), kinds)
        self.assertNotIn("Description", collect.quadlet_parse(QUADLET))  # only the [Container] section


class JobsCertsReaders(unittest.TestCase):
    def test_job_files_resolve_relative_scripts(self):
        import tempfile
        d = tempfile.mkdtemp()
        try:
            os.makedirs(os.path.join(d, "nightly-backup"))
            for f in ("nightly-backup/backup.py", "run.sh"):
                open(os.path.join(d, f), "w").write("#!/bin/sh\n")
            app = os.path.join(d, "nightly-backup")
            line = "30 3 * * * cd %s && flock -n /tmp/sb.lock python3 backup.py >> logs/cron.log 2>&1" % app
            self.assertIn(os.path.join(app, "backup.py"), collect.job_files(line))
            self.assertIn(os.path.join(app, "backup.py"),
                          collect.job_files("cd ~/nightly-backup && python3 backup.py", home=d))
            self.assertIn(os.path.join(d, "run.sh"), collect.job_files("@daily ./run.sh", home=d))
            self.assertIn(os.path.join(d, "run.sh"), collect.job_files("@daily bash $HOME/run.sh", home=d))
            self.assertEqual(collect.job_files("@daily python3 missing.py", home=d), set())
        finally:
            import shutil
            shutil.rmtree(d, ignore_errors=True)

    def test_name_served(self):
        served = {"shop.example.com", "*.apps.example.com"}
        self.assertTrue(collect.name_served("shop.example.com", served))
        self.assertTrue(collect.name_served("x.apps.example.com", served))
        self.assertTrue(collect.name_served("*.example.com", {"shop.example.com"}))
        self.assertFalse(collect.name_served("old.example.com", served))
        self.assertFalse(collect.name_served("*.example.com", {"a.b.example.com"}))

    def test_readers_note_names_service_accounts(self):
        import pwd
        saved = list(collect.LISTEN), list(collect._READERS)
        try:
            del collect._READERS[:]
            collect.LISTEN[:] = [("tcp", "0.0.0.0", "8080", "python3", str(os.getpid()), "ALL"),
                                 ("tcp", "127.0.0.1", "9000", "gunicorn", str(os.getpid()), "loopback"),
                                 ("udp", "0.0.0.0", "68", "dhclient", str(os.getpid()), "ALL")]
            note = collect.readers_note()
            if os.geteuid() == 0:
                self.assertEqual(note, "")
            else:
                self.assertIn("%s (gunicorn, python3)" % pwd.getpwuid(os.geteuid()).pw_name, note)  # grouped
                self.assertIn("gunicorn", note)       # behind the proxy: still reachable
                self.assertNotIn("dhclient", note)    # udp housekeeping
        finally:
            collect.LISTEN[:], collect._READERS[:] = saved

if __name__ == "__main__":
    unittest.main()
