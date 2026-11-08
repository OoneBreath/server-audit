"""v0.4.2: drift without per-run fingerprints, Caddy mid-path wildcards, .htaccess ignored by Caddy/nginx."""

import json
import os
import shutil
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "scripts"))

import collect  # noqa: E402
import diff_state  # noqa: E402


class DriftWithoutFingerprints(unittest.TestCase):
    A = "[processes] secret in process arguments: node app.js --token <REDACTED len=40 fp=3fa9c01b77>"
    B = "[processes] secret in process arguments: node app.js --token <REDACTED len=40 fp=e01d4c9a2b>"

    def test_unfp(self):
        self.assertEqual(collect.unfp(self.A), collect.unfp(self.B))
        self.assertNotIn("fp=", collect.unfp(self.A))
        self.assertIn("len=40", collect.unfp(self.A))

    def test_same_secret_next_run_is_no_change(self):
        old = {"candidates": {"all": [self.A]}, "processes": {"x": ["--token <REDACTED len=40 fp=3fa9c01b77>"]}}
        new = {"candidates": {"all": [collect.unfp(self.B)]},
               "processes": {"x": ["--token <REDACTED len=40 fp=e01d4c9a2b>"]}}
        self.assertEqual(diff_state.diff(old, new), [])

    def test_old_baseline_with_fingerprints_loads_clean(self):
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d)
        with open(os.path.join(d, "state.json"), "w") as f:
            json.dump({"candidates": {"all": [self.A]}}, f)
        self.assertNotIn("fp=", json.dumps(diff_state.load(d)))

    def test_a_different_secret_still_shows(self):
        old = {"candidates": {"all": [self.A]}}
        new = {"candidates": {"all": [self.A.replace("--token", "--api-key")]}}
        self.assertEqual(len(diff_state.diff(old, new)), 2)


CADDY = [
    ("mail.example.com", "root * /srv/webmail"),
    ("mail.example.com", "php_fastcgi unix//run/php/php-fpm.sock"),
    ("mail.example.com", "file_server"),
    ("mail.example.com", "@internal path /config/* /logs/*"),
    ("mail.example.com", "respond @internal 403"),
    ("app.example.com", "@hidden path /api/*/admin/*"),
    ("app.example.com", "basic_auth /t/*/settings {"),
    ("app.example.com", "not path */public/*"),
    ("app.example.com", "respond /x/*/y 403"),
    ("app.example.com", "rewrite * /index.php?{query}"),
    ("app.example.com", "root * /srv/app"),
    ("app.example.com", "reverse_proxy 127.0.0.1:3000"),
    ("app.example.com", "@re path_regexp ^/api/[^/]+/admin/"),
    ("(common)", "@dash path /d/*/x"),
]


class CaddyWildcards(unittest.TestCase):
    def test_only_inner_wildcards(self):
        got = [p for _, p in collect.caddy_mid_wildcards(CADDY)]
        self.assertEqual(got, ["/api/*/admin/*", "/t/*/settings", "/x/*/y", "/d/*/x"])

    def test_examples_match_caddy_behaviour(self):
        # observed on Caddy 2.11: /a/*/b/* matches /a/x/b/y, not /a/x/b/y/z; /x/*/y not /x/x/y/y
        self.assertEqual(collect.wildcard_examples("/a/*/b/*"), ("/a/x/b/x", "/a/x/b/x/y"))
        self.assertEqual(collect.wildcard_examples("/x/*/y"), ("/x/x/y", "/x/x/y/y"))

    def test_flag_only_mixed_patterns(self):
        collect.FLAGS.clear()
        collect.OUT.clear()
        collect.caddy_wildcard_report(CADDY)
        self.assertEqual(len(collect.FLAGS), 1)
        self.assertIn("path pattern /api/*/admin/*", collect.FLAGS[0])
        self.assertIn("/api/x/admin/x/y does not", collect.FLAGS[0])
        self.assertEqual(sum("note: Caddy" in l for l in collect.OUT), 3)

    def test_roots_only_for_sites_that_serve_files(self):
        self.assertEqual(collect.caddy_roots(CADDY), [("mail.example.com", "/srv/webmail")])


class Htaccess(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.root)
        self.write("config/.htaccess", "Require all denied\n")
        self.write("logs/.htaccess", "Order deny,allow\nDeny from all\n")
        self.write("logs/old/.htaccess", "Deny from all\n")  # below a guarded dir: not listed again
        self.write("skins/.htaccess", "Options -Indexes\n")  # not a deny rule
        self.write("vendor/.htaccess", "RewriteRule ^ - [F,L]\n")
        self.write(".htaccess", "RedirectMatch 403 ^/?(config|temp|logs)/\n")
        self.write("node_modules/x/.htaccess", "Deny from all\n")  # pruned
        collect.FLAGS.clear()
        collect.OUT.clear()
        collect.WEB_ROOTS.clear()

    def write(self, rel, text):
        p = os.path.join(self.root, rel)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "w") as f:
            f.write(text)

    def test_guards(self):
        self.assertEqual(sorted(collect.htaccess_guards(self.root)), [".", "config", "logs", "vendor"])

    def test_missing_root(self):
        self.assertEqual(collect.htaccess_guards(os.path.join(self.root, "nope")), [])

    def test_flag_lists_what_the_config_does_not_block(self):
        collect.WEB_ROOTS.append(("Caddy", "mail.example.com", self.root, "@internal path /config/* respond 403"))
        collect.htaccess_report()
        self.assertEqual(len(collect.FLAGS), 1)
        f = collect.FLAGS[0]
        self.assertIn("Caddy ignores .htaccess: 3 are protected only there (/, /logs/, /vendor/)", f)
        self.assertNotIn("/config/", f)

    def test_note_when_config_names_every_dir(self):
        self.write(".htaccess", "Options -Indexes\n")
        shutil.rmtree(os.path.join(self.root, "vendor"))
        collect.WEB_ROOTS.append(("nginx", "mail.example.com", self.root, "~ ^/(config|logs)/"))
        collect.htaccess_report()
        self.assertEqual(collect.FLAGS, [])
        self.assertTrue(any("probably blocks them" in l for l in collect.OUT))


class NginxRoots(unittest.TestCase):
    def test_roots_and_deny_locations(self):
        conf = ("# configuration file /etc/nginx/conf.d/m.conf:\n"
                "server { listen 80; server_name m.example.com; root /srv/webmail;\n"
                "  location ~ ^/(config|logs)/ { deny all; }\n"
                "  location /static/ { root /srv/static; } }\n")
        servers, _ = collect.nginx_servers(collect.nginx_tree(conf))
        self.assertEqual(servers[0]["roots"], ["/srv/static", "/srv/webmail"])
        self.assertEqual([l["path"] for l in servers[0]["locations"] if l["protected"] == "deny"],
                         ["~ ^/(config|logs)/"])


if __name__ == "__main__":
    unittest.main()
