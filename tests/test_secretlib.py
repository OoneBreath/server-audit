"""Masking must never let a value through. All values below are fake."""
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "scripts"))
import secretlib  # noqa: E402

FAKE = {
    "anthropic": "sk-ant-api03-" + "A1b2C3d4E5f6G7h8I9j0" * 3,
    "stripe": "sk_live_" + "51Hx" * 6,
    "whsec": "whsec_" + "q9W8e7R6t5Y4u3I2" * 2,
    "github": "ghp_" + "Zx9" * 12,
    "aws": "AKIA" + "ABCDEFGHIJKLMNOP",
    "jwt": "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dBjftJeZ4CVPmB92K27uhbUJU1p1r_wW1gFWFOEjXk",
    "bcrypt": "$2a$14$" + "a" * 53,
}


class MaskTests(unittest.TestCase):
    def assertMasked(self, line, *secrets):
        masked, findings = secretlib.scan_line(line)
        for s in secrets:
            self.assertNotIn(s, masked, "value leaked: %r -> %r" % (line, masked))
            for f in findings:
                self.assertNotIn(s, repr(f))
        self.assertTrue(findings, "nothing found in %r" % line)
        return masked, findings

    def test_known_tokens(self):
        for name, v in FAKE.items():
            with self.subTest(name=name):
                self.assertMasked("some text %s more" % v, v)

    def test_env_assignments(self):
        self.assertMasked("STRIPE_SECRET_KEY=" + FAKE["stripe"], FAKE["stripe"])
        self.assertMasked("export INGEST_TOKEN=Qm9vbGVhbkFsZ2VicmE", "Qm9vbGVhbkFsZ2VicmE")
        self.assertMasked('POSTGRES_PASSWORD="change_me"', "change_me")
        self.assertMasked("ADMIN_BASIC_AUTH_PASS = hunter2hunter2", "hunter2hunter2")
        self.assertMasked('{"api_key": "abcd1234efgh5678"}', "abcd1234efgh5678")
        self.assertMasked('Environment="RUNNER_EXECUTE_TOKEN=tok_9f8e7d6c5b4a"', "tok_9f8e7d6c5b4a")
        self.assertMasked("password: S3cr3t-Pa55-W0rd", "S3cr3t-Pa55-W0rd")

    def test_printf_format_is_a_placeholder(self):
        self.assertEqual(secretlib.scan_line("printf 'DB_PASSWORD=%s\\n' \"$PW\"")[1], [])
        self.assertEqual(secretlib.scan_line("API_TOKEN=%-20s")[1], [])

    def test_glued_key_names(self):
        # found by the lab audit: PGPASSWORD was neither detected nor masked
        for key in ("PGPASSWORD", "SMTPPASSWORD", "MYSQLPASSWD", "APPSECRET", "CSRFTOKEN", "REDISCLI_AUTH", "PGPASS"):
            with self.subTest(key=key):
                self.assertMasked("%s=Xk3_9fQ-2mZpL0aBcD7eFgHi" % key, "Xk3_9fQ-2mZpL0aBcD7eFgHi")
        for key in ("TOKENIZER", "SECRETARY", "PASSPORT", "OLDPWD"):
            with self.subTest(key=key):
                self.assertFalse(secretlib.SECRET_KEY.search(key), key)

    def test_yaml_colon_values_still_found(self):
        self.assertMasked("password: hunter2", "hunter2")
        self.assertMasked("password: secret", "secret")
        self.assertMasked("db_password: correcthorsebattery", "correcthorsebattery")

    def test_weak_flag(self):
        _, f = secretlib.scan_line('POSTGRES_PASSWORD="change_me"')
        self.assertTrue(f[0]["weak"])
        _, f = secretlib.scan_line("ADMIN_PASSWORD=Ab3dEf7h")  # 8 chars
        self.assertTrue(f[0]["weak"])
        _, f = secretlib.scan_line("ADMIN_PASSWORD=Ab3dEf7hKk2mQq9zWw")
        self.assertFalse(f[0]["weak"])

    def test_url_and_cli(self):
        self.assertMasked("DATABASE_URL=postgresql://app:pgS3cretValue@db:5432/app", "pgS3cretValue")
        self.assertMasked("git remote https://user:ghp_" + "Zx9" * 12 + "@github.com/x/y", "Zx9Zx9Zx9")
        self.assertMasked("curl -u admin:Tr0ub4dor https://x", "Tr0ub4dor")
        self.assertMasked("mysql -h db -pVeryS3cret db", "VeryS3cret")
        self.assertMasked("app --password=Hunter2Hunter2 --verbose", "Hunter2Hunter2")
        self.assertMasked('curl -H "Authorization: Bearer abcdef0123456789abcdef"', "abcdef0123456789abcdef")

    def test_placeholders_not_flagged(self):
        for line in ("API_KEY=", "API_KEY=${API_KEY}", "TOKEN=<your token>", "PASSWORD=xxxx",
                     "SECRET_KEY=your_secret_here", "SSL_KEY_FILE=/etc/ssl/private/k.key",
                     "token_ttl=3600", "PASSWORD_MIN_LENGTH=12", "author=someone",
                     "(`--password=…`, `mysql -p…`, tokens)"):
            with self.subTest(line=line):
                _, f = secretlib.scan_line(line)
                self.assertEqual(f, [], line)

    def test_prose_lenient_only_for_detection(self):
        for line in ("- accounts with empty password: HIGH.",
                     "!! full sudo without password: any process running as ubuntu can become root"):
            self.assertEqual(secretlib.scan_line(line, lenient=True)[1], [], line)
        self.assertEqual(secretlib.scan_line('"password_reset": "Reset your password now"', lenient=True)[1], [])
        # masking stays strict: an unquoted YAML passphrase with spaces is still redacted
        masked, f = secretlib.scan_line("password: my very secret phrase")
        self.assertNotIn("very secret phrase", masked)
        self.assertTrue(f)

    def test_code_expressions_not_flagged(self):
        for line in ('password1 = getpass("Password: ")', "password_hash = generate_password_hash(pw)",
                     'section_token = ("[%s]" % s)', "API_KEY = os.environ['API_KEY']",
                     "secret = settings.SECRET_KEY", "token = None", "const apiKey = process.env.API_KEY"):
            with self.subTest(line=line):
                self.assertEqual(secretlib.scan_line(line, code=True)[1], [], line)
        # an unquoted identifier is a variable in code, but a value in a .env file
        self.assertEqual(secretlib.scan_line("password = pw_value", code=True)[1], [])
        self.assertTrue(secretlib.scan_line("password = pw_value_long", code=False)[1])
        # quoted literals in code still count
        self.assertMasked('DB_PASSWORD = "Real1y-S3cret"', "Real1y-S3cret")
        _, f = secretlib.scan_line('DB_PASSWORD = "Real1y-S3cret"', code=True)
        self.assertTrue(f)

    def test_ordinary_code_is_not_a_secret(self):
        # lines from a real open-source repo (v0.3.1): each was reported as a secret by v0.3.0
        cases = [
            ("r = await fetch('/api/v1' + path, { credentials: 'same-origin', headers, ...opts });", True),
            ('"token_bucket":     "unknown",', True),
            ('TOKEN_FILE="$PUB/.token"', False),
            ('TOKEN=$(cat "$TOKEN_FILE")', False),
            ("TOKEN=`cat /run/token`", False),
            ('{"built_at":"$(date -u +%Y-%m-%dT%H:%M:%SZ)","url":"$BASE/install.html"}', False),
            ("lines.push((ok ? 'PASS' : 'FAIL') + ' ' + name);", False),
            ('buckets = api(auth["apiUrl"] + "/b2api/v2/b2_list_buckets", token=auth["authorizationToken"],', False),
            ("token_type: bearer", False),
            ("SESSION_TOKEN_TTL=3600000", False),
        ]
        for line, code in cases:
            with self.subTest(line=line):
                self.assertEqual(secretlib.scan_line(line, code=code, lenient=True)[1], [], line)

    def test_ordinary_code_rules_keep_real_values(self):
        lenient = lambda line, code=False: secretlib.scan_line(line, code=code, lenient=True)[1]  # noqa: E731
        self.assertTrue(lenient('TOKEN="$PREFIX-9f8e7d6c5b4a3f2e1d0c"'))   # a literal after the variable
        self.assertTrue(lenient("ADMIN_PASSWORD=Unkn0wn-But-Real"))
        self.assertTrue(lenient("curl -u deploy:S3cr3t-Value https://x.example"))
        self.assertTrue(lenient("DB_PASSWORD_HINT=Real1y-S3cret"))         # only listed suffixes are metadata
        self.assertTrue(lenient("VAULT_SECRET_ID=7d2f1c0e-real-secret-id"))  # AppRole secret_id is a credential
        self.assertTrue(lenient("htpasswd: $argon2id$v=19$m=65536,t=3,p=4$c2FsdHNhbHQ$aGFzaGhhc2hoYXNo"))
        # masking stays strict: the same lines are still redacted in inventories
        masked, _ = secretlib.scan_line('"token_bucket": "Real1y-S3cret-bucket"')
        self.assertNotIn("Real1y-S3cret-bucket", masked)

    def test_ui_strings_are_not_secrets(self):
        # translation and UI keys in app bundles (reported from a real audit: most of 1819 hits)
        cases = [('"forgot_password": "Forgot password?",', False),
                 ("forgot_password: 'Zapomniałeś hasła?',", True),
                 ('"confirm_password": "Confirm password",', False),
                 ('"new_password": "Nowe hasło",', False),
                 ('"invalid_password": "Invalid password.",', False),
                 ('"password_label": "Passwort",', False),
                 ('"token_expired": "Expired",', False),
                 ('"password": "Your password",', False)]
        for line, code in cases:
            with self.subTest(line=line):
                self.assertEqual(secretlib.scan_line(line, code=code, lenient=True)[1], [], line)
        lenient = lambda line: secretlib.scan_line(line, lenient=True)[1]  # noqa: E731
        self.assertTrue(lenient("NEW_PASSWORD=Xk29-lq0P-7Hd"))
        self.assertTrue(lenient('"reset_token": "9f8e7d6c5b4a3f2e1d0c"'))
        self.assertTrue(lenient('"confirm_password": "Xk29-lq0P-7Hd"'))
        masked, _ = secretlib.scan_line('"forgot_password": "Forgot password?"')
        self.assertNotIn("Forgot password?", masked)  # masking stays strict

    def test_prose_files_need_the_key_at_line_start(self):
        prose = lambda line: secretlib.scan_line(line, lenient=True, prose=True)[1]  # noqa: E731
        self.assertEqual(prose("- the SSH brute force guessed password = root, then gave up"), [])
        self.assertEqual(prose("Rotate it: the old token = 5f2b9c… is in the transcript"), [])
        self.assertTrue(prose("DB_PASSWORD=Real1y-S3cret-v4lue"))
        self.assertTrue(prose("  - password: Real1y-S3cret-v4lue"))
        self.assertTrue(prose("export API_TOKEN=Real1y-S3cret-v4lue"))
        self.assertTrue(secretlib.scan_line("the guessed password = Real1y-S3cret-v4lue", lenient=True)[1])

    def test_public_by_design_keys(self):
        phc = "phc_" + "Ab1Cd2Ef3Gh4" * 4
        _, f = secretlib.scan_line('DefaultToken = "%s"' % phc, code=True, lenient=True)
        self.assertEqual([x["type"] for x in f], ["public-key"])
        self.assertNotIn(phc, repr(f))
        _, f = secretlib.scan_line("STRIPE_API_KEY=pk_live_" + "51Hx" * 6, lenient=True)
        self.assertEqual([x["type"] for x in f], ["public-key"])
        # a PostHog personal key (phx_) is a secret; masking still hides the public one
        _, f = secretlib.scan_line("POSTHOG_TOKEN=phx_" + "Ab1Cd2Ef3Gh4" * 4, lenient=True)
        self.assertEqual([x["type"] for x in f], ["assignment"])
        masked, _ = secretlib.scan_line('usage_token = "%s"' % phc)
        self.assertNotIn(phc, masked)

    def test_constant_named_after_itself(self):
        self.assertEqual(secretlib.scan_line('_API_V2_BEARER_TOKEN_KEY = "api_v2_bearer_token_key"', code=True)[1], [])
        self.assertEqual(secretlib.scan_line("APP_TOKEN = 'app-token'", code=True)[1], [])

    def test_fingerprint_matches_within_run(self):
        _, a = secretlib.scan_line("DB_PASSWORD=SharedPass99")
        _, b = secretlib.scan_line("PANEL_PASSWORD=SharedPass99")
        self.assertEqual(a[0]["fp"], b[0]["fp"])

    def test_mask_block_private_key(self):
        body = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASC"
        text = "x=1\n-----BEGIN PRIVATE KEY-----\n%s\n-----END PRIVATE KEY-----\ny=2" % body
        out = secretlib.mask(text)
        self.assertNotIn(body, out)
        self.assertIn("y=2", out)

    def test_private_key_header_contexts(self):
        self.assertTrue(secretlib.scan_line("-----BEGIN OPENSSH PRIVATE KEY-----")[1])
        self.assertTrue(secretlib.scan_line('"private_key": "-----BEGIN PRIVATE KEY-----\\nMIIEvQIB"')[1])
        body = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7"
        line = '{"private_key": "-----BEGIN PRIVATE KEY-----\\n%s\\n-----END PRIVATE KEY-----\\n", "x": 1}' % body
        self.assertNotIn(body, secretlib.mask(line))
        self.assertNotIn(body, secretlib.scan_line(line)[0])
        # the pattern quoted inside source code is not a key
        self.assertEqual(secretlib.scan_line('rx = re.compile(r"-----BEGIN (?:[A-Z]+ )*PRIVATE KEY-----")')[1], [])

    def test_caddy_basicauth(self):
        out = secretlib.mask("basic_auth {\n    operator " + FAKE["bcrypt"] + "\n}")
        self.assertNotIn(FAKE["bcrypt"], out)


if __name__ == "__main__":
    unittest.main()
