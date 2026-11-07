"""Shared secret detection and masking for server-audit scripts.

Rule: nothing that leaves this module may contain a secret value. Callers get the
masked line, the key name (if any), the secret type, the value length and a
fingerprint that is only comparable within one run (HMAC with a random per-run key),
so duplicates can be spotted without making the report useful for offline guessing.
"""

import hashlib
import hmac
import os
import re

_RUN_KEY = os.urandom(32)

# Known token formats: (type, regex). Order matters: more specific first.
TOKEN_PATTERNS = [
    # a real key header ends the line (PEM file) or is followed by an escaped newline (JSON service account)
    ("private-key", re.compile(r"-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY-----(?=\\n|\s*$)")),
    ("anthropic-key", re.compile(r"sk-ant-[A-Za-z0-9_\-]{20,}")),
    ("openrouter-key", re.compile(r"sk-or-v1-[A-Za-z0-9]{32,}")),
    ("openai-key", re.compile(r"sk-(?!ant-|or-)(?:proj-)?[A-Za-z0-9_\-]{32,}")),
    ("stripe-live-key", re.compile(r"\b(?:sk|rk)_live_[A-Za-z0-9]{16,}")),
    ("stripe-test-key", re.compile(r"\b(?:sk|rk)_test_[A-Za-z0-9]{16,}")),
    ("stripe-webhook-secret", re.compile(r"\bwhsec_[A-Za-z0-9]{16,}")),
    ("github-token", re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{40,})")),
    ("aws-access-key", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("slack-token", re.compile(r"\bxox[abposr]-[A-Za-z0-9-]{10,}")),
    ("google-api-key", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}")),
    ("sendgrid-key", re.compile(r"\bSG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}")),
    ("telegram-bot-token", re.compile(r"\b\d{8,10}:AA[A-Za-z0-9_\-]{33}\b")),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}")),
    ("bcrypt-hash", re.compile(r"\$2[aby]\$\d{2}\$[./A-Za-z0-9]{53}")),
    ("bearer-token", re.compile(r"(?i)(?<=bearer )[A-Za-z0-9._~+/\-]{16,}=*")),
    ("basic-auth-header", re.compile(r"(?i)(?<=basic )[A-Za-z0-9+/]{12,}={0,2}")),
]

# Credentials embedded in a URL: scheme://user:PASSWORD@host
URL_CREDS = re.compile(r"([a-zA-Z][a-zA-Z0-9+.\-]*://[^/\s:@'\"]+:)([^/\s@'\"]+)(@)")

# CLI arguments that carry secrets: --password=X, --token X, curl -u user:X, mysql -pX
CLI_ARG = re.compile(
    r"(?i)(--(?:password|passwd|pass|token|secret|api-key|apikey|auth-token|key)[= ])(\S+)"
    r"|(\s-u\s+[^:\s+%][^:\s]*:)(\S+)"  # not `date -u +%Y-%m-%dT%H:%M`
    r"|(\bmysql(?:dump)?\b[^\n]*?\s-p)(\S+)"
)

# Key names that hold secrets (matched against the key, not the value).
SECRET_KEY = re.compile(
    r"(?i)(?:^|[_\-.])(?:pass(?:word|wd)?|pwd|secret|token|api[_\-]?key|apikey|"
    r"private[_\-]?key|access[_\-]?key|client[_\-]?secret|auth[_\-]?(?:token|key|pass)|"
    r"credentials?|dsn|webhook[_\-]?secret|signing[_\-]?key|salt|session[_\-]?key|"
    r"bcrypt|htpasswd)(?:$|[_\-.0-9])"
    # glued names: PGPASSWORD, SMTPPASSWORD, MYSECRET, CSRFTOKEN; and tool-specific env names
    r"|(?:password|passwd|secret|token)(?:$|[_\-.0-9])"
    r"|^(?:auth|identitytoken|pgpass|rediscli_auth|masterauth|requirepass)$"
)

# KEY=VALUE, export KEY=VALUE, KEY: VALUE, "key": "value", Environment="KEY=VALUE"
ASSIGN = re.compile(
    r"""(?P<pre>(?:^|[\s"'{,;(])(?:export\s+|Environment=["']?)?)"""
    r"""(?P<q1>["']?)(?P<key>[A-Za-z_][A-Za-z0-9_.\-]{1,80})(?P=q1)"""
    r"""(?P<sep>\s*[:=]\s*)"""
    r"""(?P<q2>["']?)(?P<val>[^\s"'#,;}]+(?:[^\n"'#,;}]*[^\s"'#,;}])?)(?P=q2)"""
)

WEAK_VALUES = {
    "change_me", "changeme", "change-me", "password", "passw0rd", "admin", "administrator",
    "secret", "123456", "12345678", "123456789", "qwerty", "letmein", "test", "testing",
    "demo", "demo123", "root", "toor", "default", "guest", "welcome", "postgres", "mysql",
    "redis", "pass", "password1", "password123", "admin123", "secret123", "example",
}

PLACEHOLDER = re.compile(
    r"(?i)^(?:|[^A-Za-z0-9]+|\$\{?[A-Za-z_][A-Za-z0-9_]*\}?|<[^>]*>|x{3,}|\*{3,}|\.{3,}|your[_\-].*|"
    r".*_here|todo|tbd|none|null|nil|true|false|yes|no|on|off|\d{1,6}|"
    r"(?:/|~/|\./)[^\s]*|%\(.*\)s|%-?\d*[sdqv](?:\\[nrt])*|\{\{.*\}\}|redacted|<redacted.*|sha256:.*)$"
)


_DIR_OK = {}


def world_accessible(path: str) -> bool:
    """True if ANY local user can read path: o+r on it and o+x on every ancestor directory."""
    import stat as _st
    try:
        st = os.stat(path)
    except OSError:
        return False
    need = _st.S_IROTH | (_st.S_IXOTH if _st.S_ISDIR(st.st_mode) else 0)
    if _st.S_IMODE(st.st_mode) & need != need:
        return False
    d = os.path.dirname(os.path.abspath(path))
    chain = []
    while True:
        if d in _DIR_OK:
            ok = _DIR_OK[d]
            break
        try:
            ok = bool(_st.S_IMODE(os.stat(d).st_mode) & _st.S_IXOTH)
        except OSError:
            ok = False
        chain.append(d)
        if not ok or d == "/":
            break
        d = os.path.dirname(d)
    for c in chain:
        _DIR_OK.setdefault(c, ok)
    return ok


def fingerprint(value: str) -> str:
    """Per-run fingerprint: equal values in one run match; useless outside the run."""
    return hmac.new(_RUN_KEY, value.encode("utf-8", "replace"), hashlib.sha256).hexdigest()[:8]


UPPER_PLACEHOLDER = re.compile(r"^(?:PASSWORD|PASSWD|PASS|TOKEN|SECRET|KEY|VALUE|USER|X+|N+|HERE|CHANGEME)$")


def _not_a_secret(value):
    v = value.strip().strip("`'\"")
    return (len(v) < 4 and v.lower() not in WEAK_VALUES) or bool(UPPER_PLACEHOLDER.match(v))


def _finding(kind, value, key=None):
    v = value.strip()
    return {
        "type": kind,
        "key": key,
        "length": len(v),
        "fp": fingerprint(v),
        "weak": v.lower() in WEAK_VALUES or (key is not None and _is_password_key(key) and 0 < len(v) < 12),
    }


def _is_password_key(key):
    return re.search(r"(?i)pass(word|wd)?|pwd", key or "") is not None


def _redacted(value):
    return "<REDACTED len=%d fp=%s>" % (len(value), fingerprint(value))


# Detection only (lenient): values and keys that are ordinary code or metadata, never credentials.
# Masking ignores these rules, so a line that matches them is still redacted in inventories.
# shell expansions: $(cmd), `cmd`, a path built on a variable ("$DIR/.token")
SHELL_EXPANSION = re.compile(r"^(?:\$\(|`|\$\{?[A-Za-z_][A-Za-z0-9_]*\}?/)")
# fetch()/CORS options and status words
NON_SECRET_WORDS = {"same-origin", "same_origin", "include", "omit", "unknown", "required", "optional",
                    "disabled", "enabled", "inherit", "unset", "empty", "hidden", "masked", "n/a"}
# key names that describe a secret instead of holding it: TOKEN_FILE, PASSWORD_PATH, SESSION_TOKEN_TTL
META_KEY = re.compile(r"(?i)[_\-.](?:file|path|dir|url|uri|endpoint|expires?|expiry|ttl|type|length|len|"
                      r"header|bucket|count|limit|name)$")
# keys that are public by design (shipped in web pages and apps): PostHog project keys, Stripe publishable
# keys, Mapbox public tokens. Reported as public-key so the scan can count them apart from secrets.
PUBLIC_KEY = re.compile(r"^(?:phc_[A-Za-z0-9]{30,}|pk_(?:live|test)_[A-Za-z0-9]{16,}|pk\.eyJ[A-Za-z0-9_\-.]{20,})$")
# translation and UI keys: forgot_password, confirm_password, password_label, token_expired
UI_KEY = re.compile(r"(?i)(?:^|[_\-.])(?:forgot|reset|change|confirm|confirmation|new|old|current|repeat|retype|enter|"
                    r"invalid|wrong|incorrect|weak|strong|mismatch|required|label|hint|placeholder|title|text|message|"
                    r"msg|errors?|help|tooltip|button|btn|prompt|desc|description|show|hide|toggle|link|lost|strength|"
                    r"policy|rules|expired|sent|changed|updated|success|failed|subject|heading|caption|notice|"
                    r"warning)(?:$|[_\-.])")
# the value names the thing itself ("Your password", "Hasło jest za krótkie"): UI text, not a credential
SECRET_WORD = re.compile(r"(?i)\b(?:pass(?:word|wort|wd)?|has(?:ł|l)\w*|contrase\w*|senha|wachtwoord|"
                         r"mot de passe|token|secret|key|klucz\w*)\b")
# prose files: an assignment counts only when the key starts the line (a config line, a list item)
PROSE_PREFIX = re.compile(r"^\s*(?:[-*+>]\s+|\d+[.)]\s+)?(?:export\s+)?[\"'`]?$")


def _ui_text(key, val):
    """True for UI strings: a UI-ish key with text, or any text value that names the secret itself."""
    texty = bool(re.search(r"\s", val)) or val.rstrip().endswith(("?", ".", "!", ":", "…")) or (
        val.isalpha() and val[:1].isupper() and len(val) <= 30)
    if UI_KEY.search(key) and texty:
        return True
    return bool(re.search(r"\s", val)) and bool(SECRET_WORD.search(val))


# a call or an index on a name: token=auth["authorizationToken"] (the quote ends the captured value)
CODE_INDEX = re.compile(r"^[A-Za-z_][\w.]*[\[(]$")


def _ordinary_code(m, key, val):
    """True when an assignment match is ordinary code or metadata (detection only)."""
    if SHELL_EXPANSION.match(val) or val.lower() in NON_SECRET_WORDS or META_KEY.search(key) \
            or CODE_INDEX.match(val):
        return True
    # a ternary branch, not an assignment: ok ? 'PASS' : 'FAIL'
    return m.string[:m.start("key")].rstrip("'\" ").endswith("?")


CODE_EXT = (".py", ".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx", ".go", ".rb", ".php", ".java", ".kt", ".rs",
            ".cs", ".swift", ".scala", ".c", ".h", ".cpp", ".lua", ".pl", ".vue", ".svelte")
# values that are code, not secrets: calls, attribute access, collections, None/null
CODE_VALUE = re.compile(r"^(?:[A-Za-z_][\w.]*\(|[\(\[\{]|(?:None|null|undefined|nil)$|"
                        r"[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)+$|(?:os|process|ENV|env|getenv|config|settings)\b)")


INLINE_KEY = re.compile(r"-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY-----\\n.*?(?:-----END (?:[A-Z0-9]+ )*PRIVATE KEY-----|$)")
PEM_HEADER = re.compile(r"^\s*-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY-----\s*$")


def is_code_path(path: str) -> bool:
    return path.lower().endswith(CODE_EXT)


PROSE_EXT = (".md", ".markdown", ".rst", ".adoc", ".txt")


def is_prose_path(path: str) -> bool:
    return path.lower().endswith(PROSE_EXT)


def scan_line(line: str, code: bool = False, lenient: bool = False, prose: bool = False):
    """Return (masked_line, findings). Findings never contain the value itself.
    code=True (source files): only quoted string literals count as assigned secrets.
    lenient=True (detection only, never for masking output): prose after a colon is not a value.
    prose=True (with lenient; .md/.txt/.rst files): key=value counts only at the start of a line.
    Masking must stay strict: over-redacting prose is harmless, under-redacting is a leak."""
    findings = []
    masked = line

    # one-line keys (JSON service accounts): header, escaped newlines and body on the same line
    def inline_key(m):
        findings.append(_finding("private-key", m.group(0)))
        return "-----BEGIN PRIVATE KEY-----<REDACTED key body len=%d>" % len(m.group(0))

    masked = INLINE_KEY.sub(inline_key, masked)

    def tok_sub(kind):
        def _sub(m):
            findings.append(_finding(kind, m.group(0)))
            if kind == "private-key":
                return m.group(0)  # header itself is not secret; the body lines are skipped by callers
            return _redacted(m.group(0))
        return _sub

    for kind, rx in TOKEN_PATTERNS:
        masked = rx.sub(tok_sub(kind), masked)

    def url_sub(m):
        if m.group(2).startswith("<REDACTED") or _not_a_secret(m.group(2)):
            return m.group(0)
        findings.append(_finding("url-credentials", m.group(2)))
        return m.group(1) + _redacted(m.group(2)) + m.group(3)

    masked = URL_CREDS.sub(url_sub, masked)

    def cli_sub(m):
        for pre_i, val_i in ((1, 2), (3, 4), (5, 6)):
            if m.group(pre_i) is not None:
                val = m.group(val_i)
                if val.startswith("<REDACTED") or PLACEHOLDER.match(val) or _not_a_secret(val):
                    return m.group(0)
                findings.append(_finding("cli-argument", val))
                return m.group(pre_i) + _redacted(val)
        return m.group(0)

    masked = CLI_ARG.sub(cli_sub, masked)

    def assign_sub(m):
        key, val = m.group("key"), m.group("val")
        if not SECRET_KEY.search(key) or val.startswith("<REDACTED") or PLACEHOLDER.match(val) \
                or _not_a_secret(val):
            return m.group(0)
        if CODE_VALUE.match(val) or (code and not m.group("q2")):
            return m.group(0)
        # a constant holding its own name ("TOKEN_KEY = 'token_key'") is a storage key, not a secret
        if re.sub(r"[_\-.]", "", val).lower() == re.sub(r"[_\-.]", "", key).lower().lstrip("_"):
            return m.group(0)
        # Prose after a colon ("password: HIGH.", "without password: any process can …") is text,
        # not a credential: unquoted and either several words or one short plain word.
        # UI strings ("password_reset": "Reset your password") — several words are text, not a credential
        if lenient and len(val.split()) >= 3:
            return m.group(0)
        if lenient and (_ordinary_code(m, key, val) or _ui_text(key, val)):
            return m.group(0)
        if lenient and prose and not PROSE_PREFIX.match(m.string[:m.start("key")]):
            return m.group(0)
        if lenient and PUBLIC_KEY.match(val):
            findings.append(_finding("public-key", val, key=key))
            return m.group(0)
        if lenient and ":" in m.group("sep") and not m.group("q2") and (
                re.search(r"\s", val) or
                (re.match(r"^[A-Za-z]{1,11}[.!?]?$", val) and val.lower().rstrip(".!?") not in WEAK_VALUES)):
            return m.group(0)
        if "REDACTED" in val:
            return m.group(0)
        findings.append(_finding("assignment", val, key=key))
        q = m.group("q2")
        return (m.group("pre") + m.group("q1") + key + m.group("q1") + m.group("sep")
                + q + _redacted(val) + q)

    masked = ASSIGN.sub(assign_sub, masked)
    return masked, findings


def mask(text: str) -> str:
    """Mask every secret in a block of text (used for config dumps)."""
    out = []
    in_key = False
    for line in text.splitlines():
        if in_key:
            if "-----END" in line and "PRIVATE KEY-----" in line:
                in_key = False
                out.append(line)
            continue
        masked, _ = scan_line(line)
        if re.search(r"-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY-----\s*$", line):
            in_key = True
            out.append(masked + "  <private key body omitted>")
            continue
        out.append(masked)
    return "\n".join(out)
