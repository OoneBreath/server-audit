#!/usr/bin/env python3
"""Find secrets on a host without ever printing them.

    sudo python3 -I find_secrets.py [--git-history] [--transcripts] [--out FILE] [PATH ...]

Default PATHs: /etc /opt /srv /var/www /home /root /usr/local/etc /var/backups
For every hit it prints WHERE it is and HOW EXPOSED it is — never the value:

    <exposure tags>  <type>  <path>:<line>  key=<NAME>  mode owner  len=N fp=XXXXXXXX [weak]

Exposure tags:
  WORLD-READABLE  any local user can read the file
  GROUP-READABLE  the file's (non-root) group can read it
  GIT-TRACKED     the file is committed in a git repository (check where that repo is pushed)
  GIT-HISTORY     the value was added in some commit (still recoverable even if the file is gone now)
  SHELL-HISTORY   in a shell/REPL history file (it was typed or pasted)
  TRANSCRIPT      in an AI-agent transcript (it was printed to a model; treat as leaked)
  LOG             in a log file
  COPY            in a backup / archived / .bak copy
fp is an HMAC fingerprint valid only inside this run: the same fp in several places = the same value
(reused password, or copies that must all be rotated together).

Package caches, SDKs and editor servers (~/.pub-cache, ~/.gradle, ~/.m2, ~/.cargo/registry, flutter,
android-sdk, ~/.vscode-server, ~/.windsurf-server, ...) are skipped unless --include-caches: third-party
code, slow to walk, full of example keys. Progress goes to stderr (--quiet silences it). On a host with
many repositories and long agent transcripts the scan takes minutes: run it in the background, and use
--max-seconds N (partial report that names what was not scanned) or --since 30d (recent transcripts only).
"""

import argparse
import os
import re
import stat
import subprocess
import time
import sys
import pwd
import grp
from collections import defaultdict

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import secretlib  # noqa: E402

DEFAULT_PATHS = ["/etc", "/opt", "/srv", "/var/www", "/home", "/root", "/usr/local/etc", "/var/backups"]
PRUNE = {"node_modules", ".git", "venv", ".venv", "site-packages", "dist-packages", "__pycache__", ".cache",
         "vendor", "third_party", "third-party", "bower_components", ".skill-airlock", "Pods",
         # this skill's own outputs (masked, fingerprints only): scanned when named explicitly, not while walking
         ".server-audit",
         "lang", "langs", "locales", "i18n", "l10n", "translations",
         ".npm", ".next", "dist", "build", "target", ".rustup", ".nvm", "go", ".pyenv",
         "share", "locale", "man", "doc", "fonts", "icons"}
# Package caches, SDKs and editor servers: third-party code with thousands of example keys, and most of the
# walking time on a developer's host. Skipped by default (--include-caches scans them). The credential files
# that sit next to a cache are still scanned: ~/.pub-cache/credentials.json, ~/.gradle/gradle.properties,
# ~/.m2/settings.xml, ~/.cargo/credentials.toml. "a/b" entries match a directory b inside a directory a.
CACHE_DIRS = {".pub-cache/hosted", ".pub-cache/git", ".pub-cache/_temp", ".gradle/caches", ".gradle/wrapper",
              ".gradle/daemon", ".gradle/native", ".gradle/jdks", ".m2/repository", ".cargo/registry", ".cargo/git",
              ".windsurf-server", ".vscode-server", ".vscode-server-insiders", ".cursor-server",
              ".vscode/extensions", ".cursor/extensions", ".windsurf/extensions", ".nuget/packages", ".yarn/cache",
              ".pnpm-store", ".local/share/pnpm", ".bun/install", ".deno", ".dartServer", ".sdkman", ".conda/pkgs",
              "miniconda3", "anaconda3", "Android/Sdk", ".android/cache"}
# SDKs found by what is inside them (a project folder called "flutter" is not skipped)
SDK_MARKERS = (("bin/flutter", "packages/flutter_tools"), ("platform-tools",), ("build-tools",),
               ("cmdline-tools",))
SKIP_EXT = (".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".svg", ".woff", ".woff2", ".ttf", ".otf",
            ".mp4", ".mp3", ".zip", ".gz", ".tgz", ".xz", ".bz2", ".7z", ".tar", ".whl", ".so", ".o",
            ".a", ".pyc", ".class", ".jar", ".pdf", ".map", ".lock", ".min.js", ".min.css", ".sqlite",
            ".sqlite3", ".db", ".wasm", ".pack", ".idx", ".crt", ".pub")
SKIP_PREFIX = ("/etc/ssl/certs", "/etc/ca-certificates", "/usr/share", "/proc", "/sys", "/etc/alternatives",
               "/etc/fonts", "/etc/mailcap")
HISTORY = re.compile(r"(^|/)\.(bash|zsh|python|psql|mysql|node_repl|sqlite|rediscli|lesshst)_?history$|(^|/)\.viminfo$")
COPY = re.compile(r"(?i)(\.bak|\.old|\.orig|\.save|~|\.\d{8}.*|backup|archive|\.swp)$|/backups?/|secret-archive|"
                  r"/file-history/|\.bak-")
LOG = re.compile(r"(?i)(\.log(\.\d+)?$|/var/log/)")
EXAMPLE = re.compile(r"(?i)(example|sample|template|\.dist$|\.tmpl$|(?:^|/)tests?/|(?:^|/)fixtures?/|(?:^|/)spec/|"
                     r"_test\.(?:go|py|rb|exs?)$|(?:^|/)test_[^/]*\.py$|\.(?:test|spec)\.[cm]?[jt]sx?$|_spec\.rb$|"
                     r"Tests?\.(?:swift|kt|java|cs)$)")
# prompt histories of AI agents: what the operator typed or pasted, sent to the model provider
AGENT_HISTORY = re.compile(r"/\.(claude|codex|gemini|aider|cursor)[^/]*/(?:.*/)?history[^/]*\.jsonl?$|/\.aider\.chat\.history\.md$")


def owner(st):
    try:
        u = pwd.getpwuid(st.st_uid).pw_name
    except KeyError:
        u = str(st.st_uid)
    try:
        g = grp.getgrgid(st.st_gid).gr_name
    except KeyError:
        g = str(st.st_gid)
    return "%s:%s" % (u, g)


def is_cache_dir(parent, name):
    """A package cache, SDK or editor server directory (see CACHE_DIRS)."""
    if name in CACHE_DIRS or os.path.basename(parent) + "/" + name in CACHE_DIRS:
        return True
    low = name.lower()
    if "flutter" in low or "sdk" in low:
        full = os.path.join(parent, name)
        return any(all(os.path.exists(os.path.join(full, m)) for m in markers) for markers in SDK_MARKERS)
    return False


CACHE_PARENTS = {e.split("/")[0] for e in CACHE_DIRS if "/" in e}  # ~/.gradle, ~/.pub-cache, ...


def inside_cache(path):
    """True when path is a cache, inside one, or a cache's parent (~/.gradle): named explicitly on the command
    line, so everything under it is scanned."""
    parts = os.path.abspath(path).split("/")
    return parts[-1] in CACHE_PARENTS or any(is_cache_dir("/".join(parts[:i]) or "/", parts[i])
                                             for i in range(1, len(parts)))


def parse_age(text):
    """'30d', '12h', '2w' or a number of days -> seconds."""
    m = re.fullmatch(r"(\d+(?:\.\d+)?)\s*([hdw]?)", (text or "").strip().lower())
    if not m:
        raise argparse.ArgumentTypeError("expected an age like 30d, 12h or 2w")
    return float(m.group(1)) * {"h": 3600, "d": 86400, "w": 7 * 86400, "": 86400}[m.group(2)]


class Stop(Exception):
    """--max-seconds reached."""


class Scanner:
    def __init__(self, max_bytes, transcripts, exclude=(), include_caches=False, deadline=None, since=None,
                 progress=None):
        self.exclude = tuple(os.path.abspath(os.path.expanduser(e)) for e in exclude)
        self.max_bytes = max_bytes
        self.transcripts = transcripts
        self.include_caches = include_caches
        self.deadline = deadline          # time.time() value after which the scan stops (partial report)
        self.since = since                # transcripts older than this many seconds are skipped
        self.progress = progress or (lambda msg: None)
        self.caches_skipped = []
        self.old_transcripts = 0
        self.stopped_at = None
        self.not_scanned = []
        self._repo_of = {}                # directory -> repo root or None (in_repo used to stat every parent)
        self._beat = time.time()
        self.hits = []
        self.by_fp = defaultdict(list)
        self.tracked = {}  # repo root -> set(abs paths)
        self.repos = []
        self.files = 0
        self.skipped_large = 0
        self.public = set()  # fingerprints of public-by-design keys (counted, not listed)

    # -- git
    def repo_tracked(self, root):
        if root not in self.tracked:
            try:
                p = subprocess.run(["git", "-c", "safe.directory=*", "-C", root, "ls-files", "-z"],
                                   stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=60)
                self.tracked[root] = {os.path.join(root, f) for f in p.stdout.decode(errors="replace").split("\0") if f}
            except Exception:
                self.tracked[root] = set()
            self.repos.append(root)
        return self.tracked[root]

    def repo_of(self, d):
        if d not in self._repo_of:
            if not d or d == "/":
                self._repo_of[d] = None
            elif os.path.exists(os.path.join(d, ".git")):
                self._repo_of[d] = d
            else:
                self._repo_of[d] = self.repo_of(os.path.dirname(d))
        return self._repo_of[d]

    def in_repo(self, path):
        root = self.repo_of(os.path.dirname(path))
        return bool(root) and path in self.repo_tracked(root)

    def tick(self, where):
        now = time.time()
        if self.deadline and now > self.deadline:
            self.stopped_at = where
            raise Stop()
        if now - self._beat >= 15:
            self._beat = now
            self.progress("  … %d files so far, now in %s" % (self.files, where))

    # -- files
    def walk(self, roots):
        roots = list(roots)
        for n, root in enumerate(roots, 1):
            self.progress("scanning %s (%d/%d)…" % (root, n, len(roots)))
            try:
                self.walk_one(root)
            except Stop:
                self.not_scanned = roots[n:]
                return False
        return True

    def walk_one(self, root):
        if os.path.isfile(root):
            self.scan_file(root)
            return
        skip_caches = not self.include_caches and not inside_cache(root)
        for dirpath, dirnames, filenames in os.walk(root, onerror=lambda e: None):
            self.tick(dirpath)
            if dirpath.startswith(SKIP_PREFIX) or (self.exclude and dirpath.startswith(self.exclude)):
                dirnames[:] = []
                continue
            if os.path.exists(os.path.join(dirpath, ".git")):
                self.repo_tracked(dirpath)
            keep = []
            for d in dirnames:
                full = os.path.join(dirpath, d)
                if d in PRUNE or os.path.islink(full):
                    continue
                if d == "projects" and dirpath.endswith("/.claude") and not self.transcripts:
                    continue
                if skip_caches and is_cache_dir(dirpath, d):
                    self.caches_skipped.append(full)
                    continue
                keep.append(d)
            dirnames[:] = keep
            for fn in filenames:
                self.scan_file(os.path.join(dirpath, fn))

    def scan_file(self, path):
        low = path.lower()
        if low.endswith(SKIP_EXT):
            return
        try:
            st = os.lstat(path)
        except OSError:
            return
        if not stat.S_ISREG(st.st_mode) or st.st_size == 0:
            return
        is_transcript = ("/.claude/projects/" in path and path.endswith(".jsonl")) or bool(AGENT_HISTORY.search(path))
        if is_transcript and self.since and time.time() - st.st_mtime > self.since:
            self.old_transcripts += 1
            return
        limit = self.max_bytes * (40 if is_transcript else 1)
        if st.st_size > limit:
            self.skipped_large += 1
            return
        try:
            with open(path, "rb") as f:
                head = f.read(8192)
                if b"\0" in head:
                    return
                data = head + f.read()
        except OSError:
            return
        self.files += 1
        text = data.decode("utf-8", "replace")
        tags = self.exposure(path, st, is_transcript)
        code = secretlib.is_code_path(path)
        prose = secretlib.is_prose_path(path)
        in_key = False
        per_file = 0
        lines = text.splitlines()
        for i, line in enumerate(lines, 1):
            if in_key:
                if "PRIVATE KEY-----" in line and "END" in line:
                    in_key = False
                continue
            if len(line) > 20000:
                line = line[:20000]
            _, found = secretlib.scan_line(line, code=code, lenient=True, prose=prose)
            if found and known_example(path, found):
                found = [f for f in found if not known_example(path, [f])]
            if secretlib.PEM_HEADER.match(line):
                in_key = True
                # fingerprint the key itself, not its header: every key shares the header, and the same key
                # body in two places (or on two hosts: a cloned image) is the finding worth seeing
                body = []
                for nxt in lines[i:i + 200]:
                    if "PRIVATE KEY-----" in nxt and "END" in nxt:
                        break
                    body.append(nxt.strip())
                found = [secretlib.key_body_finding("".join(body)) if f["type"] == "private-key" else f
                         for f in found]
            for f in found:
                per_file += 1
                if per_file > 200:
                    break
                self.add(tags, f, path, i, st)

    def exposure(self, path, st, is_transcript):
        m = stat.S_IMODE(st.st_mode)
        tags = []
        if secretlib.world_accessible(path):
            tags.append("WORLD-READABLE")
        elif m & stat.S_IRGRP and st.st_gid != 0:
            tags.append("GROUP-READABLE")
        if self.in_repo(path):
            tags.append("GIT-TRACKED")
        if HISTORY.search(path):
            tags.append("SHELL-HISTORY")
        if is_transcript:
            tags.append("TRANSCRIPT")
        if LOG.search(path):
            tags.append("LOG")
        if COPY.search(path):
            tags.append("COPY")
        if EXAMPLE.search(path):
            tags.append("example?")
        return tags

    def add(self, tags, f, where, line, st=None):
        if f["type"] == "public-key":
            self.public.add(f["fp"])
            return
        rec = {
            "tags": list(tags),
            "type": f["type"],
            "where": "%s:%s" % (where, line),
            "key": f["key"],
            "mode": ("%04o %s" % (stat.S_IMODE(st.st_mode), owner(st))) if st else "-",
            "len": f["length"],
            "fp": f["fp"],
            "xfp": f.get("xfp"),
            "weak": f["weak"],
        }
        self.hits.append(rec)
        self.by_fp[f["fp"]].append(rec)

    # -- git history
    @staticmethod
    def local_emails(repo):
        emails = set()
        homes = {os.path.expanduser("~")}
        su = os.environ.get("SUDO_USER")
        if su:
            try:
                homes.add(pwd.getpwnam(su).pw_dir)
            except KeyError:
                pass
        for cfg in [os.path.join(repo, ".git", "config")] + [os.path.join(h, ".gitconfig") for h in homes]:
            try:
                with open(cfg, errors="replace") as f:
                    emails |= set(re.findall(r"^\s*email\s*=\s*(\S+)", f.read(), re.M))
            except OSError:
                pass
        return emails

    def is_own_repo(self, repo):
        """A repo with at least one commit by a local identity. Clones of third-party projects
        (no local commits) are skipped in history mode: their history is upstream's, not ours."""
        emails = self.local_emails(repo)
        if not emails:
            return True
        for e in emails:
            try:
                p = subprocess.run(["git", "-c", "safe.directory=*", "-C", repo, "log", "--all", "-1", "--format=%h",
                                    "--author=" + e], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=60)
            except Exception:
                continue
            if p.stdout.strip():
                return True
        return False

    def histories(self, repos, all_history, max_commits):
        """Scan the history of each repo (own repos only unless all_history); returns the skipped clones."""
        skipped = []
        repos = list(repos)
        for n, r in enumerate(repos, 1):
            if self.deadline and time.time() > self.deadline:
                self.stopped_at = self.stopped_at or "git history of " + r
                self.not_scanned += ["git history: " + x for x in repos[n - 1:]]
                break
            if all_history or self.is_own_repo(r):
                self.progress("git history %s (%d/%d)…" % (r, n, len(repos)))
                self.history(r, max_commits)
            else:
                skipped.append(r)
        return skipped

    def history(self, repo, max_commits):
        cmd = ["git", "-c", "safe.directory=*", "-C", repo, "log", "--all", "-p", "--no-color", "--no-ext-diff",
               "-U0", "--format=commit %h", "-n", str(max_commits)]
        try:
            p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        except OSError:
            return
        commit, fname = "?", "?"
        seen = set()
        key_body = None  # (fname, commit, [lines]) while a private key is being added in a diff
        try:
            def flush(kb):
                f = secretlib.key_body_finding("".join(kb[2]))
                if (f["fp"], kb[0]) not in seen:
                    seen.add((f["fp"], kb[0]))
                    tags = ["GIT-HISTORY"] + (["example?"] if EXAMPLE.search(kb[0]) else [])
                    self.add(tags, f, "%s@%s:%s" % (repo, kb[1], kb[0]), "+")
            for raw in p.stdout:
                if self.deadline and time.time() > self.deadline:
                    self.stopped_at = "git history of %s (partly scanned)" % repo
                    break
                line = raw.decode("utf-8", "replace").rstrip("\n")
                added = line.startswith("+") and not line.startswith("+++")
                if key_body is not None and not added:
                    flush(key_body)  # the hunk ended before the END line
                    key_body = None
                if line.startswith("commit "):
                    commit = line[7:].strip()
                elif line.startswith("+++ "):
                    fname = line[6:] if line.startswith("+++ b/") else line[4:]
                elif key_body is not None:
                    if "PRIVATE KEY-----" in line and "END" in line:
                        flush(key_body)
                        key_body = None
                    else:
                        key_body[2].append(line[1:].strip())
                elif line.startswith("+") and not line.startswith("+++"):
                    if secretlib.PEM_HEADER.match(line[1:]):
                        key_body = (fname, commit, [])
                        continue
                    _, found = secretlib.scan_line(line[1:2000], code=secretlib.is_code_path(fname), lenient=True,
                                                   prose=secretlib.is_prose_path(fname))
                    for f in found:
                        k = (f["fp"], fname)
                        if k in seen:
                            continue
                        seen.add(k)
                        tags = ["GIT-HISTORY"] + (["example?"] if EXAMPLE.search(fname) else [])
                        self.add(tags, f, "%s@%s:%s" % (repo, commit, fname), "+")
        finally:
            p.kill()
            p.wait()


# Examples that ship in distribution configs, identical on every install (not this host's secrets):
# OpenSSL's CMP demo section (`secret = pass:insta`).
KNOWN_EXAMPLES = {"openssl.cnf": {"secret"}}


def known_example(path, found):
    keys = KNOWN_EXAMPLES.get(os.path.basename(path))
    return bool(keys) and all(f.get("key") in keys for f in found)


SEVERITY_ORDER = ["TRANSCRIPT", "GIT-HISTORY", "GIT-TRACKED", "WORLD-READABLE", "SHELL-HISTORY", "LOG",
                  "COPY", "GROUP-READABLE"]


def rank(rec):
    for i, t in enumerate(SEVERITY_ORDER):
        if t in rec["tags"]:
            return i
    return len(SEVERITY_ORDER)


def main():
    ap = argparse.ArgumentParser(description="Find secrets without printing them.")
    ap.add_argument("paths", nargs="*")
    ap.add_argument("--git-history", action="store_true", help="also scan added lines in git history of found repos")
    ap.add_argument("--max-commits", type=int, default=3000)
    ap.add_argument("--all-history", action="store_true",
                    help="scan history of every repo, also clones with no local commits (third-party projects)")
    ap.add_argument("--exclude", action="append", default=[], help="skip paths starting with this (repeatable)")
    ap.add_argument("--transcripts", action="store_true", help="also scan ~/.claude/projects/*.jsonl transcripts")
    ap.add_argument("--max-mb", type=float, default=5.0, help="skip files larger than this (transcripts: 40x)")
    ap.add_argument("--out", help="write the report to this file (mode 600) instead of stdout")
    ap.add_argument("--include-examples", action="store_true", help="show hits in example/test files too")
    ap.add_argument("--include-caches", action="store_true",
                    help="also scan package caches, SDKs and editor servers (~/.pub-cache, ~/.gradle, flutter, "
                         "android-sdk, ~/.vscode-server, ...): slow, and nearly every hit there is third-party")
    ap.add_argument("--max-seconds", type=float,
                    help="stop after this many seconds and write a partial report that says what was not scanned")
    ap.add_argument("--since", type=parse_age,
                    help="with --transcripts: only transcripts and agent histories changed in this period (30d, 12h)")
    ap.add_argument("--quiet", action="store_true", help="no progress lines on stderr")
    ap.add_argument("--fleet-key-stdin", action="store_true",
                    help="read a comparison key (hex, from fleet.py key) on stdin and add xfp= fingerprints that "
                         "match across hosts audited with the same key; the key is never written anywhere")
    args = ap.parse_args()

    os.umask(0o077)
    if args.fleet_key_stdin:
        line = sys.stdin.readline().strip()
        if not re.fullmatch(r"[0-9a-f]{32,128}", line):
            sys.exit("find_secrets: --fleet-key-stdin expects the hex key from `fleet.py key` on stdin")
        secretlib.set_fleet_key(bytes.fromhex(line))
    started = time.time()

    def progress(msg):
        if not args.quiet:
            sys.stderr.write("[%4.0fs] %s\n" % (time.time() - started, msg))
            sys.stderr.flush()

    s = Scanner(int(args.max_mb * 1024 * 1024), args.transcripts, args.exclude, include_caches=args.include_caches,
                deadline=started + args.max_seconds if args.max_seconds is not None else None, since=args.since,
                progress=progress)
    s.walk(args.paths or DEFAULT_PATHS)
    skipped_hist = []
    if args.git_history:
        if s.stopped_at:
            s.not_scanned.append("git history of %d repos" % len(s.repos))
        else:
            skipped_hist = s.histories(s.repos, args.all_history, args.max_commits)
    elapsed = time.time() - started
    progress("done in %.0f s: %d files, %d hits" % (elapsed, s.files, len(s.hits)))

    hits = [h for h in s.hits if args.include_examples or "example?" not in h["tags"]]
    hits.sort(key=lambda h: (rank(h), h["where"]))
    out = []
    out.append("find_secrets — SENSITIVE (locations of secrets). Values are never printed.")
    out.append("scanned %d text files in %s; %d repos%s; %d large files skipped; running as %s"
               % (s.files, " ".join(args.paths or DEFAULT_PATHS), len(s.repos),
                  " (+history)" if args.git_history else "", s.skipped_large,
                  "root" if os.geteuid() == 0 else "NON-ROOT (unreadable files missed)"))
    if s.stopped_at:
        out.append("INCOMPLETE: stopped after %.0f s (--max-seconds) in %s; not scanned: %s"
                   % (elapsed, s.stopped_at, ", ".join(s.not_scanned) or "the rest of that path"))
    out.append("hits: %d (examples/tests hidden: %d); took %.0f s" % (len(hits), len(s.hits) - len(hits), elapsed))
    if s.caches_skipped:
        out.append("package caches / SDKs / editor servers skipped: %d (%s%s; --include-caches to scan them)"
                   % (len(s.caches_skipped), ", ".join(s.caches_skipped[:6]), ", …" if len(s.caches_skipped) > 6 else ""))
    if s.old_transcripts:
        out.append("transcripts older than --since skipped: %d" % s.old_transcripts)
    if secretlib.fleet_key_id():
        out.append("fleet key id: %s (xfp= values match across hosts scanned with this key; delete the key after "
                   "the comparison)" % secretlib.fleet_key_id())
    if s.public:
        out.append("public-by-design keys seen (PostHog phc_, Stripe pk_, Mapbox pk.; not secrets, not listed): %d"
                   % len(s.public))
    if skipped_hist:
        out.append("git history NOT scanned (no local commits — third-party clones; --all-history to include): "
                   + ", ".join(skipped_hist))
    out.append("")
    for h in hits:
        out.append("%-34s %-22s %s  key=%s  %s  len=%d fp=%s%s%s" % (
            ",".join(h["tags"]) or "-", h["type"], h["where"], h["key"] or "-", h["mode"], h["len"], h["fp"],
            (" xfp=" + h["xfp"]) if h.get("xfp") else "", " WEAK" if h["weak"] else ""))
    out.append("")
    out.append("values found in more than one place (rotate together; different keys = reused secret):")
    any_dup = False
    for fp, recs in sorted(s.by_fp.items(), key=lambda kv: -len(kv[1])):
        recs = [r for r in recs if args.include_examples or "example?" not in r["tags"]]
        places = sorted({r["where"].rsplit(":", 1)[0] for r in recs})
        keys = sorted({r["key"] for r in recs if r["key"]})
        if len(places) < 2:
            continue
        any_dup = True
        out.append("  fp=%s in %d places, keys: %s%s" % (fp, len(places), ", ".join(keys) or "-",
                                                          "  <- SAME VALUE UNDER DIFFERENT NAMES" if len(keys) > 1 else ""))
        for p in places[:12]:
            out.append("      " + p)
    if not any_dup:
        out.append("  none")
    text = "\n".join(out) + "\n"
    if args.out:
        with open(args.out, "w") as f:
            f.write(text)
        os.chmod(args.out, 0o600)
        su = os.environ.get("SUDO_UID")
        if su:
            os.chown(args.out, int(su), int(os.environ.get("SUDO_GID", su)))
        print(args.out)
        print("hits: %d" % len(hits))
    else:
        sys.stdout.write(text)


if __name__ == "__main__":
    main()
