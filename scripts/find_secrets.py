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
"""

import argparse
import os
import re
import stat
import subprocess
import sys
import pwd
import grp
from collections import defaultdict

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import secretlib  # noqa: E402

DEFAULT_PATHS = ["/etc", "/opt", "/srv", "/var/www", "/home", "/root", "/usr/local/etc", "/var/backups"]
PRUNE = {"node_modules", ".git", "venv", ".venv", "site-packages", "dist-packages", "__pycache__", ".cache",
         "vendor", "third_party", "third-party", "bower_components", ".skill-airlock", "Pods",
         "lang", "langs", "locales", "i18n", "l10n", "translations",
         ".npm", ".next", "dist", "build", "target", ".cargo", ".rustup", ".nvm", "go", ".pyenv",
         "share", "locale", "man", "doc", "fonts", "icons"}
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
EXAMPLE = re.compile(r"(?i)(example|sample|template|\.dist$|\.tmpl$|(?:^|/)tests?/|(?:^|/)fixtures?/|(?:^|/)spec/)")
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


class Scanner:
    def __init__(self, max_bytes, transcripts, exclude=()):
        self.exclude = tuple(os.path.abspath(os.path.expanduser(e)) for e in exclude)
        self.max_bytes = max_bytes
        self.transcripts = transcripts
        self.hits = []
        self.by_fp = defaultdict(list)
        self.tracked = {}  # repo root -> set(abs paths)
        self.repos = []
        self.files = 0
        self.skipped_large = 0

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

    def in_repo(self, path):
        d = os.path.dirname(path)
        while d and d != "/":
            if os.path.exists(os.path.join(d, ".git")):
                return path in self.repo_tracked(d)
            d = os.path.dirname(d)
        return False

    # -- files
    def walk(self, roots):
        for root in roots:
            if os.path.isfile(root):
                self.scan_file(root)
                continue
            for dirpath, dirnames, filenames in os.walk(root, onerror=lambda e: None):
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
        in_key = False
        per_file = 0
        for i, line in enumerate(text.splitlines(), 1):
            if in_key:
                if "PRIVATE KEY-----" in line and "END" in line:
                    in_key = False
                continue
            if len(line) > 20000:
                line = line[:20000]
            _, found = secretlib.scan_line(line, code=code, lenient=True)
            if secretlib.PEM_HEADER.match(line):
                in_key = True
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
        rec = {
            "tags": list(tags),
            "type": f["type"],
            "where": "%s:%s" % (where, line),
            "key": f["key"],
            "mode": ("%04o %s" % (stat.S_IMODE(st.st_mode), owner(st))) if st else "-",
            "len": f["length"],
            "fp": f["fp"],
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

    def history(self, repo, max_commits):
        cmd = ["git", "-c", "safe.directory=*", "-C", repo, "log", "--all", "-p", "--no-color", "--no-ext-diff",
               "-U0", "--format=commit %h", "-n", str(max_commits)]
        try:
            p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        except OSError:
            return
        commit, fname = "?", "?"
        seen = set()
        try:
            for raw in p.stdout:
                line = raw.decode("utf-8", "replace").rstrip("\n")
                if line.startswith("commit "):
                    commit = line[7:].strip()
                elif line.startswith("+++ "):
                    fname = line[6:] if line.startswith("+++ b/") else line[4:]
                elif line.startswith("+") and not line.startswith("+++"):
                    _, found = secretlib.scan_line(line[1:2000], code=secretlib.is_code_path(fname), lenient=True)
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
    args = ap.parse_args()

    os.umask(0o077)
    s = Scanner(int(args.max_mb * 1024 * 1024), args.transcripts, args.exclude)
    s.walk(args.paths or DEFAULT_PATHS)
    skipped_hist = []
    if args.git_history:
        for r in list(s.repos):
            if args.all_history or s.is_own_repo(r):
                s.history(r, args.max_commits)
            else:
                skipped_hist.append(r)

    hits = [h for h in s.hits if args.include_examples or "example?" not in h["tags"]]
    hits.sort(key=lambda h: (rank(h), h["where"]))
    out = []
    out.append("find_secrets — SENSITIVE (locations of secrets). Values are never printed.")
    out.append("scanned %d text files in %s; %d repos%s; %d large files skipped; running as %s"
               % (s.files, " ".join(args.paths or DEFAULT_PATHS), len(s.repos),
                  " (+history)" if args.git_history else "", s.skipped_large,
                  "root" if os.geteuid() == 0 else "NON-ROOT (unreadable files missed)"))
    out.append("hits: %d (examples/tests hidden: %d)" % (len(hits), len(s.hits) - len(hits)))
    if skipped_hist:
        out.append("git history NOT scanned (no local commits — third-party clones; --all-history to include): "
                   + ", ".join(skipped_hist))
    out.append("")
    for h in hits:
        out.append("%-34s %-22s %s  key=%s  %s  len=%d fp=%s%s" % (
            ",".join(h["tags"]) or "-", h["type"], h["where"], h["key"] or "-", h["mode"], h["len"], h["fp"],
            " WEAK" if h["weak"] else ""))
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
