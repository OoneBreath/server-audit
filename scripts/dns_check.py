#!/usr/bin/env python3
"""DNS and mail-authentication check for the operator's own domains. Read-only DNS lookups via `dig`.

    python3 -I dns_check.py NAME [NAME ...] [--origin IP[,IP]] [--cdn NAME[,NAME]] [--dkim-selectors a,b]

NAME: hostnames served by the host (take them from the proxy config). For each name: A/AAAA/CNAME,
dangling CNAMEs (subdomain takeover), and whether a name that should sit behind a CDN publishes the
origin IP. For each zone the names belong to: NS, MX (and whether MX hosts resolve), SPF, DMARC,
DKIM (common selectors + --dkim-selectors), CAA, DNSSEC (DS at the parent), MTA-STS and TLS-RPT.

Lines starting with "!!" are candidate findings. Only public DNS is queried (the system resolver);
nothing is sent to the host itself and no third-party service is used.
"""

import argparse
import re
import shutil
import subprocess
import sys

COMMON_DKIM = ["default", "dkim", "mail", "google", "selector1", "selector2", "s1", "s2", "k1", "k2", "mx",
               "smtp", "email", "key1", "mailcow", "sendgrid", "mandrill", "mailjet", "zoho", "protonmail"]


def dig(name, rtype):
    """Answer records (+short). Empty list on no answer."""
    try:
        p = subprocess.run(["dig", "+short", "+time=3", "+tries=2", rtype, name], stdout=subprocess.PIPE,
                           stderr=subprocess.DEVNULL, text=True, timeout=20)
    except (OSError, subprocess.TimeoutExpired):
        return []
    return [l.strip() for l in p.stdout.splitlines() if l.strip() and not l.startswith(";")]


def dig_status(name):
    """DNS response status for NAME (NOERROR, NXDOMAIN, SERVFAIL, ...)."""
    try:
        p = subprocess.run(["dig", "+noall", "+comments", "+time=3", "+tries=2", "A", name],
                           stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, timeout=20)
    except (OSError, subprocess.TimeoutExpired):
        return "?"
    m = re.search(r"status:\s*(\w+)", p.stdout)
    return m.group(1) if m else "?"


def txt_join(record):
    """dig prints long TXT records as several quoted chunks: join them into one string."""
    chunks = re.findall(r'"((?:[^"\\]|\\.)*)"', record)
    text = "".join(chunks) if chunks else record
    # dig escapes non-printable bytes as \DDD (decimal) and quotes as \"
    text = re.sub(r"\\(\d{3})", lambda m: chr(int(m.group(1))), text)
    return re.sub(r"\\(.)", r"\1", text)


WILDCARD_DNS = ("sslip.io", "nip.io", "xip.io", "traefik.me", "localtest.me", "lvh.me")


# ------------------------------------------------------------------ analysers (pure, unit-tested)
def analyse_spf(txts, resolve_txt=None, has_mx=True):
    """Return (level, message) items for the SPF policy. level: ok | warn | bad."""
    spf = [t for t in txts if t.lower().startswith("v=spf1")]
    if not spf:
        if has_mx:
            return [("bad", "no SPF record — anyone can send mail as this domain")]
        return [("warn", "no SPF record and no MX — publish 'v=spf1 -all' so nobody can send as this domain")]
    if len(spf) > 1:
        return [("bad", "%d SPF records — receivers treat this as an error (permerror)" % len(spf))]
    rec = spf[0]
    out = []
    m = re.search(r"(?:^|\s)([+?~-]?)all\b", rec)
    q = m.group(1) if m else None
    if q is None:
        if "redirect=" not in rec:
            out.append(("warn", "SPF has no 'all' term — mail from anywhere is 'neutral'"))
    elif q in ("", "+"):
        out.append(("bad", "SPF ends with '+all' — every server on the internet is allowed to send"))
    elif q == "?":
        out.append(("warn", "SPF ends with '?all' (neutral) — offers no protection"))
    elif q == "~":
        out.append(("ok", "SPF ~all (softfail) — fine with an enforcing DMARC policy"))
    else:
        out.append(("ok", "SPF -all (fail)"))
    lookups = count_spf_lookups(rec, resolve_txt)
    if lookups > 10:
        out.append(("bad", "SPF needs %d DNS lookups (limit 10) — receivers return permerror" % lookups))
    else:
        out.append(("ok", "SPF DNS lookups: %d of 10" % lookups))
    return out


def count_spf_lookups(rec, resolve_txt=None, depth=0):
    terms = rec.split()
    n = 0
    for t in terms:
        t = t.lstrip("+?~-").lower()
        if t.startswith(("include:", "redirect=")):
            n += 1
            if resolve_txt and depth < 4:
                target = t.split(":", 1)[1] if t.startswith("include:") else t.split("=", 1)[1]
                sub = [x for x in resolve_txt(target) if x.lower().startswith("v=spf1")]
                if sub:
                    n += count_spf_lookups(sub[0], resolve_txt, depth + 1)
        elif t in ("a", "mx", "ptr") or t.startswith(("a:", "mx:", "ptr:", "a/", "mx/", "exists:")):
            n += 1
    return n


def analyse_dmarc(txts):
    rec = [t for t in txts if t.lower().startswith("v=dmarc1")]
    if not rec:
        return [("bad", "no DMARC record — spoofed mail from this domain is not rejected and you get no reports")]
    tags = dict((k.strip().lower(), v.strip()) for k, _, v in (p.partition("=") for p in rec[0].split(";")) if k)
    p = tags.get("p", "").lower()
    out = []
    if p == "none":
        out.append(("warn", "DMARC p=none — monitoring only, spoofed mail is still delivered"))
    elif p in ("quarantine", "reject"):
        out.append(("ok", "DMARC p=%s" % p))
    else:
        out.append(("bad", "DMARC record without a valid p= tag"))
    if tags.get("pct") and tags["pct"] != "100":
        out.append(("warn", "DMARC pct=%s — the policy applies only to part of the mail" % tags["pct"]))
    if not tags.get("rua"):
        out.append(("warn", "DMARC has no rua= — you receive no aggregate reports"))
    return out


def dkim_key_bits(record):
    m = re.search(r"(?:^|;)\s*p=([^;]*)", record)
    if not m:
        return None
    b64 = re.sub(r"\s", "", m.group(1))  # DKIM allows folding whitespace inside the key
    if not b64:
        return 0  # revoked key
    raw = len(b64) * 3 // 4
    return 1024 if raw < 200 else (2048 if raw < 400 else 4096)


def analyse_caa(records):
    if not records:
        return [("warn", "no CAA record — any certificate authority may issue certificates for this domain")]
    issuers = sorted({m.group(1) for r in records for m in [re.search(r'issue(?:wild)?\s+"([^";]*)', r)] if m})
    return [("ok", "CAA allows: %s" % (", ".join(i or "(none)" for i in issuers) or "?"))]


# ------------------------------------------------------------------ driver
def zone_of(name, resolve=dig):
    labels = name.rstrip(".").split(".")
    for i in range(len(labels) - 1):
        cand = ".".join(labels[i:])
        if resolve(cand, "SOA"):
            return cand
    return ".".join(labels[-2:])


def check_name(name, origin, cdn, resolve=dig, status=dig_status, say=print):
    cname = resolve(name, "CNAME")
    a = [x for x in resolve(name, "A") if re.match(r"^\d+\.\d+\.\d+\.\d+$", x)]
    aaaa = [x for x in resolve(name, "AAAA") if ":" in x]
    say("  %s  A=%s AAAA=%s%s" % (name, ",".join(a) or "-", ",".join(aaaa) or "-",
                                  ("  CNAME=" + cname[0]) if cname else ""))
    if cname and not a and not aaaa:
        target = cname[-1].rstrip(".")
        st = status(target)
        if st == "NXDOMAIN":
            say("  !! %s is a dangling CNAME to %s (NXDOMAIN) — whoever registers that target can serve content "
                "for %s (subdomain takeover)" % (name, target, name))
        else:
            say("  !! %s CNAME %s resolves to no address (%s) — stale record?" % (name, target, st))
    if not cname and not a and not aaaa:
        say("  !! %s does not resolve — remove it from the proxy config or add the record" % name)
    pub = set(a) | set(aaaa)
    if origin and name in cdn and pub & origin:
        say("  !! %s should be behind the CDN but DNS publishes the origin address %s (record not proxied)"
            % (name, ", ".join(sorted(pub & origin))))
    return bool(origin and pub & origin)


def check_zone(zone, selectors, resolve=dig, say=print):
    say("")
    say("## zone %s" % zone)
    ns = resolve(zone, "NS")
    say("  NS: %s" % (", ".join(ns) or "?"))
    mx = resolve(zone, "MX")
    say("  MX: %s" % (", ".join(mx) or "none"))
    for r in mx:
        host = r.split()[-1].rstrip(".")
        if host and host != "." and not (resolve(host, "A") or resolve(host, "AAAA")):
            say("  !! MX host %s does not resolve" % host)
    txt = [txt_join(t) for t in resolve(zone, "TXT")]
    for level, msg in analyse_spf(txt, lambda n: [txt_join(t) for t in resolve(n, "TXT")], has_mx=bool(mx)):
        say("  %s %s" % ("!!" if level == "bad" else ("! " if level == "warn" else "ok"), msg))
    dm = [txt_join(t) for t in resolve("_dmarc." + zone, "TXT")]
    for level, msg in analyse_dmarc(dm):
        if not mx and level != "ok" and dm == []:
            level, msg = "warn", "no DMARC record — for a domain that sends no mail publish 'v=DMARC1; p=reject'"
        say("  %s %s" % ("!!" if level == "bad" else ("! " if level == "warn" else "ok"), msg))
    found = []
    for sel in selectors:
        recs = [txt_join(t) for t in resolve("%s._domainkey.%s" % (sel, zone), "TXT")]
        recs = [r for r in recs if "p=" in r]
        if recs:
            bits = dkim_key_bits(recs[0])
            found.append(sel)
            if bits == 0:
                say("  ok DKIM selector %s: revoked (empty p=)" % sel)
            elif bits == 1024:
                say("  !  DKIM selector %s: ~1024-bit key — rotate to 2048-bit" % sel)
            else:
                say("  ok DKIM selector %s: ~%s-bit key" % (sel, bits))
    if mx and not found:
        say("  !  no DKIM key found under common selectors — check the selector your mail server signs with "
            "(--dkim-selectors)")
    for level, msg in analyse_caa(resolve(zone, "CAA")):
        say("  %s %s" % ("! " if level == "warn" else "ok", msg))
    ds = resolve(zone, "DS")
    say("  %s DNSSEC %s" % ("ok" if ds else "! ", "enabled (DS at parent)" if ds else
                             "not enabled — DNS answers for this zone can be forged on the path"))
    if mx:
        sts = [txt_join(t) for t in resolve("_mta-sts." + zone, "TXT")]
        rpt = [txt_join(t) for t in resolve("_smtp._tls." + zone, "TXT")]
        say("     MTA-STS: %s · TLS-RPT: %s" % ("yes" if sts else "no", "yes" if rpt else "no"))


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("names", nargs="+")
    ap.add_argument("--origin", default="", help="the host's public IP(s), comma-separated")
    ap.add_argument("--cdn", default="", help="names that should only be reachable through a CDN")
    ap.add_argument("--dkim-selectors", default="", help="extra DKIM selectors to try")
    args = ap.parse_args(argv)
    if not shutil.which("dig"):
        print("dig not found — install dnsutils/bind-utils, or run this on another machine")
        return 2
    origin = {x.strip() for x in args.origin.split(",") if x.strip()}
    cdn = {x.strip().rstrip(".").lower() for x in args.cdn.split(",") if x.strip()}
    names = sorted({n.strip().rstrip(".").lower() for n in args.names if n.strip() and "*" not in n})
    selectors = COMMON_DKIM + [s for s in args.dkim_selectors.split(",") if s]
    print("# dns_check — names: %d, origin: %s, behind CDN: %s" % (len(names), ",".join(sorted(origin)) or "-",
                                                                     ",".join(sorted(cdn)) or "-"))
    print("## names")
    zones, direct = {}, []
    for n in names:
        if check_name(n, origin, cdn):
            direct.append(n)
        if n.endswith(WILDCARD_DNS):
            continue
        zones.setdefault(zone_of(n), []).append(n)
    if cdn and direct:
        print("     note: the origin IP is public anyway through %s — the CDN-only names must refuse direct "
              "connections at the origin (probe_external.sh --cdn checks that)" % ", ".join(direct))
    skipped = [n for n in names if n.endswith(WILDCARD_DNS)]
    if skipped:
        print("     (%s: public wildcard-DNS service, zone checks skipped)" % ", ".join(skipped))
    for z in sorted(zones):
        check_zone(z, selectors)
    return 0


if __name__ == "__main__":
    sys.exit(main())
