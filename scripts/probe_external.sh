#!/usr/bin/env bash
# probe_external.sh — outside-in check of ONE host you own or are authorised to test.
# Run it from a DIFFERENT machine (another VPS, a laptop). Probing a host's own public IP from
# itself goes over loopback and skips its firewall, so the result would be meaningless.
#
# Gentle by design: single TCP connects with a delay, single HTTP requests, no credentials,
# no payloads, no brute force. Needs only bash, curl, openssl (no nmap).
#
# usage: probe_external.sh TARGET [options]
#   TARGET              IP or hostname of the host under audit (IPv6 literal works too)
#   --ports LIST        comma-separated ports (default: a list of ~55 common service/admin ports)
#   --urls FILE         lines "URL EXPECTED" — EXPECTED like 401, 401|403, 2xx, 3xx, 404 ("#" = comment)
#   --sni NAME[,NAME]   hostnames served on :443 of TARGET (TLS checks use these for SNI)
#   --cdn NAME[,NAME]   hostnames that should only be reachable through a CDN (e.g. Cloudflare):
#                       checks whether TARGET answers for them directly (origin bypass)
#   --delay SECONDS     pause between TCP connects (default 0.3)
#   --v6 ADDRESS        also scan this IPv6 address and compare (automatic when TARGET is a name with AAAA)
set -u

DEFAULT_PORTS="21,22,23,25,53,80,110,111,135,139,143,389,443,445,465,587,631,993,995,1433,1521,2049,2375,2376,\
3000,3001,3306,3389,4000,5000,5001,5432,5555,5601,5672,5900,6379,6380,7654,8000,8008,8080,8081,8088,8443,\
8888,9000,9090,9100,9200,9443,10000,11211,11434,13306,15672,27017"

TARGET="${1:-}"; shift || true
PORTS="$DEFAULT_PORTS"; URLS=""; SNI=""; CDN=""; DELAY="0.3"; V6=""
while [ $# -gt 0 ]; do
  case "$1" in
    --ports) PORTS="$2"; shift 2 ;;
    --urls) URLS="$2"; shift 2 ;;
    --sni) SNI="$2"; shift 2 ;;
    --cdn) CDN="$2"; shift 2 ;;
    --delay) DELAY="$2"; shift 2 ;;
    --v6) V6="$2"; shift 2 ;;
    -h|--help) sed -n '2,21p' "$0"; exit 0 ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
done
[ -z "$TARGET" ] && { sed -n '2,21p' "$0"; exit 2; }

# Resolve to one address.
if [[ "$TARGET" =~ ^[0-9.]+$ || "$TARGET" == *:* ]]; then IP="$TARGET"
else IP="$(getent ahosts "$TARGET" | awk 'NR==1{print $1}')"; fi
[ -z "$IP" ] && { echo "cannot resolve $TARGET" >&2; exit 2; }

# Refuse to probe ourselves.
is_self() { ip -o addr 2>/dev/null | awk '{print $4}' | cut -d/ -f1 | grep -qxF "$1"; }
if is_self "$IP"; then
  echo "REFUSED: $IP is an address of this machine. Traffic to it goes over loopback and bypasses the"
  echo "firewall, so every port would look reachable. Run this script from another host."
  exit 3
fi
if [ -z "$V6" ] && ! [[ "$TARGET" =~ ^[0-9.]+$ || "$TARGET" == *:* ]]; then
  V6="$(getent ahostsv6 "$TARGET" 2>/dev/null | awk '$1 !~ /^::ffff:/ {print $1; exit}')"
fi
[[ "$IP" == *:* ]] && V6=""   # the main target is already IPv6
if [ -n "$V6" ] && is_self "$V6"; then V6=""; fi

URLHOST="$IP"; [[ "$IP" == *:* ]] && URLHOST="[$IP]"
echo "# outside-in probe from $(hostname) ($(hostname -I 2>/dev/null | awk '{print $1}')) at $(date -u '+%F %T') UTC"
echo "# target $TARGET ($IP)"
echo

IFS=',' read -ra PLIST <<< "$PORTS"
scan_ports() {  # $1 = address; sets SCAN_OPEN
  SCAN_OPEN=()
  local p rc
  for p in "${PLIST[@]}"; do
    timeout 3 bash -c "exec 3<>/dev/tcp/$1/$p" 2>/dev/null; rc=$?
    case $rc in
      0) echo "  $p open"; SCAN_OPEN+=("$p") ;;
      *) : ;;    # closed (refused) or filtered (124 = silently dropped)
    esac
    sleep "$DELAY"
  done
  echo "  open: ${SCAN_OPEN[*]:-(none)}   (all others: closed or filtered)"
}

echo "## TCP ports"
scan_ports "$IP"
OPEN=("${SCAN_OPEN[@]}")
echo

if [ -n "$V6" ]; then
  echo "## TCP ports on IPv6 $V6"
  if ! ip -6 route get "$V6" >/dev/null 2>&1; then
    echo "  (this machine has no IPv6 route — IPv6 NOT tested; run from a machine with IPv6)"
  else
    scan_ports "$V6"
    only6=(); for p in "${SCAN_OPEN[@]}"; do [[ " ${OPEN[*]:-} " == *" $p "* ]] || only6+=("$p"); done
    only4=(); for p in "${OPEN[@]}"; do [[ " ${SCAN_OPEN[*]:-} " == *" $p "* ]] || only4+=("$p"); done
    [ ${#only6[@]} -gt 0 ] && echo "  !! open on IPv6 but not on IPv4: ${only6[*]} — the IPv6 firewall is looser"
    [ ${#only4[@]} -gt 0 ] && echo "  note: open on IPv4 only: ${only4[*]}"
    [ ${#only6[@]} -eq 0 ] && [ ${#only4[@]} -eq 0 ] && echo "  same open ports as IPv4"
  fi
  echo
fi

echo "## What answers on open ports"
for p in "${OPEN[@]}"; do
  case "$p" in
    22)
      banner="$(timeout 4 bash -c "exec 3<>/dev/tcp/$IP/22; head -c 80 <&3" 2>/dev/null | tr -d '\r\n')"
      echo "  22 banner: ${banner:-?}"
      if command -v ssh >/dev/null; then
        methods="$(ssh -o BatchMode=yes -o PreferredAuthentications=none -o StrictHostKeyChecking=no \
          -o UserKnownHostsFile=/dev/null -o ConnectTimeout=5 -o LogLevel=ERROR "audit-probe@$IP" 2>&1 \
          | grep -o 'Permission denied (.*)' | head -1)"
        echo "  22 auth methods offered: ${methods:-?}"
        [[ "$methods" == *password* || "$methods" == *keyboard-interactive* ]] && \
          echo "  !! SSH offers password/keyboard-interactive login to the internet"
      fi ;;
    25|587|465|143|993|110|995)
      if [ "$p" = 465 ] || [ "$p" = 993 ] || [ "$p" = 995 ]; then
        b="$(timeout 5 openssl s_client -connect "$URLHOST:$p" -quiet </dev/null 2>/dev/null | head -1 | tr -d '\r')"
      else
        b="$(timeout 4 bash -c "exec 3<>/dev/tcp/$IP/$p; head -1 <&3" 2>/dev/null | tr -d '\r')"
      fi
      echo "  $p banner: ${b:-?}   (open-relay/auth tests are NOT done by this script)" ;;
    80)
      code="$(curl -s -m 8 -o /dev/null -w '%{http_code} -> %{redirect_url}' "http://$URLHOST/")"
      echo "  80 http (bare IP): $code" ;;
    443)
      code="$(curl -sk -m 8 -o /dev/null -w '%{http_code}' "https://$URLHOST/")"
      echo "  443 https (bare IP, no SNI): $code" ;;
    *)
      h="$(curl -s -m 6 -o /dev/null -w '%{http_code}' "http://$URLHOST:$p/")"
      s="$(curl -sk -m 6 -o /dev/null -w '%{http_code}' "https://$URLHOST:$p/")"
      line="  $p http=$h https=$s"
      if [ "$h" != "000" ]; then line="$line   !! answers plain HTTP (credentials/cookies would travel unencrypted)"; fi
      if [ "$h" = "000" ] && [ "$s" = "000" ]; then line="$line   (not HTTP)"; fi
      echo "$line" ;;
  esac
done
echo

if [[ " ${OPEN[*]:-} " == *" 443 "* ]]; then
  echo "## TLS on 443"
  names="${SNI:-$TARGET}"
  IFS=',' read -ra NLIST <<< "$names"
  for n in "${NLIST[@]}"; do
    cert="$(timeout 8 openssl s_client -connect "$URLHOST:443" -servername "$n" </dev/null 2>/dev/null \
      | openssl x509 -noout -subject -issuer -enddate 2>/dev/null | tr '\n' ' ')"
    echo "  $n: ${cert:-no certificate}"
    for v in tls1 tls1_1; do
      if timeout 8 openssl s_client -connect "$URLHOST:443" -servername "$n" "-$v" </dev/null >/dev/null 2>&1; then
        echo "  !! $n accepts ${v/_/.} (should be disabled)"
      fi
    done
    hsts="$(curl -skI -m 8 --resolve "$n:443:$IP" "https://$n/" | grep -i '^strict-transport-security' | tr -d '\r')"
    echo "  $n HSTS: ${hsts:-none}"
  done
  echo
fi

if [ -n "$CDN" ]; then
  echo "## CDN origin bypass (does the origin answer directly for CDN-fronted names?)"
  IFS=',' read -ra CLIST <<< "$CDN"
  for n in "${CLIST[@]}"; do
    via="$(curl -sI -m 8 "https://$n/" | grep -i -E '^(cf-ray|x-amz-cf-id|x-served-by|x-cache):' | head -1 | tr -d '\r')"
    direct="$(curl -sk -m 8 -o /dev/null -w '%{http_code}' --resolve "$n:443:$IP" "https://$n/")"
    echo "  $n  via-CDN-header: ${via:-none}   direct-to-origin: $direct"
    if [[ "$direct" =~ ^[23] ]]; then
      echo "  !! origin $IP serves $n directly — WAF/DDoS protection of the CDN can be bypassed"
    fi
  done
  echo
fi

if [ -n "$URLS" ]; then
  echo "## URL expectations (no credentials sent)"
  bad=0
  while read -r url expect _; do
    [[ -z "${url:-}" || "$url" == \#* ]] && continue
    resp="$(curl -s -m 10 -o /dev/null -D - -w '\n%{http_code}' "$url" 2>/dev/null | tr -d '\r')"
    code="${resp##*$'\n'}"
    cache="$(printf '%s\n' "$resp" | grep -i -E '^(cf-cache-status|x-cache|x-cache-status|age):' | tr '\n' ' ')"
    ok=0
    IFS='|' read -ra EXP <<< "${expect:-401}"
    for e in "${EXP[@]}"; do
      if [[ "$e" == ?xx ]]; then [[ "${code:0:1}" == "${e:0:1}" ]] && ok=1
      else [[ "$code" == "$e" ]] && ok=1; fi
    done
    if [ $ok = 1 ]; then echo "  ok        $code  $url"
    else echo "  !! MISMATCH got $code expected $expect  $url"; bad=$((bad+1)); fi
    # A CDN can keep serving an old answer after a fix (or hide a broken one): ask the origin too.
    host="$(printf '%s' "$url" | sed -E 's#^[A-Za-z]+://([^/:?]+).*#\1#')"
    origin=""
    if [[ "$url" == https://* && ",$CDN," == *",$host,"* ]]; then
      origin="$(curl -sk -m 10 -o /dev/null -w '%{http_code}' --resolve "$host:443:$IP" "$url")"
    fi
    hit=0
    printf '%s' "$cache" | grep -q -i -E '(cache(-status)?: *(hit|stale|updating|revalidated))|(age: *[1-9])' && hit=1
    if [ -n "$origin" ] && [ "$origin" != "$code" ]; then
      from=""; [ $hit = 1 ] && from=" from its cache (${cache% })"
      echo "     ^ the origin answers $origin, the CDN $code$from — purge the CDN cache for this URL, then re-run"
    elif [ $hit = 1 ]; then
      echo "     ^ answered from a cache (${cache% }): the origin was not asked — check it directly" \
           "(curl --resolve $host:443:ORIGIN-IP), purge the cache after a fix, re-run"
    fi
    sleep "$DELAY"
  done < "$URLS"
  echo "  mismatches: $bad"
fi
