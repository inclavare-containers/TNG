#!/usr/bin/env bash
# OHTTP relay anonymization demo (Aliyun + Terraform).
#
# Bring-up: terraform apply -> provision ECS (TNG egress + echo) + FC relay ->
# start a local TNG ingress -> capture the TLS ClientHello on both legs ->
# curl the relay (echo reports what the gateway saw) -> compare client-side vs
# gateway-side on several dimensions -> print a per-dimension anonymity table.
# Teardown: --destroy -> terraform destroy.
#
# Prereqs (env): ALICLOUD_ACCESS_KEY, ALICLOUD_SECRET_KEY, ALICLOUD_REGION.
# Local: `tng`, `tshark`, and `terraform` on PATH, run as ROOT (raw-socket
# capture on the runner's egress for the ingress->relay ClientHello).
set -euo pipefail

DEMO_DIR="$(cd "$(dirname "$0")" && pwd)"
TF_DIR="$DEMO_DIR/terraform"
TNG_BIN="${TNG_BIN:-tng}"
PROXY_PORT="${PROXY_PORT:-41000}"
ECS_WAIT="${ECS_WAIT:-300}"   # seconds for cloud-init (TNG + nginx + acme.sh LE cert)
FC_TRIGGER_URL="${FC_TRIGGER_URL:-}"  # override if the derived URL is wrong
CAPTURE_DUR="${CAPTURE_DUR:-25}"  # seconds the ClientHello captures run

die() { echo "ERROR: $*" >&2; exit 1; }

usage() {
  cat <<EOF
Usage: $0 [--destroy] [--fc-url URL]
  --destroy          tear down the demo (terraform destroy)
  --fc-url URL       FC HTTP trigger URL (override the derived one)
Env: ALICLOUD_ACCESS_KEY, ALICLOUD_SECRET_KEY, ALICLOUD_REGION
     TNG_BIN (default: tng), PROXY_PORT (default: 41000), ECS_WAIT (default: 300)
     FC_TRIGGER_URL (override the derived FC URL), CAPTURE_DUR (default: 25)
Requires on PATH: terraform, tng, tshark, git, go. Must run as root.
EOF
}

DESTROY=0
while [ $# -gt 0 ]; do
  case "$1" in
    --destroy) DESTROY=1 ;;
    --fc-url) shift; FC_TRIGGER_URL="$1" ;;
    -h|--help) usage; exit 0 ;;
    *) die "unknown arg: $1" ;;
  esac
  shift
done

# Root: Leg A capture (ingress->relay ClientHello) uses tshark on this
# machine's egress, which needs raw-socket access.
[ "$(id -u)" -eq 0 ] || die "must run as root (tshark raw-socket capture on the runner). Re-run with sudo."
command -v tshark >/dev/null 2>&1 || die "tshark not found on this machine. Install: yum install -y wireshark-cli (or apt install -y tshark)"

# This machine's public IP, fetched once outside any capture window. It serves
# both as the SSH SG source (/32) and as the client's real IP in the table, so
# no 443 traffic from this script pollutes the Leg A capture.
RUNNER_IP="$(curl -fsS --max-time 10 https://api.ip.sb/ip || curl -fsS --max-time 10 https://ifconfig.me)" || die "could not determine this machine's public IP"
[ -n "$RUNNER_IP" ] || die "empty public IP from ip.sb/ifconfig.me"
export TF_VAR_ssh_allow_cidr="${RUNNER_IP}/32"

cd "$TF_DIR"

# Build the forked alicloud provider (TDX security_options) + dev_overrides.
# setup-provider.sh clones the fork into a sibling ./terraform-provider-alicloud/
# (gitignored, not a submodule), builds the binary, and prints the CLI config path.
echo ">>> Setting up the forked alicloud provider (TDX security_options)..."
TF_CLI_CONFIG_FILE="$(bash "$DEMO_DIR/setup-provider.sh")"
export TF_CLI_CONFIG_FILE

# Turn on FC relay body logging (ciphertext) for the demo.
export TF_VAR_fc_log_request_body=true

if [ "$DESTROY" = "1" ]; then
  echo ">>> Tearing down the demo (terraform destroy)..."
  terraform destroy -auto-approve
  echo ">>> Done. All demo resources destroyed."
  exit 0
fi

# 1. Bring up cloud resources.
echo ">>> terraform apply (ECS TNG egress + echo, FC relay, networking, SSH key)..."
terraform apply -auto-approve

ECS_EIP="$(terraform output -raw ecs_eip)"
SSH_KEY="$(terraform output -raw ssh_key_path)"
[ -n "$FC_TRIGGER_URL" ] || FC_TRIGGER_URL="$(terraform output -raw fc_trigger_url 2>/dev/null || true)"
[ -n "$FC_TRIGGER_URL" ] || die "Could not derive the FC trigger URL. Set FC_TRIGGER_URL from the FC console and re-run."
echo ">>> ECS EIP: $ECS_EIP"
echo ">>> SSH key: $SSH_KEY"
echo ">>> FC trigger URL: $FC_TRIGGER_URL"

# SSH helper for the one-shot tshark capture on the ECS (Leg B).
ssh_ecs() {
  ssh -i "$SSH_KEY" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
      -o ConnectTimeout=15 -o LogLevel=ERROR "root@${ECS_EIP}" "$@"
}

FC_HOST="$(python3 -c "from urllib.parse import urlparse; print(urlparse('$FC_TRIGGER_URL').hostname)")"
[ -n "$FC_HOST" ] || die "could not parse hostname from FC_TRIGGER_URL"
# The app requests a PLAIN-HTTP URL through the ingress (http_proxy + ohttp can
# only encapsulate plain HTTP, not HTTPS CONNECT tunnels). ohttp.tls makes the
# outer OHTTP POST HTTPS to the FC relay. Port 443 matches dst_filters.
FC_PATH="$(python3 -c "from urllib.parse import urlparse; p=urlparse('$FC_TRIGGER_URL').path; print(p or '/')")"

# 2. Wait for the FC relay to come up.
echo ">>> Waiting for FC relay /metadata..."
for i in $(seq 1 30); do
  if curl -fsS "https://${FC_HOST}/metadata" >/dev/null 2>&1; then
    echo "    FC relay up."; break
  fi
  sleep 5
done

echo ">>> Waiting ${ECS_WAIT}s for ECS cloud-init (TNG + nginx + acme.sh LE cert)..."
sleep "$ECS_WAIT"

# Install tshark on the ECS (SSH key is injected at instance creation, so SSH is
# up once sshd starts; cloud-init finished above so the yum repos are ready).
echo ">>> Installing tshark on the ECS (idempotent; first run is slow)..."
for i in $(seq 1 6); do
  if ssh_ecs "command -v tshark >/dev/null 2>&1 || yum install -y wireshark-cli >/dev/null 2>&1" 2>/dev/null \
     && ssh_ecs "command -v tshark >/dev/null 2>&1" 2>/dev/null; then
    echo "    tshark ready on ECS."; break
  fi
  [ "$i" = 6 ] && die "tshark not ready on the ECS after retries. SSH in and run: yum install -y wireshark-cli"
  sleep 10
done

# 3. Start the local TNG ingress (OHTTP client). RA off (no verify).
#    path_default=original so the outer OHTTP POST path matches the FC trigger
#    path the app requests.
echo ">>> Starting local TNG ingress on :$PROXY_PORT..."
INGRESS_PID=
cleanup() {
  if [ -n "$INGRESS_PID" ]; then kill "$INGRESS_PID" 2>/dev/null || true; fi
}
trap cleanup EXIT INT TERM

"$TNG_BIN" launch --config-content "$(cat <<EOF
{
  "add_ingress": [
    {
      "http_proxy": {
        "proxy_listen": { "host": "0.0.0.0", "port": ${PROXY_PORT} },
        "dst_filters": { "domain": "${FC_HOST}", "port": 443 }
      },
      "ohttp": { "tls": true, "path_default": "original" },
      "no_ra": true
    }
  ]
}
EOF
)" &
INGRESS_PID=$!

# Wait for the local proxy port to listen (port probe, not an OHTTP request).
for i in $(seq 1 30); do
  if (exec 3<>"/dev/tcp/127.0.0.1/${PROXY_PORT}") 2>/dev/null; then
    exec 3>&- 3<&-; break
  fi
  sleep 2
done

# 4. Capture the TLS ClientHello on both legs around the request.
#    Leg A (ingress->relay, client side): captured locally; the only 443
#    egress in this window is the ingress->fcapp.run handshake.
#    Leg B (relay->ECS:8443, gateway side): captured on the ECS via SSH.
#    tshark dissects into text fields (no pcap lands on the ECS); the Leg B
#    dump is read back with `ssh cat`.
# Capture field names target the bundled wireshark-cli on Aliyun Linux 3
# (Wireshark 2.6.2, which uses the legacy ssl.* dissector prefix; later
# Wireshark renamed these to tls.*). The runner and the ECS run the same image,
# so the names agree on both legs.
if ! tshark -G fields 2>/dev/null | grep -q $'\tssl.handshake.type\t'; then
  die "tshark here is not Aliyun Linux 3's wireshark-cli 2.6.2 (ssl.* fields missing). The capture field names target 2.6.2."
fi
HS="ssl.handshake"
# Extension type is ssl.handshake.extension.type (singular, dotted) in 2.6.2; the
# other fields use ssl.handshake.extensions_* (plural). Legacy naming.
TSHK_FIELDS="-e ${HS}.extensions_server_name -e ${HS}.extensions_alpn_str -e ${HS}.version -e ${HS}.ciphersuite -e ${HS}.extension.type -e ${HS}.extensions_supported_group -e ${HS}.extensions_ec_point_format"
TSHK_FILTER="${HS}.type == 1"
LEGA_DUMP=/tmp/tng-lega.txt
LEGB_DUMP=/tmp/tng-legb.txt
rm -f "$LEGA_DUMP" "$LEGB_DUMP"

echo ">>> Starting ClientHello captures for ${CAPTURE_DUR}s (Leg A local, Leg B on ECS)..."
tshark -i any -f 'tcp port 443' -Y "$TSHK_FILTER" -a "duration:${CAPTURE_DUR}" \
  -T fields -E separator='|' -E header=n $TSHK_FIELDS > "$LEGA_DUMP" 2>/dev/null &
LEGA_PID=$!
ssh_ecs "tshark -i any -f 'tcp port 8443' -Y '${TSHK_FILTER}' -a duration:${CAPTURE_DUR} -T fields -E separator='|' -E header=n ${TSHK_FIELDS}" > "$LEGB_DUMP" 2>/dev/null &
LEGB_PID=$!

# Let both captures attach before triggering the handshakes.
sleep 2

# 5. Through the relay: the echo reports what the server side sees. Each
#    dimension is judged independently. IP-family dimensions should be
#    ANONYMIZED (the gateway saw the relay, not the client); content headers
#    are VISIBLE (OHTTP hides the client's network identity, not the HTTP
#    content the client sent).
echo ">>> Sending a request through: local ingress -> FC relay -> ECS egress -> echo"
# A fixed User-Agent so the "client sent" value is known exactly.
ECHO_JSON="$(curl -sS -x "http://127.0.0.1:${PROXY_PORT}" \
  "http://${FC_HOST}:443${FC_PATH}" \
  -H 'accept: application/json' -H 'user-agent: tng-demo/1.0' 2>&1 || true)"

# Wait for both captures to finish (they self-stop on duration).
wait "$LEGA_PID" 2>/dev/null || true
wait "$LEGB_PID" 2>/dev/null || true

TCP_SRC="$(printf '%s' "$ECHO_JSON" | python3 -c 'import json,sys;print(json.load(sys.stdin).get("tcp_source") or "")' 2>/dev/null || true)"
X_REAL="$(printf '%s' "$ECHO_JSON" | python3 -c 'import json,sys;print(json.load(sys.stdin).get("x_real_ip") or "")' 2>/dev/null || true)"
XFF="$(printf '%s' "$ECHO_JSON" | python3 -c 'import json,sys;print(json.load(sys.stdin).get("x_forwarded_for") or "")' 2>/dev/null || true)"
HDR_GET='import json,sys;h={k.lower():v for k,v in json.load(sys.stdin).get("headers",{}).items()};print(h.get("%s") or "")'
UA_SAW="$(printf '%s' "$ECHO_JSON" | python3 -c "$(printf "$HDR_GET" user-agent)" 2>/dev/null || true)"
ACCEPT_SAW="$(printf '%s' "$ECHO_JSON" | python3 -c "$(printf "$HDR_GET" accept)" 2>/dev/null || true)"

# Client-sent values: the IP-family dimensions carry the client's real public IP
# (network-layer source); curl does not send X-Real-IP / X-Forwarded-For, those
# are added by proxies along the path; content headers are what curl put on the
# wire. Host is omitted from the table: it is the relay's own hostname (the URL
# curl requests), not a client fingerprint, so it carries no anonymity signal.
REAL_IP="$RUNNER_IP"
UA_SENT="tng-demo/1.0"
ACCEPT_SENT="application/json"

# Parse the two ClientHello dumps and compute JA3 for each. JA3 = MD5 of
# "version,ciphers,extensions,groups,ec_point_formats" (lists "-"-joined).
# tshark emits multi-value fields comma-separated; the comparison is valid
# regardless of JA3 representation convention because both legs use the same one.
PARSE="$(python3 -c '
import sys,hashlib
def load(path,want):
    try: lines=open(path).read().strip().splitlines()
    except Exception: lines=[]
    chosen=None
    for ln in lines:
        f=ln.split("|")
        if len(f)<7: continue
        if want and want in f[0]: chosen=f; break
    if chosen is None:
        for ln in lines:
            f=ln.split("|")
            if len(f)>=7: chosen=f; break
    if chosen is None: return ("<no capture>","<no capture>","<no capture>")
    sni,alpn,ver,ciph,exts,grps,ecpt=chosen[:7]
    d=lambda s:"-".join([x for x in s.split(",") if x]) if s else ""
    s=ver+","+d(ciph)+","+d(exts)+","+d(grps)+","+d(ecpt)
    return (sni,alpn,hashlib.md5(s.encode()).hexdigest())
a=load(sys.argv[1],sys.argv[2]); b=load(sys.argv[3],"")
print("\t".join([a[0],a[1],a[2],b[0],b[1],b[2]]))
' "$LEGA_DUMP" "$FC_HOST" "$LEGB_DUMP" 2>/dev/null || true)"
SNI_A="$(printf '%s' "$PARSE" | cut -f1)"; ALPN_A="$(printf '%s' "$PARSE" | cut -f2)"; JA3_A="$(printf '%s' "$PARSE" | cut -f3)"
SNI_B="$(printf '%s' "$PARSE" | cut -f4)"; ALPN_B="$(printf '%s' "$PARSE" | cut -f5)"; JA3_B="$(printf '%s' "$PARSE" | cut -f6)"

# IP-family verdict: LEAKED only when the gateway-saw value exactly equals the
# client's real IP; empty or any other value (the relay, loopback) is ANONYMIZED.
ip_verdict() {
  [ -n "$1" ] && [ "$1" = "$2" ] && echo "LEAKED" || echo "ANONYMIZED"
}
# X-Forwarded-For is a comma-separated chain; LEAKED only if the real IP is one
# of the entries.
xff_verdict() {
  local leaked=0 p
  if [ -n "$1" ]; then
    IFS=',' read -ra _parts <<< "$1"
    for p in "${_parts[@]}"; do p="${p// /}"; [ "$p" = "$2" ] && leaked=1; done
  fi
  [ "$leaked" = 1 ] && echo "LEAKED" || echo "ANONYMIZED"
}
# Content verdict: VISIBLE (容许) when the gateway saw the value — OHTTP hides
# the client's network identity, not the HTTP content, so content-header
# exposure is permitted/out-of-scope, not a leak. ANONYMIZED when empty.
content_verdict() { [ -n "$1" ] && echo "VISIBLE (permitted)" || echo "ANONYMIZED"; }
# Display a cell: "<no capture>" when the dump had no ClientHello, "<none>" for
# an empty-but-captured field, else the value.
disp() { case "$1" in "<no capture>") echo "<no capture>";; "") echo "<none>";; *) echo "$1";; esac; }
# Fingerprint verdict (TLS JA3, SNI, ALPN): compare the client-side value (Leg A)
# with the gateway-side value (Leg B). "<no capture>" on either side -> N/A
# (capture missed, can't judge). Equal non-empty -> the client's fingerprint
# reached the gateway (LEAKED); otherwise -> the relay re-originated TLS,
# severing the client-side fingerprint (ANONYMIZED). A captured-but-empty
# gateway value (the relay sent no SNI/ALPN) counts as ANONYMIZED, not N/A.
fp_verdict() {
  [ "$1" = "<no capture>" ] || [ "$2" = "<no capture>" ] && { echo "N/A"; return; }
  [ "$1" = "$2" ] && [ -n "$1" ] && echo "LEAKED" || echo "ANONYMIZED"
}

V_TCP="$(ip_verdict "$TCP_SRC" "$REAL_IP")"
V_XR="$(ip_verdict "$X_REAL" "$REAL_IP")"
V_XFF="$(xff_verdict "$XFF" "$REAL_IP")"
V_UA="$(content_verdict "$UA_SAW")"
V_ACC="$(content_verdict "$ACCEPT_SAW")"
V_JA3="$(fp_verdict "$JA3_A" "$JA3_B")"
V_SNI="$(fp_verdict "$SNI_A" "$SNI_B")"
V_ALPN="$(fp_verdict "$ALPN_A" "$ALPN_B")"

rule="$(printf '%.0s-' $(seq 1 117))"
fmt='  %-18s %-42s %-42s %s\n'

echo
echo "  OHTTP relay anonymity probe"
echo "  $rule"
printf "$fmt" "dimension" "client sent" "gateway saw" "verdict"
echo "  $rule"
printf "$fmt" "TCP source IP" "$(disp "$REAL_IP")" "$(disp "$TCP_SRC")" "$V_TCP"
printf "$fmt" "X-Real-IP" "$(disp "<none>")" "$(disp "$X_REAL")" "$V_XR"
printf "$fmt" "X-Forwarded-For" "$(disp "<none>")" "$(disp "$XFF")" "$V_XFF"
printf "$fmt" "TLS fingerprint" "$(disp "$JA3_A")" "$(disp "$JA3_B")" "$V_JA3"
printf "$fmt" "SNI" "$(disp "$SNI_A")" "$(disp "$SNI_B")" "$V_SNI"
printf "$fmt" "ALPN" "$(disp "$ALPN_A")" "$(disp "$ALPN_B")" "$V_ALPN"
echo "  $rule"
printf "$fmt" "User-Agent" "$(disp "$UA_SENT")" "$(disp "$UA_SAW")" "$V_UA"
printf "$fmt" "Accept" "$(disp "$ACCEPT_SENT")" "$(disp "$ACCEPT_SAW")" "$V_ACC"
echo "  $rule"
echo "  note: teardown  $0 --destroy"
echo "  note: content headers are out of OHTTP scope; hiding them needs app-layer anonymization"
echo
