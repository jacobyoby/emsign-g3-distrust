#!/usr/bin/env bash
# Live-fire test for emsign-g3-distrust.rules: generate a cert whose ISSUER DN equals a
# compromised eMudhra intermediate, present it over TLS 1.2 (so the cert is in cleartext),
# capture the handshake, run the ruleset offline, and confirm an emSign rule fires.
#
# Needs root for loopback capture:  sudo ./suricata_livefire_test.sh
# Optional: SURICATA_YAML=/path/to/suricata.yaml  and  arg1 = path to the .rules file.
#
# This uses a SYNTHETIC CA with the same issuer DN string the rule matches on — it does not
# use (or need) the real compromised private key. It proves the rule logic fires on that
# issuer; Part A (openssl verify on the real Shelikhoo leaf) already proved the trust/revocation path.
set -uo pipefail

RULES="${1:-$(cd "$(dirname "$0")" && pwd)/emsign-g3-distrust.rules}"
YAML="${SURICATA_YAML:-/opt/homebrew/etc/suricata/suricata.yaml}"
[ -f "$YAML" ] || YAML="/etc/suricata/suricata.yaml"
PORT="${PORT:-443}"   # Suricata's default TLS app-layer detection is port 443; use it
IFACE="${IFACE:-lo0}"          # lo0 on macOS, "lo" on Linux
command -v suricata >/dev/null || { echo "suricata not found on PATH"; exit 1; }
[ -f "$RULES" ] || { echo "rules file not found: $RULES"; exit 1; }

T="$(mktemp -d)"
SRV=""; TCPD=""
cleanup(){ [ -n "$SRV" ] && kill "$SRV" 2>/dev/null; [ -n "$TCPD" ] && kill "$TCPD" 2>/dev/null; rm -rf "$T"; }
trap cleanup EXIT

echo "# live-fire test  (rules: $RULES)"
echo "# workdir: $T   iface: $IFACE   port: $PORT"

# 1. synthetic chain whose CA subject == forged leaf's issuer DN
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-384 -nodes \
  -keyout "$T/ca.key" -out "$T/ca.pem" -days 1 \
  -subj "/C=NL/O=eMudhra BV/CN=EM DV TLS CA - G3B" 2>/dev/null
openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
  -keyout "$T/leaf.key" -out "$T/leaf.csr" -subj "/CN=victim.example.test" 2>/dev/null
openssl x509 -req -in "$T/leaf.csr" -CA "$T/ca.pem" -CAkey "$T/ca.key" \
  -CAcreateserial -days 1 -out "$T/leaf.pem" 2>/dev/null
cat "$T/leaf.pem" "$T/ca.pem" > "$T/chain.pem"
echo "  issuer presented: $(openssl x509 -in "$T/leaf.pem" -noout -issuer | sed 's/issuer=//')"

# 2. capture (root BPF)
tcpdump -i "$IFACE" -w "$T/hs.pcap" "tcp port $PORT" 2>"$T/tcpdump.err" &
TCPD=$!
sleep 1
if ! kill -0 "$TCPD" 2>/dev/null; then
  echo "FAIL: capture did not start — $(cat "$T/tcpdump.err")"
  echo "      (run under sudo; loopback capture needs root BPF)"; exit 2
fi

# 3. TLS 1.2 handshake (cert in cleartext)
openssl s_server -tls1_2 -cert "$T/chain.pem" -key "$T/leaf.key" \
  -accept "$PORT" -quiet >/dev/null 2>&1 &
SRV=$!
sleep 1
echo Q | openssl s_client -tls1_2 -connect "127.0.0.1:$PORT" \
  -servername victim.example.test >/dev/null 2>&1
sleep 1
kill "$SRV" 2>/dev/null; SRV=""
sleep 1
kill "$TCPD" 2>/dev/null; TCPD=""
sleep 1

PKTS=$(tcpdump -r "$T/hs.pcap" 2>/dev/null | wc -l | tr -d ' ')
echo "  packets captured: $PKTS"

# 4. run the ruleset offline over the pcap.
#    Force TLS app-layer detection on this PORT in case the default yaml gates it to 443.
# -k none: loopback TCP checksums are offloaded/invalid; without this Suricata drops the
# packets from reassembly and never runs the TLS parser.
suricata -r "$T/hs.pcap" -S "$RULES" -c "$YAML" -l "$T" -k none \
  --set "app-layer.protocols.tls.detection-ports.dp=$PORT" >/dev/null 2>&1

# inline diagnostics (printed as root, so no file-permission issues for the operator)
TLS_EVENTS=$(grep -c '"event_type":"tls"' "$T/eve.json" 2>/dev/null); TLS_EVENTS=${TLS_EVENTS:-0}
ISSUER=$(grep -o '"issuerdn":"[^"]*"' "$T/eve.json" 2>/dev/null | head -1)
ALERTS=$(grep -c '"event_type":"alert"' "$T/eve.json" 2>/dev/null); ALERTS=${ALERTS:-0}
LINKTYPE=$(tcpdump -r "$T/hs.pcap" -c1 2>&1 | head -1)
echo "  suricata saw: tls_events=$TLS_EVENTS  alerts=$ALERTS"
[ -n "$ISSUER" ] && echo "  parsed issuer: $ISSUER"

# 5. verdict
if grep -q "Bug2083449" "$T/fast.log" 2>/dev/null || \
   grep -q "Bug2083449" "$T/eve.json" 2>/dev/null; then
  echo "PASS: emSign-G3 rule fired on the handshake:"
  { grep -ho '"signature":"[^"]*"' "$T/eve.json" 2>/dev/null | sort -u; \
    grep "Bug2083449" "$T/fast.log" 2>/dev/null; } | sed 's/^/    /'
  exit 0
else
  echo "FAIL: no emSign rule fired."
  echo "  - packets: $PKTS (0 => capture/iface wrong; try IFACE=lo on Linux)"
  echo "  - tls_events=$TLS_EVENTS: if 0, Suricata did not parse TLS (port/linktype);"
  echo "    if >0 but alerts=0, the cert was parsed but the issuer content did not match."
  echo "  - confirm TLS 1.2 (TLS 1.3 encrypts the cert; this script forces 1.2)"
  echo "  - artifacts (root-owned): $T/fast.log  $T/eve.json  $T/hs.pcap"
  trap - EXIT; [ -n "$SRV" ] && kill "$SRV" 2>/dev/null; [ -n "$TCPD" ] && kill "$TCPD" 2>/dev/null
  echo "  (workdir kept: $T)"
  exit 3
fi
