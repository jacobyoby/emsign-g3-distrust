#!/usr/bin/env bash
# Live-fire test for emsign-g3-distrust.rules: replay a recorded TLS 1.2 handshake whose
# server leaf was issued under a compromised eMudhra intermediate, run the ruleset offline,
# and confirm an emSign rule fires. No root, no network, no keys.
#
# Optional: SURICATA_YAML=/path/to/suricata.yaml  arg1 = .rules file  arg2 = .pcap fixture
#
# The default fixture (tests/fixtures/em-dv-tls-ca-g3b-handshake.pcap) is a real handshake
# with dv-g3b-emudhra.we-have-a-problem.com, a public researcher demo of this compromise,
# recorded by tools/record_handshake_fixture.py. Its leaf is issued by EM DV TLS CA - G3B.
# Nothing in this repo mints or signs a certificate.
set -uo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
RULES="${1:-$HERE/emsign-g3-distrust.rules}"
PCAP="${2:-$HERE/../tests/fixtures/em-dv-tls-ca-g3b-handshake.pcap}"
YAML="${SURICATA_YAML:-/opt/homebrew/etc/suricata/suricata.yaml}"
[ -f "$YAML" ] || YAML="/etc/suricata/suricata.yaml"
command -v suricata >/dev/null || { echo "suricata not found on PATH"; exit 1; }
[ -f "$RULES" ] || { echo "rules file not found: $RULES"; exit 1; }
[ -f "$PCAP" ] || { echo "pcap fixture not found: $PCAP"; exit 1; }

T="$(mktemp -d)"
trap 'rm -rf "$T"' EXIT

echo "# live-fire test  (rules: $RULES)"
echo "# fixture: $PCAP   workdir: $T"

# 1. run the ruleset offline over the recorded handshake
suricata -r "$PCAP" -S "$RULES" -c "$YAML" -l "$T" >/dev/null 2>&1

TLS_EVENTS=$(grep -c '"event_type":"tls"' "$T/eve.json" 2>/dev/null); TLS_EVENTS=${TLS_EVENTS:-0}
ISSUER=$(grep -o '"issuerdn":"[^"]*"' "$T/eve.json" 2>/dev/null | head -1)
ALERTS=$(grep -c '"event_type":"alert"' "$T/eve.json" 2>/dev/null); ALERTS=${ALERTS:-0}
echo "  suricata saw: tls_events=$TLS_EVENTS  alerts=$ALERTS"
[ -n "$ISSUER" ] && echo "  parsed issuer: $ISSUER"

# 2. verdict
if grep -q "Bug2083449" "$T/fast.log" 2>/dev/null || \
   grep -q "Bug2083449" "$T/eve.json" 2>/dev/null; then
  echo "PASS: emSign-G3 rule fired on the handshake:"
  { grep -ho '"signature":"[^"]*"' "$T/eve.json" 2>/dev/null | sort -u; \
    grep "Bug2083449" "$T/fast.log" 2>/dev/null; } | sed 's/^/    /'
  exit 0
else
  echo "FAIL: no emSign rule fired."
  echo "  - tls_events=$TLS_EVENTS: if 0, Suricata did not parse TLS (yaml/app-layer config);"
  echo "    if >0 but alerts=0, the cert was parsed but the issuer content did not match."
  trap - EXIT
  echo "  (workdir kept: $T)"
  exit 3
fi
