# Deny the compromised eMudhra / emSign G3 intermediate CAs

In October 2026, the private keys of **eight eMudhra intermediate CA certificates**
were found to be trivially recoverable (P-384 keys generated with private scalars
below 256). They were revoked `cACompromise` on 2026-10-18 and distrusted by the
Mozilla, Chrome, Microsoft and Apple root programs — see
[Mozilla Bug 2083449](https://bugzilla.mozilla.org/show_bug.cgi?id=2083449).

Because a leaked private key cannot be un-leaked, **anyone** can mint a validly-signed
certificate for **any** domain (6 TLS keys) or **any** publisher (2 code-signing keys)
that chains to these intermediates. Such a forgery is accepted by any client that still
trusts the emSign G3 roots and has not received the distrust push — and a forged leaf
need carry no revocation pointer, so a client that only checks the *leaf's* revocation
will not catch it. This repo helps you **detect and deny** that path.

> This repository deliberately contains **no private keys** — only the public
> certificates, their fingerprints, and tooling to distrust them.

## The eight compromised intermediates

| CA | Type | SHA-256 | Serial |
|----|------|---------|--------|
| EM DV TLS CA - G3B | TLS | `42c4accd…ba1493` | A4AEE678F23362B4C0E460B772F214 |
| EM DV TLS CA - G3C | TLS | `0164d7ce…934d19` | 588B2E3C2BB8CDA13E1A1209254321 |
| EM EV TLS CA - G3B | TLS | `e7568fe6…333838` | C7C41EFE92D825F05EAE841A4A82C1 |
| EM EV TLS CA - G3C | TLS | `432ec25f…0261f3` | 8009928A64107601AF05FA2F19F109 |
| EM OV TLS CA - G3B | TLS | `98b89662…83bc25b` | 6CADA367FB1C100088120EA202D568 |
| EM OV TLS CA - G3C | TLS | `cb6e1516…bf9c7c3f` | 296926C227A3A1526392B19482A504 |
| EM OV CS CA - G3B | Code signing | `9e39de28…b067b4` | 7818933F8F85B4619A2B35FBA83D0A |
| EM OV CS CA - G3C | Code signing | `4b2460a4…630b1` | 544B7F922C31AE220A4A922916F6E6 |

Roots: `emSign Root TLS CA - G3` (`7dd78d5f…2746ed8d`), `emSign Root CS CA - G3`
(`f2edaaff…aba34a5`). Full machine-readable list in [`indicators.csv`](indicators.csv),
PEMs in [`certs/`](certs/).

## Tools

- **`tools/emsign_trust_scanner.py`** — inventory a host's trust stores (OS, macOS
  keychain, Windows root, Firefox/NSS) for these anchors. Read-only. `python3 … [--json]`.
- **`tools/emsign_distrust.py`** — add the eight intermediates to each store's
  *disallowed/deny* set so a forgery is rejected even without revocation checking.
  Dry-run by default; `--apply` (sudo) to execute, `--undo` to roll back.
- **`tools/emsign-g3-distrust.rules`** — Suricata/Snort rules that drop TLS whose leaf
  is issued by any of the eight (matches `tls.cert_issuer`). Deploy inline or behind a
  decrypting proxy. Verified to fire on Suricata 8.
- **`tools/suricata_livefire_test.sh`** — replays a recorded real-world handshake
  (`tests/fixtures/`) through the rules and checks they fire. No root, no network.
- **`tools/record_handshake_fixture.py`** — how that fixture was recorded: a TLS 1.2
  handshake with a public researcher demo host, captured without root.

## The durable fix

Trust-store distrust reaches browsers via OneCRL / CRLSet and OS CA updates. The long
tail — non-browser TLS clients, embedded devices, Java/Node/`certifi` bundles, code
signing — updates on its own schedule. Use the scanner to find exposed clients and the
distruster/IDS rules to deny the keys until every client has dropped the roots.
