# Detection rule artifacts

Committed SIEM starter rules generated from [`indicators.csv`](../indicators.csv).

| Directory | Format | Use |
|-----------|--------|-----|
| [`sigma/`](sigma/) | Sigma YAML | Import into Sigma-compatible SIEMs; maps Suricata EVE `tls.issuerdn` and `alert.signature_id`. |
| [`elastic/`](elastic/) | Elastic KQL | Paste into Kibana detection rules; tune ECS field names for your pipeline. |

Network blocking for inline sensors remains [`tools/emsign-g3-distrust.rules`](../tools/emsign-g3-distrust.rules) (Suricata/Snort).

Regenerate after changing indicators:

```bash
tools/regenerate_detection_rules.sh
```

CI verifies committed files match generators (`--check-committed-rules`).
