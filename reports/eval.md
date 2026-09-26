# privasoc evaluation (2026-09-26)

Fixtures: Elastic integrations pipeline tests @ `354ff4c940`, first half of each file visible to the generator, second half held out for scoring. F1 is micro-averaged over extractable ECS fields.

| configuration | pass@1 | pass@k | F1 (all runs) | F1 (proposed) | held-out parsed | attempts | LLM s/run | ungrounded |
|---|---|---|---|---|---|---|---|---|
| qwen3:8b (local) · structured · pseudo on · dev | 70% | 80% (k=3) | 0.37 | 0.53 | 60% | 1.9 | 24.8 | 0 |
| qwen3:8b (local) · structured · pseudo off · dev | 70% | 70% (k=3) | 0.40 | 0.57 | 64% | 1.73 | 18.0 | 0 |
| qwen3:8b (local) · vrl · pseudo on · dev | 0% | 0% (k=3) | 0.00 | 0.00 | 0% | 2.57 | 28.3 | 0 |
| hand-written (reference) · structured · pseudo on · dev | 100% | 100% (k=1) | 0.87 | 0.87 | 91% | 1 | 0.0 | 0 |
| qwen3:8b (local) · structured · pseudo on · holdout | 67% | 75% (k=3) | 0.14 | 0.21 | 64% | 1.92 | 38.5 | 0 |

Per fixture (proposed/runs, best F1):

| fixture | qwen3:8b (local) · structured · pseudo on · dev | qwen3:8b (local) · structured · pseudo off · dev | qwen3:8b (local) · vrl · pseudo on · dev | hand-written (reference) · structured · pseudo on · dev | qwen3:8b (local) · structured · pseudo on · holdout |
|---|---|---|---|---|---|
| apache | 3/3, 0.59 | 3/3, 0.54 | 0/3, 0.00 | 1/1, 0.83 |  |
| barracuda_waf |  |  |  |  | 2/3, 0.00 |
| checkpoint | 3/3, 0.80 | 3/3, 0.73 | 0/3, 0.00 |  |  |
| cisco_asa | 0/3, 0.00 | 0/3, 0.00 | 0/3, 0.00 |  |  |
| cisco_ios |  |  |  |  | 0/3, 0.00 |
| fortigate | 3/3, 0.93 | 3/3, 0.92 | 0/3, 0.00 |  |  |
| iptables | 3/3, 0.95 | 3/3, 0.95 | 0/3, 0.00 | 1/1, 0.80 |  |
| juniper_srx |  |  |  |  | 3/3, 0.23 |
| nginx | 3/3, 0.71 | 3/3, 0.76 | 0/3, 0.00 | 1/1, 0.91 |  |
| pfsense | 1/3, 0.22 | 3/3, 0.09 | 0/3, 0.00 |  |  |
| sonicwall | 3/3, 0.06 | 3/3, 0.06 | 0/3, 0.00 |  |  |
| sophos_xg |  |  |  |  | 3/3, 0.52 |
| squid | 0/3, 0.00 | 0/3, 0.00 | 0/3, 0.00 |  |  |
| sshd_auth | 2/3, 0.00 | 0/3, 0.00 | 0/3, 0.00 | 1/1, 0.95 |  |

## Pseudonymisation leakage

163 of 2010 known-sensitive values survived (**8.1%**), measured on the raw fixture lines against the values Elastic's pipeline extracts.

| field | leaked / total | rate |
|---|---|---|
| client.ip | 0 / 5 | 0% |
| destination.address | 5 / 220 | 2% |
| destination.domain | 6 / 14 | 43% |
| destination.ip | 0 / 320 | 0% |
| destination.nat.ip | 0 / 16 | 0% |
| destination.user.name | 0 / 3 | 0% |
| dns.question.name | 0 / 18 | 0% |
| host.hostname | 0 / 205 | 0% |
| observer.name | 38 / 120 | 32% |
| source.address | 3 / 281 | 1% |
| source.domain | 4 / 15 | 27% |
| source.ip | 0 / 429 | 0% |
| source.nat.ip | 0 / 29 | 0% |
| source.user.name | 101 / 177 | 57% |
| url.domain | 0 / 116 | 0% |
| user.name | 6 / 42 | 14% |
