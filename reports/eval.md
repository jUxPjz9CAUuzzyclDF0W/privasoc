# privasoc evaluation (2026-09-26)

Fixtures: Elastic integrations pipeline tests @ `354ff4c940`, first half of each file visible to the generator, second half held out for scoring. F1 is micro-averaged over extractable ECS fields.

| configuration | pass@1 | pass@k | F1 (all runs) | F1 (proposed) | held-out parsed | attempts | LLM s/run | ungrounded |
|---|---|---|---|---|---|---|---|---|
| hand-written (reference) · structured · pseudo on | 100% | 100% (k=1) | 0.87 | 0.87 | 91% | 1 | 0.0 | 0 |

Per fixture (proposed/runs, best F1):

| fixture | hand-written (reference) · structured · pseudo on |
|---|---|
| apache | 1/1, 0.83 |
| iptables | 1/1, 0.80 |
| nginx | 1/1, 0.91 |
| sshd_auth | 1/1, 0.95 |

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
