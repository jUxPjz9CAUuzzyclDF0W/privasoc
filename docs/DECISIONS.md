# privasoc: decision log

Living log of every design decision. Only what is written here is decided.
IDs are stable; superseded decisions are struck through and point to their replacement.
Framing sessions: 2026-09-26 (7 rounds). Previous Codex prototype (`soc-workbench`) is reference only and not reused.

## Goal

| ID | Decision |
|----|----------|
| D0 | Public GitHub portfolio project supporting an application for *Research Engineer, Cybersecurity RL* (Anthropic). Selection criteria: maximise AI-engineering learning, stay simple, stay reproducible by a reviewer. |
| D0b | **Privacy first.** A local LLM is the default. A remote API can be configured, but critical fields are always pseudonymised before any call. |

## Framing

| ID | Topic | Decision |
|----|-------|----------|
| D1 | Context | Homelab first, personal data only. Architecture must not prevent a later production (SOC/MSSP) use. |
| D2 | Input | Raw logs (syslog, files, Windows events, firewall...) that we parse and normalise ourselves. We do not start from pre-built alerts. |
| D3 | AI roles | ~~Initial priorities~~ revised by D19: 1. parser generation, 2. alert triage, 3. Sigma rule writing, 4. natural-language hunting. |
| D4 | Build vs assemble | Hybrid: the normalisation pipeline is ours (learning goal); storage and search reuse existing components. |
| D5 | Definition of done | 3 sources normalised, a detection fires, the AI produces a readable triage, end to end and demonstrable, plus a reproducible evaluation report. |
| D6 | Repository | New clean repository (`privasoc`). The old prototype stays untouched as reference. |

## Technical choices

| ID | Topic | Decision | Rationale |
|----|-------|----------|-----------|
| D7 | Data | Two tracks: **public labelled data** for evaluation and reproducibility; **live homelab data** for the demo, never committed. | Reviewers cannot replay personal logs; public data gives ground truth. |
| D8 | Schema | Elastic Common Schema (ECS). | Sigma mappings exist; LLMs know it well. |
| D9 | Normalisation | Vector + VRL, each parser covered by tests. AI-generated parsers are VRL too. | VRL is sandboxed: a generated parser cannot execute arbitrary code. Vector also handles collection. |
| D10 | Storage and detection | SQLite + Sigma rules compiled to SQL with `pySigma-backend-sqlite`. No OpenSearch. | No heavy infrastructure; SQL also serves NL hunting. |
| D11 | Runtime | Docker Compose, runnable on a laptop with sample data. Live: a Proxmox VM. LLM runs on the GPU workstation, reached over the LAN. | Reproducibility. |
| D12 | LLM providers | One OpenAI-compatible interface: local server by default, any remote API optional. Pseudonymisation is enforced in code for every provider. | Privacy (D0b). |
| D13 | Language | Python (uv, pydantic, FastAPI, Typer, pySigma). | Security and ML ecosystem. |

## Positioning

| ID | Topic | Decision |
|----|-------|----------|
| D14 | Showcase | Working AI SOC tool **plus an evaluation harness** (quality local vs API, latency, pseudonymisation leakage). No gym-style RL environment for now. |
| D15 | Pseudonymisation | Fields: IPs, hostnames, users, domains, emails, SIDs, user paths, free text (command lines, messages). Deterministic keyed-HMAC typed tokens; IPs mapped while preserving subnet and private/public class; local mapping table to re-identify LLM answers. Applied **always**, local LLM included. An automated test searches every outgoing prompt for original values. |
| D16 | Language | Repository in English, including this log. |
| D17 | Deadline | ~~1 week~~ superseded by D32. |
| D18 | Sources | Check Point and Pi-hole available at home. Guiding idea: when a log format is unknown, the AI helps parse and ingest it. |

## The core feature

| ID | Topic | Decision |
|----|-------|----------|
| D19 | Hero | **AI parser generation for unknown formats**: samples → pseudonymisation → LLM writes VRL emitting ECS → sandboxed run (`vector vrl`) → validation (ECS schema + fixtures) → error feedback → at most N attempts → human approval. Metrics: compile rate, per-field ECS F1, attempts, latency; local vs API; with vs without pseudonymisation. |
| D20 | Ground truth | Elastic integrations pipeline-test fixtures (raw lines + expected ECS), ~10 formats including Check Point. Downloaded at evaluation time, not redistributed. Few-shot on some lines, scored on held-out lines. |
| D21 | Check Point | Homelab device (no employer/customer data): usable live. |
| D22 | Scope | Originally cut for one week; superseded by D32 (full scope). |
| D23 | Human in the loop | A generated parser is activated only after explicit approval (diff + test results). |
| D24 | Interface | CLI (Typer) + web UI + static HTML evaluation report. |
| D25 | Sensitive-value detection | Typed regex detectors (IPv4/v6, email, MAC, FQDN, SID, user paths, URL) + key=value heuristics + **local LLM pass** for residual entities. Improves over time (D33). Tokens are **shape-preserving** (an IP stays a valid IP, an email an email). Residual leakage is measured and published. |
| D26 | Unknown format | Lines not matched by any approved parser go to a per-source **quarantine** (SQLite `unparsed`), clustered by template (Drain, D35). |
| D27 | LLM output | ~~A VRL program only~~ extended by D44. A VRL program only. K = 10 sample lines, N = 5 attempts, compiler error or field diff fed back on failure. |
| D28 | Models | **One small local model** with task-specific prompts. **API fallback** to any provider, always behind pseudonymisation. |
| D29 | Web UI | Parser review page (samples, VRL, tests, ECS output, approve/reject) **plus alerts and triage view**. |
| D30 | Sources | Source-agnostic: generic inputs (syslog, files). No device-specific assumption. |
| D31 | Name | `privasoc`. |

## Final arbitrations

| ID | Topic | Decision |
|----|-------|----------|
| D32 | Time | Time is not a constraint: ship fast **with every feature**, incrementally. |
| D33 | Learning pseudonymisation | Learn generalisable patterns (key names, regexes) plus a **local-only, git-ignored** value list. Each learned item is **human-approved** with a preview of its effect on the latest logs. |
| D34 | API fallback | Human action by default; automatic when configured (after N local failures) **or when the local model admits its limit or hallucinates** (D38). Every API call is logged (provider, size, number of pseudonymised tokens). |
| D35 | Drain | Drain groups log lines into templates (variable parts become `<*>`). Used for **stratified sampling** and a template-coverage metric. One parser per source. Library: `drain3`. |
| D36 | Local model | Reached through a **configurable URL** (OpenAI-compatible). Any server, any model. Default chosen by a mini-benchmark recorded here. |
| D37 | Licence and publishing | **MIT**. Public from the start; `gitleaks` in pre-commit and CI; `data/` and the vault git-ignored. |
| D38 | Hallucination / limits | (a) Self-report: JSON `status: ok \| cannot_parse \| unsure` + reason; (b) **grounding check**: every extracted value must appear in the raw line or derive from a known deterministic transform (timestamp, case, integer); (c) stagnation: same error class twice in a row. Ungrounded-value rate is an evaluation metric. |
| D39 | Build order | 1. Core (Vector → quarantine → SQLite, regex pseudonymisation, CLI). 2. Generation loop + sandbox + Drain + anti-hallucination + API fallback. 3. Parser evaluation + HTML report. 4. Review UI. 5. Local-LLM pseudonymisation + learning. 6. Sigma + alerts + triage + UI. 7. AI Sigma rules, then NL hunting. 8. Triage evaluation, then Windows and Proxmox collection. |
| D40 | Triage and rules | Structured JSON: verdict (`true_positive \| false_positive \| needs_investigation`), confidence, summary, ATT&CK techniques, investigation steps, suggested SQL. Re-identified only at display time. SigmaHQ rules auto-enabled when their `logsource` matches present data. |
| D41 | Access and secrets | UI on the LAN behind a single access token. Mapping vault in a separate file (mode 600), **encrypted at rest**; HMAC and encryption keys in `.env`. |
| D42 | Parser library | Approved parsers are indexed; the 2-3 nearest (Drain template similarity) are injected as examples. "Learning curve" evaluation: F1 and attempts versus library size. |
| D44 | Structured mode | After two real runs where `qwen3:8b` could not produce valid free-form VRL (syntax from other languages, `+=`, unassigned variables, a single regex for 7 line shapes), a second mode is added and made the default: the model answers with a YAML spec (prefix regex, timestamp, constants, and one regex + ECS mapping per line shape). privasoc validates it in Python (unsupported Rust-regex features, unknown groups, sample lines matching no shape) and compiles it to VRL with a deterministic, tested compiler; lines matching no shape abort and return to quarantine. Same sandbox, ECS and grounding checks afterwards. Free-form VRL stays available (`--mode vrl`), and the evaluation compares both modes: small model with structure versus free-form code. |
| D43 | Anonymity | The project is anonymous: no real name, personal handle or real homelab address anywhere (code, tests, docs, licence, git identity). Test data uses placeholders (`jdoe`, `laptop-01`, 192.168.1.0/24). Licence holder: "privasoc contributors". Commits use the GitHub no-reply identity. |

## Implementation notes
Decisions taken while building, same format.

| ID | Topic | Decision |
|----|-------|----------|
| I1 | Collector | Vector 0.55.0. `socket` sources (UDP/TCP 5514) with `codec: bytes` and a `file` inbox: raw lines are never pre-parsed. Source identity = `syslog:<sender>` or `file:<name>`. Delivery to the API through the `http` sink (NDJSON, bearer token, retries). |
| I2 | Pseudonym formats | user `user-xxxxxx`, keyed host `host-xxxxxx`; FQDN label-wise and suffix-consistent, TLD kept; email `uxxxxxx@<fqdn token>`; IPv4 private → 10/8, public → 198.18.0.0/15, /24 kept consistent; IPv6 → 2001:db8::/32, /64 kept consistent; MAC → locally administered `02:...`; SID domain part hashed, RID kept. Collisions resolved by a salt counter in the vault. |
| I3 | Propagation | A value detected once in a line is replaced everywhere in that line (catches free-text mentions of a keyed user). |
| I4 | Leak check | Word-boundary, case-insensitive search of every original in the outgoing text. The CLI refuses to print a line that still leaks. |
| I5 | Vault | SQLite, lookup by HMAC digest, originals encrypted with Fernet, file mode 600. |
| I6 | Sandbox | `vector vrl --print-object`, one process per line (runtime errors go to stderr without line alignment), empty environment, 20 s timeout, static denylist of host-reading functions (`get_env_var`, `get_hostname`, secrets, DNS). |
| I7 | Parser contract | The program receives `{message}` and assigns ECS fields on the root. At deployment it is wrapped: envelope saved, event reset (JSON round-trip so Vector's type checker sees an open object), `event.original` added, envelope rebuilt with `ecs` and `parser_id`. |
| I8 | Deployment | `vector/vector.yaml` = sources; `vector/pipeline.yaml` generated from approved parsers (route by source, one remap per parser, `drop_on_error` + `reroute_dropped` so failures return to quarantine). Every approval is checked with `vector validate`; a config Vector cannot load is rolled back. Vector runs with `--watch-config`. |
| I9 | Loop checks | In order: JSON answer, self-reported status (D38a), compile, runtime on every sample line, ECS validation (field sets, enumerations, IP and port types), grounding (D38b). Stagnation = same failure class twice in a row (D38c). A proposal is then re-run locally on the *real* lines (`real_lines_ok`) to prove that shape-preserving pseudonyms did not mislead the parser. |
| I10 | Leak guard | `LLMClient.chat` refuses to send any message containing an original value, whatever the provider. Only sizes, latency and token counts of calls are logged, never content. |
| I12 | First real run | On a consumer GPU the first run looked stuck. Fixes: live progress per attempt; preflight checks (Vector binary, LLM server, model name) before any LLM time; reasoning mode off by default for the local model (`/no_think` soft switch, `PRIVASOC_LLM_LOCAL_THINK`); only the latest attempt kept in context, since small local models have small windows. `init` now adds settings introduced after the `.env` was created. |
| I13 | Answer format | First real run with `qwen3:8b`: 3 of 5 attempts lost to invalid JSON, because VRL regexes (`\d`, `\S`) break JSON string escaping. Code is no longer requested inside JSON: the model answers `STATUS:` / `REASON:` lines plus a fenced ```` ```vrl ```` block (JSON still accepted). Truncated answers (`finish_reason=length`) get specific feedback. Prompt states that VRL has no methods (`split(x, ":")`, not `x.split(":")`), the second observed error. Sandbox output decoded as UTF-8 (Windows defaulted to cp1252, garbling compiler errors fed back to the model). |
| I14 | Second real run | (1) Answers still truncated at 2048 tokens: `/no_think` alone does not disable Qwen3 reasoning on Ollama's `/v1`; the local client now also sends `reasoning_effort: "none"` (retried without it if a server rejects the field). (2) **Residual leak found on real Pi-hole v6 logs**: hostnames under a private TLD (`*.lab`) were not detected and reached the (local) model. Any lowercase multi-label name is now an FQDN candidate; path components and code namespaces are excluded. Regression test added. (3) The model twice used a variable without assigning it: feedback now carries hints per VRL error code and the numbered program; the system prompt has a complete worked example that is itself tested. (4) Stagnation now means the *same* error (codes or fields) twice, not just the same class. |
| I15 | Deterministic repairs | In structured mode the model repeated invalid categorisation values (`event.type: dns`, `event.outcome: blocked`) despite precise feedback. Such values are now removed automatically, never invented, and every repair is reported to the model and shown to the reviewer (`auto_repairs` metric). A prefix that swallows what the shapes expect gets a targeted hint (the shapes would match if the prefix kept only the timestamp). |
| I16 | Repairs and partial parsers | Replaying the three real structured runs of `qwen3:8b` showed the shapes were right every time and the failures came from the prefix and mappings. Deterministic, value-free repairs now apply before validation: unnamed prefix groups are named, the timestamp group is found by trying the stated format on each prefix group, a prefix that swallows what the shapes expect is cut back to the timestamp, mappings to missing groups or non-ECS fields are dropped, and constants outside categorisation fields (invented values such as `network.transport: udp`) are dropped. Each repair is reported. A spec that covers at least `PRIVASOC_MIN_COVERAGE` (0.8) of up to 500 real lines, measured locally, can be proposed as partial; unmatched lines keep going to quarantine. Retries raise the temperature (0.2 → 0.8) so the model does not resend the same answer. Result on the recorded real answers: 3 runs out of 3 that previously failed now give 1 full parser (100 % of recent lines, 0 ungrounded values) and 1 partial (89 %), the third still stagnates. |
| I17 | First real parser | `qwen3:8b`, structured mode, real Pi-hole v6 logs: proposal after 3 attempts, 28.5 s of LLM time, 6 automatic repairs, 10/10 sample lines parsed, 0 ungrounded values, 100 % of recent real lines covered. Human review then caught what automated checks did not: `dns.resolved_ip` received non-IP answers (`NODATA-IPv6`), and blocked/local answers were mapped to `destination.ip`. Fix: the compiler only assigns IP fields when the value is an IPv4/IPv6 (`is_ipv4`/`is_ipv6`), and `dns.resolved_ip` joins the validated IP fields. Semantic choices (which ECS field) remain the reviewer's job, which is the point of D23. |
| I18 | Held-out coverage | A real proposal passed 10/10 sample lines yet missed `cached x is NODATA-IPv6` on 25 % of recent lines: the value differs but the Drain template is the same, so stratified sampling cannot see it. A structured spec that passes the sample is now checked on up to 500 real lines of the source (local Python dry run). Up to five unmatched lines, chosen across templates and pseudonymised first (their originals join the leak check), are fed back as a `coverage` failure; the best spec above `PRIVASOC_MIN_COVERAGE` stays a partial candidate. The prompt also gives one-line meanings for the key ECS fields (e.g. `dns.resolved_ip` = IPs in a DNS answer), after two real runs put DNS answers in `destination.ip`. |
| I19 | Held-out feedback works | Next real run (`qwen3:8b`, structured): 5 attempts, 48.7 s of LLM time. After the held-out coverage feedback, the model added two shapes it had never seen in its sample (`cached x is NODATA-IPv6`, `special domain x is NXDOMAIN`) and mapped DNS answers to `dns.resolved_ip` and query types to `dns.question.type`. Result: partial parser covering 94 % of 500 real lines and 100 % of recent ones, 0 ungrounded values, 9 automatic repairs. Remaining gaps are visible to the reviewer (a malformed YAML mapping dropped `dns.resolved_ip` for `cached-stale`; `cached x is <IP>` still unmatched). |
| I11 | Local model | The benchmark (D36) could not run from the build environment (LAN blocked); it runs on the user's machine. First candidate: `qwen3:8b` via Ollama. |

## Dropped (from the Codex prototype)
- "Firewall/EDR alerts only, no raw logs": replaced by D2.
- Hand-written SIEM in Node.js + PostgreSQL: replaced by D4/D10.
- Sizing for 400 customers / 1M alerts per day: out of scope (D1).
