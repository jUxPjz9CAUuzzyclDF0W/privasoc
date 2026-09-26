"""Task-specific prompts for the single local model (D28)."""

PARSER_SYSTEM = r"""You are a detection engineer. You write Vector Remap Language (VRL) programs that parse
ONE raw log line into Elastic Common Schema (ECS).

Contract
- The input event has a single field `.message` containing the raw line.
- Assign ECS fields on the event root, e.g. `.source.ip = parsed.src`.
- Keep `.message`. Do not add fields that are not ECS; put vendor-specific data under `.labels`.
- Only extract values that literally appear in the line. Never invent values.
  Categorisation fields (event.kind/category/type/outcome) are the only chosen constants.
- Values such as IPs, hostnames (e.g. d1a2b3c.lan), users (e.g. user-1a2b3c) and emails are
  pseudonymised placeholders: treat them as real values of their type.
- The program must work for every sample line. Use fallible functions with `!`, and
  `if` / `??` for optional parts.

Useful VRL
- parse_regex!(.message, r'^(?P<ts>\S+ \d+ [\d:]+) (?P<host>\S+) ...')  named groups
- parse_key_value!(.message, key_value_delimiter: "=", field_delimiter: " ")
- parse_syslog!(.message), parse_json!(.message), parse_csv!(.message)
- parse_timestamp!(value, format: "%Y-%m-%dT%H:%M:%S%z") ; to_int!(value) ; downcase(value)
- Syslog dates have no year: prepend it, e.g.
  parse_timestamp!(format_timestamp!(now(), format: "%Y") + " " + p.ts, format: "%Y %b %d %H:%M:%S")
- Epoch seconds: from_unix_timestamp!(to_int!(p.time))
- exists(x.field) ; x = parsed.field ?? null ; string!(value)

Useful ECS fields
@timestamp, event.kind, event.category (array), event.type (array), event.outcome,
event.action, source.ip, source.port, destination.ip, destination.port, network.transport,
network.protocol, user.name, host.name, host.hostname, process.name, process.pid,
dns.question.name, dns.question.type, dns.answers, observer.vendor, observer.product,
log.level, rule.name, url.original, http.request.method, http.response.status_code

VRL is not Python or JavaScript: there are no methods. Write split(value, "x"), not
value.split("x"); index arrays with value[0]; strings use double quotes, regexes r'...'.

Complete example (another format, for the structure only):
line: Sep 26 10:01:02 srv sshd[812]: Failed password for user-1a2b3c from 10.1.2.3 port 5122 ssh2
STATUS: ok
REASON: sshd authentication line
```vrl
p = parse_regex!(.message, r'^(?P<ts>\w{3} +\d+ [\d:]+) (?P<host>\S+) (?P<proc>\w+)\[(?P<pid>\d+)\]: (?P<msg>.*)$')
.@timestamp = parse_timestamp!(format_timestamp!(now(), format: "%Y") + " " + p.ts, format: "%Y %b %d %H:%M:%S")
.host.hostname = p.host
.process.name = p.proc
.process.pid = to_int!(p.pid)
.event.kind = "event"
a = parse_regex(p.msg, r'^(?P<result>Failed|Accepted) password for (?P<user>\S+) from (?P<ip>\S+) port (?P<port>\d+)') ?? {}
if exists(a.user) {
  .event.category = ["authentication"]
  .event.outcome = if a.result == "Accepted" { "success" } else { "failure" }
  .user.name = a.user
  .source.ip = a.ip
  .source.port = to_int!(a.port)
}
```
Note: the result of parse_regex! is assigned to a variable (p = ...) before p.x is used.

Answer in exactly this format, nothing else:
STATUS: ok | cannot_parse | unsure
REASON: <one sentence>
```vrl
<program>
```
Use cannot_parse or unsure honestly when the format is beyond you.
"""


def parser_user(
    source: str, samples: list[str], templates: list[str], examples: list[dict] | None = None
) -> str:
    parts = [f"Source: {source}", "", "Line templates found (Drain, <*> = variable):"]
    parts += [f"- {t}" for t in templates[:15]]
    if examples:
        parts += ["", "Approved parsers for similar formats (for reference):"]
        for ex in examples:
            parts += [f"# sample: {ex['sample']}", ex["vrl"], ""]
    parts += ["", "Sample lines:"]
    parts += [f"{i + 1}. {s}" for i, s in enumerate(samples)]
    parts += ["", "Write the VRL program."]
    return "\n".join(parts)


VRL_HINTS = {
    "E701": "A variable is used before being assigned. Assign first, e.g. "
    "`p = parse_regex!(.message, r'...')`, then use p.field.",
    "E103": "A fallible call is not handled: add `!` (abort on error) or `?? default`.",
    "E620": "`!` is used on an infallible function: remove the `!`.",
    "E651": "`??` is used on an expression that cannot fail: remove the `?? ...` part.",
    "E110": "A condition can fail: use a `!` function or `?? false` inside the `if`.",
    "E105": 'Unknown function: VRL has no methods; use functions like split(x, ",").',
    "E204": "Syntax error: check brackets, quotes and that regexes use r'...'.",
}


def parser_feedback(error_class: str, details: list[str], program: str | None = None) -> str:
    head = {
        "compile": "The program does not compile.",
        "runtime": "The program fails on some sample lines.",
        "schema": "The output is not valid ECS.",
        "ungrounded": "Some extracted values do not appear in the line (hallucinated).",
        "format": "Your answer did not follow the required format.",
    }[error_class]
    body = "\n".join(f"- {d}" for d in details[:12])
    import re

    codes = sorted(set(re.findall(r"\bE\d{3}\b", " ".join(details))))
    hints = [VRL_HINTS[c] for c in codes if c in VRL_HINTS]
    parts = [head, body]
    if hints:
        parts.append("Hint: " + " ".join(hints))
    if program and error_class in {"compile", "runtime"}:
        numbered = "\n".join(f"{i:3} | {ln}" for i, ln in enumerate(program.splitlines(), 1))
        parts.append("Your program, with line numbers:\n" + numbered)
    parts.append("Fix it and answer in the same STATUS / REASON / ```vrl format.")
    return "\n\n".join(parts)
