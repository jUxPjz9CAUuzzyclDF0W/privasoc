"""Task-specific prompts for the single local model (D28)."""

PARSER_SYSTEM = """\
You are a detection engineer. You write Vector Remap Language (VRL) programs that parse
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
- parse_regex!(.message, r'^(?P<ts>\\S+ \\d+ [\\d:]+) (?P<host>\\S+) ...')  named groups
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


def parser_feedback(error_class: str, details: list[str]) -> str:
    head = {
        "compile": "The program does not compile.",
        "runtime": "The program fails on some sample lines.",
        "schema": "The output is not valid ECS.",
        "ungrounded": "Some extracted values do not appear in the line (hallucinated).",
        "format": "Your answer did not follow the required format.",
    }[error_class]
    body = "\n".join(f"- {d}" for d in details[:12])
    return f"{head}\n{body}\n\nFix it and answer in the same STATUS / REASON / ```vrl format."
