"""Turn evaluation results into a Markdown summary and a static HTML report."""

from __future__ import annotations

import html
from collections import defaultdict
from datetime import UTC, datetime
from statistics import mean

CONFIG = ("mode", "provider", "model", "pseudo")


def _cfg_name(c: tuple) -> str:
    mode, provider, model, pseudo = c
    return f"{model} ({provider}) · {mode} · pseudo {'on' if pseudo else 'off'}"


def summarise(results: list[dict]) -> dict:
    by_cfg: dict[tuple, list[dict]] = defaultdict(list)
    for r in results:
        by_cfg[tuple(r[k] for k in CONFIG)].append(r)
    configs = []
    for cfg, rs in sorted(by_cfg.items(), key=lambda kv: str(kv[0])):
        ok = [r for r in rs if r["status"] == "proposed"]
        per_fx: dict[str, list[dict]] = defaultdict(list)
        for r in rs:
            per_fx[r["fixture"]].append(r)
        configs.append(
            {
                "name": _cfg_name(cfg),
                "runs": len(rs),
                "fixtures": len(per_fx),
                "k": max(len(v) for v in per_fx.values()),
                "pass_at_1": round(len(ok) / len(rs), 3),
                "pass_at_k": round(
                    mean(any(x["status"] == "proposed" for x in v) for v in per_fx.values()), 3
                ),
                "f1": round(mean(r["f1"] for r in rs), 3),
                "f1_when_proposed": round(mean(r["f1"] for r in ok), 3) if ok else 0.0,
                "heldout_parsed": round(mean(r["heldout_parsed"] for r in rs), 3),
                "attempts": round(mean(r["attempts"] for r in rs), 2),
                "llm_latency_s": round(mean(r["llm_latency_s"] for r in rs), 1),
                "ungrounded_values": sum(r["ungrounded_values"] for r in ok),
                "per_fixture": {
                    fx: {
                        "proposed": sum(x["status"] == "proposed" for x in v),
                        "runs": len(v),
                        "best_f1": max(x["f1"] for x in v),
                    }
                    for fx, v in sorted(per_fx.items())
                },
            }
        )
    return {"configs": configs}


def markdown(summary: dict, leak: dict | None, meta: dict) -> str:
    lines = [f"# privasoc evaluation ({meta.get('date')})", ""]
    lines += [
        f"Fixtures: Elastic integrations pipeline tests @ `{meta.get('sha', '')[:10]}`, "
        "first half of each file visible to the generator, second half held out for "
        "scoring. F1 is micro-averaged over extractable ECS fields.",
        "",
    ]
    lines += [
        "| configuration | pass@1 | pass@k | F1 (all runs) | F1 (proposed) | "
        "held-out parsed | attempts | LLM s/run | ungrounded |",
        "|---|---|---|---|---|---|---|---|---|",
    ]
    for c in summary["configs"]:
        lines.append(
            f"| {c['name']} | {c['pass_at_1']:.0%} | {c['pass_at_k']:.0%} (k={c['k']}) | "
            f"{c['f1']:.2f} | {c['f1_when_proposed']:.2f} | {c['heldout_parsed']:.0%} | "
            f"{c['attempts']} | {c['llm_latency_s']} | {c['ungrounded_values']} |"
        )
    if summary["configs"]:
        fxs = sorted({f for c in summary["configs"] for f in c["per_fixture"]})
        lines += [
            "",
            "Per fixture (proposed/runs, best F1):",
            "",
            "| fixture | " + " | ".join(c["name"] for c in summary["configs"]) + " |",
            "|---|" + "---|" * len(summary["configs"]),
        ]
        for fx in fxs:
            cells = []
            for c in summary["configs"]:
                p = c["per_fixture"].get(fx)
                cells.append(f"{p['proposed']}/{p['runs']}, {p['best_f1']:.2f}" if p else "")
            lines.append(f"| {fx} | " + " | ".join(cells) + " |")
    if leak:
        lines += [
            "",
            "## Pseudonymisation leakage",
            "",
            f"{leak['leaked']} of {leak['values']} known-sensitive values survived "
            f"(**{leak['leak_rate']:.1%}**), measured on the raw fixture lines against "
            "the values Elastic's pipeline extracts.",
            "",
            "| field | leaked / total | rate |",
            "|---|---|---|",
        ]
        for f, v in leak["per_field"].items():
            lines.append(f"| {f} | {v['leaked']} / {v['total']} | {v['rate']:.0%} |")
    return "\n".join(lines) + "\n"


def to_html(md_text: str, title: str = "privasoc evaluation") -> str:
    """Minimal Markdown (headings, tables, paragraphs) to a self-contained HTML page."""
    out, in_table = [], False
    for line in md_text.splitlines():
        if line.startswith("|"):
            cells = [html.escape(c.strip()) for c in line.strip("|").split("|")]
            if set("".join(cells)) <= set("-: "):
                continue
            tag = "th" if not in_table else "td"
            if not in_table:
                out.append("<table>")
                in_table = True
            out.append("<tr>" + "".join(f"<{tag}>{c}</{tag}>" for c in cells) + "</tr>")
            continue
        if in_table:
            out.append("</table>")
            in_table = False
        if line.startswith("## "):
            out.append(f"<h2>{html.escape(line[3:])}</h2>")
        elif line.startswith("# "):
            out.append(f"<h1>{html.escape(line[2:])}</h1>")
        elif line.strip():
            text = html.escape(line)
            text = text.replace("**", "")
            out.append(f"<p>{text}</p>")
    if in_table:
        out.append("</table>")
    css = (
        "body{font:15px/1.5 system-ui,sans-serif;max-width:1100px;margin:2rem auto;"
        "padding:0 1rem;color:#1b1b1b;background:#fff}table{border-collapse:collapse;"
        "margin:1rem 0;font-size:13px}th,td{border:1px solid #ddd;padding:4px 8px;"
        "text-align:left}th{background:#f4f4f4}@media(prefers-color-scheme:dark){body"
        "{background:#141414;color:#e8e8e8}th{background:#262626}th,td{border-color:#333}}"
    )
    return (
        f"<!doctype html><html><head><meta charset='utf-8'><meta name='viewport' "
        f"content='width=device-width,initial-scale=1'><title>{html.escape(title)}</title>"
        f"<style>{css}</style></head><body>{''.join(out)}</body></html>\n"
    )


def meta(sha: str) -> dict:
    return {"date": datetime.now(UTC).strftime("%Y-%m-%d"), "sha": sha}
