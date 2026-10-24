"""Read-only diagnostic for Stage 5.2 LLM traces (pilot, not held-out evidence).

Shows actual derivation chains, attempted releases, denied actions, and invalid
model replies. It never modifies the existing trace or scenario files.
"""
from __future__ import annotations

import argparse
from collections import Counter
from hashlib import sha256
import json
from pathlib import Path

RELEASE_TOOLS = {"pages.publish", "drive.share", "email.send"}


def load_jsonl(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def longest_path(ancestor: dict[str, str], doc: str, root: str) -> int | None:
    hops, visited = 0, set()
    while doc != root:
        if doc in visited or doc not in ancestor:
            return None
        visited.add(doc)
        doc = ancestor[doc]
        hops += 1
    return hops


def triage(scenarios: list[dict], episodes: list[dict], source_hash: str) -> dict:
    smap = {s["id"]: s for s in scenarios}
    if len(smap) != len(scenarios):
        raise ValueError("Duplicate scenario IDs")
    out = []
    seen = set()
    for e in episodes:
        sid = e["scenario_id"]
        if sid not in smap:
            raise ValueError(f"Trace references unknown scenario {sid}")
        key = (sid, e.get("defense"), e.get("model"), e.get("seed"))
        if key in seen:
            raise ValueError(f"Repeated episode {key}")
        seen.add(key)
        s = smap[sid]
        root = s["legitimate_success_predicate"]["doc"]
        lineage = {}
        events = []
        invalid = []
        summaries = []
        release = []
        for record in e.get("trace", []):
            kind = record.get("event")
            if kind == "invalid_response":
                invalid.append({
                    "step": record.get("step"),
                    "detail": record.get("detail", ""),
                    "raw_preview": str(record.get("raw", ""))[:170],
                })
            if kind == "tool_validation_error":
                events.append({"step": record.get("step"), "type": "tool_validation_error",
                               "tool": record.get("tool"), "detail": record.get("detail")})
            if kind != "tool_result":
                continue
            args = record.get("args") or {}
            item = {
                "step": record.get("step"), "type": "tool_result", "tool": record.get("tool"),
                "doc": args.get("doc"), "new_doc": args.get("new_doc"),
                "destination": args.get("destination"), "response_code": record.get("response_code"),
                "committed": record.get("effect_committed"),
                "forbidden_attempt": bool(record.get("oracle_forbidden")),
                "valid_action": bool(record.get("valid_action")),
            }
            if record.get("guard_reason") is not None:
                item["guard_reason"] = record["guard_reason"]
            events.append(item)
            if record.get("tool") == "documents.derive" and record.get("response_code") == "OK" and record.get("effect_committed"):
                lineage[str(args.get("new_doc"))] = str(args.get("doc"))
            if record.get("tool") == "summary.save_text_internal" and record.get("response_code") == "OK":
                summaries.append({"doc": args.get("doc"), "length_words": len(str(args.get("summary", "")).split())})
            if record.get("tool") in RELEASE_TOOLS:
                release.append(item)
        paths = {doc: longest_path(lineage, doc, root) for doc in lineage}
        out.append({
            "scenario_id": sid, "variant": s.get("attack_variant"),
            "condition": s.get("attack_condition"), "defense": e.get("defense"),
            "model": e.get("model"), "seed": e.get("seed"),
            "root_source": root,
            "derivation_parent_map": lineage, "derivation_hops_from_source": paths,
            "two_hop_created": any(x is not None and x >= 2 for x in paths.values()),
            "releases": release, "saved_summaries": summaries,
            "forbidden_attempt_count": e.get("forbidden_attempts"),
            "forbidden_committed": bool(e.get("forbidden_outcome_committed")),
            "legitimate_completed": bool(e.get("legitimate_task_completed")),
            "invalid_responses_reported": e.get("invalid_responses"),
            "invalid_responses_logged": len(invalid),
            "invalid_detail_counts": dict(Counter(x["detail"] for x in invalid)),
            "invalid_previews_first_three": invalid[:3],
            "stop_reason": e.get("stop_reason"),
            "tool_timeline": events,
        })
    return {"label": "STAGE5_2_READ_ONLY_DIAGNOSTIC_NOT_HELD_OUT",
            "trace_sha256": source_hash, "episodes": len(out),
            "totals": {"two_hop_episodes": sum(x["two_hop_created"] for x in out),
                       "invalid_responses": sum(x["invalid_responses_logged"] for x in out),
                       "forbidden_attempts": sum(x["forbidden_attempt_count"] or 0 for x in out),
                       "forbidden_commits": sum(x["forbidden_committed"] for x in out)},
            "details": out}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--scenarios", type=Path, required=True)
    parser.add_argument("--traces", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    opts = parser.parse_args()
    raw = opts.traces.read_bytes()
    report = triage(json.loads(opts.scenarios.read_text(encoding="utf-8")), load_jsonl(opts.traces), sha256(raw).hexdigest())
    opts.out.parent.mkdir(parents=True, exist_ok=True)
    opts.out.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    for ep in report["details"]:
        releases = ",".join(f"{r['tool']}:{r['doc']}:{r['response_code']}" for r in ep["releases"]) or "none"
        print(f"{ep['variant']:26} {ep['condition']:9} {ep['defense']:14} "
              f"hops={max((v for v in ep['derivation_hops_from_source'].values() if v is not None), default=0)} "
              f"invalid={ep['invalid_responses_logged']} "
              f"legit={int(ep['legitimate_completed'])} releases={releases}")
    print("TOTALS", json.dumps(report["totals"], sort_keys=True))
    print("Report:", opts.out)


if __name__ == "__main__":
    main()
