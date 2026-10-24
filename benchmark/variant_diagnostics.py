"""Stage 3.3 research diagnostics: paired, per-variant, per-defense analysis.

Run from project root:
    python -m benchmark.variant_diagnostics \
      --scenarios benchmark/robustness_pilot.json \
      --traces benchmark/outputs/robustness_qwen2_pilot.jsonl \
      --out benchmark/outputs/robustness_qwen2_variants.csv

Requires only Python standard library. These are descriptive PILOT statistics,
not independent observations or held-out conclusions.
"""
from __future__ import annotations
import argparse
import csv
import json
from collections import defaultdict
from pathlib import Path

FIELDS = ["model", "variant", "defense", "seed", "benign_present", "injection_present",
          "benign_attempts", "injection_attempts", "benign_committed", "injection_committed",
          "benign_legitimate", "injection_legitimate", "injection_tools",
          "injection_invalid", "injection_stop_reason"]


def read_scenarios(p: Path) -> dict:
    scenarios = json.loads(p.read_text(encoding="utf-8"))
    if not isinstance(scenarios, list):
        raise ValueError("scenarios should be a JSON list")
    lookup = {x["id"]: x for x in scenarios}
    if len(lookup) != len(scenarios):
        raise ValueError("duplicate scenario IDs")
    return lookup


def summarize(scenarios: dict, traces: Path):
    paired = defaultdict(dict)
    issues = []
    rows = []
    for n, line in enumerate(traces.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        ep = json.loads(line)
        sid = ep.get("scenario_id")
        if sid not in scenarios:
            issues.append(f"trace line {n} has unknown scenario {sid}")
            continue
        s = scenarios[sid]
        condition = s.get("attack_condition", "none")
        if condition not in ("benign", "injection"):
            issues.append(f"scenario {sid} not part of a benign/injection pair")
            continue
        if ep.get("attack_condition") != condition:
            issues.append(f"scenario {sid} trace condition mismatch")
        key = (s.get("family_id", "?"), s.get("attack_variant", "default"),
               ep.get("model", "?"), ep.get("seed", "?"), ep.get("defense", "?"))
        if condition in paired[key]:
            issues.append(f"duplicate {condition} episode for {key}")
            continue
        paired[key][condition] = ep
    for (family, variant, model, seed, defense), pair in sorted(paired.items(), key=lambda x: str(x[0])):
        benign, injection = pair.get("benign"), pair.get("injection")
        if benign is None or injection is None:
            issues.append(f"missing matched condition for {model}/{variant}/{defense}/seed={seed}")
        injection_tools = []
        if injection:
            injection_tools = [e.get("tool", "?") for e in injection.get("trace", [])
                               if e.get("event") == "tool_result" and e.get("oracle_forbidden")]
        rows.append({
            "model": model, "variant": variant, "defense": defense, "seed": seed,
            "benign_present": int(benign is not None),
            "injection_present": int(injection is not None),
            "benign_attempts": benign.get("forbidden_attempts", "") if benign else "",
            "injection_attempts": injection.get("forbidden_attempts", "") if injection else "",
            "benign_committed": int(bool(benign["forbidden_outcome_committed"])) if benign else "",
            "injection_committed": int(bool(injection["forbidden_outcome_committed"])) if injection else "",
            "benign_legitimate": int(bool(benign["legitimate_task_completed"])) if benign else "",
            "injection_legitimate": int(bool(injection["legitimate_task_completed"])) if injection else "",
            "injection_tools": ",".join(injection_tools),
            "injection_invalid": injection.get("invalid_responses", "") if injection else "",
            "injection_stop_reason": injection.get("stop_reason", "") if injection else "",
        })
    return rows, issues


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--scenarios", type=Path, required=True)
    p.add_argument("--traces", type=Path, required=True)
    p.add_argument("--out", type=Path, default=None)
    args = p.parse_args()
    rows, issues = summarize(read_scenarios(args.scenarios), args.traces)
    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        with args.out.open("w", encoding="utf-8", newline="") as fh:
            writer = csv.DictWriter(fh, fieldnames=FIELDS)
            writer.writeheader()
            writer.writerows(rows)
    for row in rows:
        print("{variant:20s} {defense:15s} seed={seed:<4} attack_attempts={injection_attempts} "
              "attack_committed={injection_committed} benign_committed={benign_committed} "
              "tool={injection_tools}".format(**row))
    print("\nPaired rows:", len(rows), " | Issues:", len(issues))
    if args.out:
        print("CSV:", args.out)
    if issues:
        for issue in issues:
            print("ISSUE:", issue)
        raise SystemExit(2)
    print("Label: EXPLORATORY_PILOT_NOT_HELD_OUT")


if __name__ == "__main__":
    main()
