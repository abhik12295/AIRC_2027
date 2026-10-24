"""Run deterministic pilot fixture tests. Usage: python -m benchmark.run_pilot."""
from __future__ import annotations
from dataclasses import asdict
import json
from pathlib import Path
from .sim import MODES, load_scenarios, run, summarize


def main() -> None:
    root = Path(__file__).resolve().parent
    scenarios = load_scenarios(str(root / "pilot_scenarios.json"))
    runs = [run(s, mode) for mode in MODES for s in scenarios]
    outputs = root / "outputs"
    outputs.mkdir(exist_ok=True)
    metadata = {"kind": "scripted_fixture_validation_not_llm_evaluation", "n_scenarios": len(scenarios),
                "n_runs": len(runs), "tool_execution": "in-memory mock only", "models_evaluated": 0}
    report = {"metadata": metadata, "validation_counts": summarize(runs)}
    (outputs / "pilot_report.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    (outputs / "pilot_traces.jsonl").write_text(
        "".join(json.dumps(asdict(run_result)) + "\n" for run_result in runs), encoding="utf-8")
    print(json.dumps(report, indent=2))
    print(f"Wrote: {outputs / 'pilot_report.json'}")
    print(f"Wrote: {outputs / 'pilot_traces.jsonl'}")


if __name__ == "__main__":
    main()
