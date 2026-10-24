"""Run controlled post-denial model episodes; records split and real/model identity.

Examples:
  python -m benchmark.run_experiment --backend replay
  python -m benchmark.run_experiment --backend ollama --models qwen2.5:3b --seeds 41 42
"""
from __future__ import annotations
import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
from .agent_loop import ReplayAgent, run_agent_episode
from .ollama_adapter import OllamaAgent, LocalModelError
from .sim import MODES, load_scenarios

ROOT = Path(__file__).resolve().parent


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Synthetic offline agent benchmark")
    parser.add_argument("--backend", choices=["replay", "ollama"], default="replay")
    parser.add_argument("--models", nargs="+", default=["qwen2.5:3b"])
    parser.add_argument("--scenarios", type=Path, default=ROOT / "pilot_scenarios.json")
    parser.add_argument("--seeds", type=int, nargs="+", default=[42])
    parser.add_argument("--modes", nargs="+", choices=MODES, default=list(MODES))
    parser.add_argument("--out", type=Path, default=None)
    parser.add_argument("--ollama-url", default="http://127.0.0.1:11434")
    parser.add_argument("--timeout", type=int, default=90)
    parser.add_argument("--max-scenarios", type=int, default=None)
    return parser


def main(argv: list[str] | None = None) -> None:
    args = argument_parser().parse_args(argv)
    if len(args.seeds) != len(set(args.seeds)):
        raise ValueError("seeds must be unique")
    cases = load_scenarios(str(args.scenarios))
    if args.max_scenarios is not None:
        if args.max_scenarios < 1:
            raise ValueError("max-scenarios must be positive")
        cases = cases[:args.max_scenarios]
    if not cases:
        raise ValueError("no scenarios")
    if args.backend == "replay":
        models = ["SCRIPTED_REPLAY_NOT_AN_LLM"]
        provenance = {models[0]: "no model — fixed actions"}
    else:
        models = args.models
        provenance = {}
        for model in models:
            agent = OllamaAgent(model, base_url=args.ollama_url, timeout=args.timeout)
            provenance[model] = agent.check_model()  # fail before emitting partial runs
    now = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    label = "ENGINEERING_REPLAY" if args.backend == "replay" else "LLM_PILOT_NOT_HELD_OUT"
    out = args.out or (ROOT / "outputs" / f"{label.lower()}_{now}.jsonl")
    out.parent.mkdir(parents=True, exist_ok=True)
    manifest = {
        "kind": label, "back_end": args.backend, "timestamp_utc": now,
        "scenarios_sha256": sha256(args.scenarios),
        "source_documents": list({json.dumps(c["source_document"], sort_keys=True) for c in cases
                                  if "source_document" in c}),
        "scenario_splits": sorted({c["scenario_split"] for c in cases}),
        "model_digests": provenance, "modes": args.modes, "seeds": args.seeds,
        "scenario_count": len(cases), "denial_step_zero": "imposed by evaluation, not an LLM decision",
        "policy_reference_note": "task_policy uses hidden trusted effect oracle; not a learned defense",
        "model_temperature": (0 if args.backend == "ollama" else None),
        "model_num_predict": (256 if args.backend == "ollama" else None),
        "runner_sha256": sha256(ROOT / "run_experiment.py"),
        "simulator_sha256": sha256(ROOT / "sim.py"),
        "agent_loop_sha256": sha256(ROOT / "agent_loop.py"),
        "source_builder_sha256": sha256(ROOT / "build_derived_cases.py"),
    }
    manifest["source_documents"] = [json.loads(x) for x in manifest["source_documents"]]
    if "runtime_guard" in args.modes:
        from .runtime_guard import RuntimeGuard
        guard = RuntimeGuard()
        manifest["runtime_policy_sha256"] = guard.policy_sha256
        manifest["runtime_guard_note"] = (
            "Application-configured effect enforcement, separate from scenario forbidden labels; "
            "prototype not a production validation or claim of novelty")
    rows = []
    for model in models:
        for s in cases:
            for seed in args.seeds:
                for mode in args.modes:
                    agent = (ReplayAgent(s["continuation_actions"]) if args.backend == "replay"
                             else OllamaAgent(model, base_url=args.ollama_url, timeout=args.timeout))
                    episode = run_agent_episode(s, mode, agent, seed=seed)
                    rows.append(episode.to_dict())
    with out.open("w", encoding="utf-8") as f:
        for row in rows:
            f.write(json.dumps(row, ensure_ascii=False) + "\n")
    manifest["run_count"] = len(rows)
    manifest_path = out.with_suffix(".manifest.json")
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"kind": label, "run_count": len(rows), "models": models,
                      "scenarios": len(cases), "out": str(out), "manifest": str(manifest_path)}, indent=2))
    if args.backend == "replay":
        print("WARNING: scripted engineering replay ONLY. No model evaluation has occurred.")
    else:
        print("LLM PILOT: experimental trajectories; do not treat pilot scenarios as held-out research results.")


if __name__ == "__main__":
    main()
