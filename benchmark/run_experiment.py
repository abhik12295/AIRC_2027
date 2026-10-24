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
    parser.add_argument("--temperature", type=float, default=0.0,
                        help="Ollama sampling temperature (default preserves historic settings)")
    parser.add_argument("--num-predict", type=int, default=256,
                        help="Maximum generated tokens per agent response")
    parser.add_argument("--frozen-protocol", type=Path,
                        help="Required for evaluation-split runs; checks prerecord design and SHA fingerprints")
    parser.add_argument("--max-scenarios", type=int, default=None)
    return parser


def main(argv: list[str] | None = None) -> None:
    args = argument_parser().parse_args(argv)
    if not 0 <= args.temperature <= 2:
        raise ValueError("temperature must be between 0 and 2")
    if not 64 <= args.num_predict <= 4096:
        raise ValueError("num-predict must be between 64 and 4096")
    if len(args.seeds) != len(set(args.seeds)):
        raise ValueError("seeds must be unique")
    cases = load_scenarios(str(args.scenarios))
    if args.max_scenarios is not None:
        if args.max_scenarios < 1:
            raise ValueError("max-scenarios must be positive")
        cases = cases[:args.max_scenarios]
    if not cases:
        raise ValueError("no scenarios")
    if any(c["scenario_split"] == "evaluation" for c in cases) and args.frozen_protocol is None:
        raise ValueError("evaluation scenarios require --frozen-protocol to prevent unfrozen runs")
    if args.backend == "replay":
        models = ["SCRIPTED_REPLAY_NOT_AN_LLM"]
        provenance = {models[0]: "no model — fixed actions"}
    else:
        models = args.models
        provenance = {}
        for model in models:
            agent = OllamaAgent(model, base_url=args.ollama_url, timeout=args.timeout,
                                temperature=args.temperature, num_predict=args.num_predict)
            provenance[model] = agent.check_model()  # fail before emitting partial runs
    now = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    is_evaluation = {c["scenario_split"] for c in cases} == {"evaluation"}
    label = ("ENGINEERING_REPLAY" if args.backend == "replay"
             else "LLM_EVALUATION_PROJECT_FROZEN_NOT_EXTERNALLY_REGISTERED" if is_evaluation
             else "LLM_PILOT_NOT_HELD_OUT")
    if args.frozen_protocol is not None:
        protocol = json.loads(args.frozen_protocol.read_text(encoding="utf-8"))
        if protocol.get("status") != "PROJECT_FROZEN_NOT_EXTERNALLY_PREREGISTERED":
            raise ValueError("Protocol is not a project-frozen evaluation lock")
        expected_files = protocol["code_sha256"]
        for f, expected in expected_files.items():
            path = ROOT.parent / f
            if not path.is_file() or sha256(path) != expected:
                raise ValueError(f"Frozen protocol code fingerprint mismatch: {f}")
        if protocol["scenario_sha256"] != sha256(args.scenarios):
            raise ValueError("Frozen protocol scenario fingerprint mismatch")
        if set(protocol["models"]) != set(models) or set(protocol["modes"]) != set(args.modes):
            raise ValueError("Frozen protocol models or modes mismatch")
        if protocol["seeds"] != args.seeds:
            raise ValueError("Frozen protocol seed list mismatch")
        if protocol["sampling"] != {"temperature": args.temperature, "num_predict": args.num_predict}:
            raise ValueError("Frozen protocol sampling settings mismatch")
        if protocol["model_digests"] != provenance:
            raise ValueError("Frozen protocol Ollama model digest mismatch")
        if len(cases) != protocol["scenario_count"] or args.max_scenarios is not None:
            raise ValueError("Frozen protocol requires the full scenario set")
    elif is_evaluation:
        raise ValueError("Cannot run evaluation without frozen protocol")
    out = args.out or (ROOT / "outputs" / f"{label.lower()}_{now}.jsonl")
    if is_evaluation and (out.exists() or out.with_suffix(".manifest.json").exists()):
        raise ValueError("Frozen evaluation output already exists; refuse overwrite of research evidence")
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
        "model_temperature": (args.temperature if args.backend == "ollama" else None),
        "model_num_predict": (args.num_predict if args.backend == "ollama" else None),
        "seed_applied_to_each_model_turn": args.backend == "ollama",
        "ollama_adapter_sha256": sha256(ROOT / "ollama_adapter.py"),
        "frozen_protocol_sha256": sha256(args.frozen_protocol) if args.frozen_protocol else None,
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
                             else OllamaAgent(model, base_url=args.ollama_url, timeout=args.timeout,
                                              temperature=args.temperature, num_predict=args.num_predict))
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
        print("PROJECT-FROZEN EVALUATION; not externally preregistered." if is_evaluation else
              "LLM PILOT: experimental trajectories; do not treat pilot scenarios as held-out research results.")


if __name__ == "__main__":
    main()
