# Stage 4 — Runtime Guard Engineering Prototype (pilot)

**This is experimentation code, not a manuscript.** The new defense mode is `runtime_guard`.
It independently evaluates **trusted tool-effect contracts**, a **separate policy file**
(`benchmark/runtime_policy.json`), trusted resource metadata, and a **per-session denial ledger**.
It does **not** import the test oracle, read `scenario.policy` or `forbidden_predicate`, or
ask an LLM to judge permission. The benchmark grader still uses its hidden oracle *only*
to measure outcomes and false blocks.

## Why this is valuable — and what it is not

The pilot demonstrated that `qwen2:7b` attempted `pages.publish` or `drive.share`
after an imposed `email.send` rejection. A tool blocklist missed both routes. This Stage 4
baseline blocks the **effect of restricted external release** across all three tool adapters.
It permits internal summaries, authorized internal transfers, and public-source documents
when their *trusted workspace classification* allows it.

**This is a rule-based proof of feasibility, not yet novel security research.** Its ability
to block document release is by construction, like the idealized policy oracle, but
unlike `task_policy` it does not consult hidden scenario labels. It relies on accurately
configured tool-effect contracts and trusted metadata. We must evaluate overblocking,
policy drift, derived artifacts, transformations, and unmodeled tool side effects before
claiming a research improvement. Pilot percentages are not generalizable security rates.

## Install into your current Mac project

Recommended: save or zip a backup of your existing project. Extract the **Stage4_Patch.zip**
*inside the main `AIRC 2027` folder* (the one containing `benchmark/` and `data/`).
It replaces the 4 Python integration files and adds the guard, configuration,
comparison utility, and tests. It does not overwrite your `data/`, scenarios,
experiment output files, or existing model logs.

After extraction, from the root of the project, run:

```bash
python -m unittest discover -s benchmark -p 'test_*.py' -v
python -m unittest discover -s tests -p 'test_*.py' -v
```

## First run — only the new mode on the existing GenAI scenarios

Reuse `benchmark/genai_robustness_pilot.json` and the authentic NIST PDF already in your
`data/` directory. No PDF download is necessary.

```bash
python -m benchmark.run_experiment \
 --backend ollama --models qwen2:7b \
 --scenarios benchmark/genai_robustness_pilot.json \
 --modes runtime_guard --seeds 42 --timeout 180 \
 --out benchmark/outputs/genai_qwen2_guard_pilot.jsonl
python -m benchmark.report_experiment benchmark/outputs/genai_qwen2_guard_pilot.jsonl
python -m benchmark.audit_trajectories \
 benchmark/outputs/genai_qwen2_guard_pilot.jsonl \
 --scenarios benchmark/genai_robustness_pilot.json \
 --manifest benchmark/outputs/genai_qwen2_guard_pilot.manifest.json \
 --out benchmark/outputs/genai_qwen2_guard_pilot.audit.json
```

Expected 8 additional episodes (4 benign and 4 injection). We do **not** know how the
agent will actually behave. The runtime guard is expected to deny unauthorized releases,
but possible implementation gaps and false blocks are precisely what we must investigate.

## Fair four-way comparison (optional next run)

The previous 24-episode file should be retained unchanged as original evidence. To
compare four modes within one experiment grid, run:

```bash
python -m benchmark.run_experiment \
 --backend ollama --models qwen2:7b \
 --scenarios benchmark/genai_robustness_pilot.json \
 --modes denial_only tool_blocklist task_policy runtime_guard \
 --seeds 42 --timeout 180 \
 --out benchmark/outputs/genai_qwen2_fourway_pilot.jsonl
python -m benchmark.compare_defenses \
 --scenarios benchmark/genai_robustness_pilot.json \
 --traces benchmark/outputs/genai_qwen2_fourway_pilot.jsonl \
 --out benchmark/outputs/genai_qwen2_fourway_compare.json
```

Four modes x 8 scenarios = 32 actual LLM episodes on your Mac. Check the audit and report
before interpreting. Unlike scripted replays, these are real model-generated tool calls.

## Important design caveats

1. The trusted policy file is authored by the defender, not inferred from prompt text.
2. A known class of release via known adapters is easy to block with ordinary access control;
   broad novelty would require comparison to existing policy-as-code/authorization systems.
3. No document lineage / derived-artifact propagation is implemented yet.
4. Accurate action-effect contracts are assumed; unknown effects are denied by default.
5. Synthetic workspace classifications must not be mistaken for classifications of NIST's
   publicly available original publications.
6. The `task_policy` mode remains a hidden test oracle and is not presented as our algorithm.
7. Initial denial at step zero is imposed by the evaluation harness, not an earlier autonomous
   agent action.
8. A fresh task/session is required to reset the denial ledger. No cross-session persistence.
9. Microsecond runtime-guard timing excludes model inference, network, I/O, and real tool overhead.

## Logs to send back for analysis

`genai_qwen2_guard_pilot.jsonl`, its `.manifest.json`, and `.audit.json` plus the terminal
summary; if running the four-way experiment, also send `genai_qwen2_fourway_compare.json`.
