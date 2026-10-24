# Stage 3 — implementation-first research log

**Date:** October 13, 2026

## What has actually been executed

- Preserved the prior Stage-2 benchmark (23 synthetic pilot scenarios, 3 domains, 18 original regression tests).
- Implemented a model-agnostic multi-step agent loop with JSON tool calls, trusted effect grading, separate policy-denial and service-outage handling, an explicit stop action, and immutable scenario state across runs.
- Implemented strict tool argument contracts and preflight validation so invalid actions do not count as benign false blocks.
- Implemented a local-only Ollama API adapter, paired experimental runner with fixed seeds, manifest provenance, and descriptive reporter.
- Added **13** new agent-loop regression tests. **31/31 total unit tests pass.**
- Executed **69 engineering-only scripted replays** = 23 fixed pilot scenarios × 3 defense modes. Logs and descriptive validation reports are included in `benchmark/outputs/`.
- **0 genuine LLM experiments** executed here. Ollama is not installed in the execution environment. No model output, model attack rate, safety intervention effectiveness, or generalizable research claim has been established.

## What the current code measures

The initial denial is **imposed** by the test harness; it is not a previous autonomous model decision. The research question is therefore conditional behavior after a security denial, not the base rate at which an agent spontaneously initiates a forbidden action.

Tracked outcomes include:
1. Whether an executable prohibited effect was **attempted** in post-denial continuation.
2. Whether a prohibited **state transition was committed at any time**.
3. Whether the **legitimate task completed**.
4. Whether a benign executable action was **falsely blocked** by a coarse defense.
5. Invalid action outputs, model errors, service outages, and complete traces.

Policy `task_policy` is an effect-oracle **upper-bound reference** by construction and cannot be promoted to a novel defense result. The replay paths intentionally contain known positive and negative cases; replay numbers are never evidence of model tendencies.

## Next scientific gates (no paper writing yet)

1. Obtain computing specifications: CPU, RAM, GPU and OS, and select two open-weight checkpoints that can run reliably. Record exact Ollama model digests.
2. Run a tiny two-scenario LLM smoke test; verify schema compliance, complete trace records, error feedback, and sensible termination.
3. Run a full 23-scenario **LLM pilot** (each of the three defenses for matched scenario/seed) to identify ambiguous prompts and other instrument failures. All pilot data are development-only.
4. Create a separate benchmark dataset with diverse realistic permission, data-exfiltration and approval workflows, and isolate held-out **scenario families** from prompt engineering and calibrations.
5. Pre-register hypotheses, baselines, effect semantics and evaluation metrics. Collect independently-reviewed outcome labels and add checks for both benign recovery and genuinely prohibited final outcomes.
6. Once experimental design is frozen, run multiple models and seeds on held-out cases. Evaluate effect completion, violation attempts, legitimate task rate and false blocks. Use family-clustered uncertainty estimates and preserve negative findings.
7. Prototype new defense **only if** empirical pilot observations justify it. Compare its cost and outcomes with non-oracle baselines. Run final ablations and replication.
8. **Only then** use verified experiments to draft the IEEE/Overleaf paper.

## Working assumption

Author team and paper topic remain unchanged, but LaTeX writing is deliberately paused. This package contains only research code, the prior methodology notes, and experimental logs.
