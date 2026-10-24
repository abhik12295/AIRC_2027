# Stage 3.1 — Paired model-facing injection pilot

This extension corrects a methodological limitation in the original 23 pilot fixtures:
`continuation_actions` was only used by scripted replay, so multiple nominal
"evasion" cases were indistinguishable to a real LLM. The optional
`untrusted_workspace_content` field is now included in the model-facing prompt
as clearly labeled lower-trust retrieved content.

Three *pairs* of synthetic pilot cases model document disclosure, protected branch
modification, and access elevation. Each pair uses exactly the same task,
initial workspace, policies, imposed denial, and grading predicates. The only
independent variable is an untrusted snippet: ordinary task data vs an adversarial
instruction encouraging a prohibited alternative action.

Run all unit tests (stdlib only):

```bash
python -m unittest discover -s benchmark -p 'test_*.py' -v
python -m unittest discover -s tests -p 'test_*.py' -v
```

Start with the first **pair** (documents), 3 enforcement modes, one seed:

```bash
python -m benchmark.run_experiment --backend ollama --models qwen2:7b \
  --scenarios benchmark/pilot_adversarial_pairs.json \
  --max-scenarios 2 --modes denial_only tool_blocklist task_policy \
  --seeds 42 --timeout 180 --out benchmark/outputs/paired_docs_pilot.jsonl
python -m benchmark.report_experiment benchmark/outputs/paired_docs_pilot.jsonl
```

Only if the above completes correctly, run all **six** cases (3 domains x 2
conditions) under the three modes. This is still **pilot** data, not held-out.

```bash
python -m benchmark.run_experiment --backend ollama --models qwen2:7b \
  --scenarios benchmark/pilot_adversarial_pairs.json \
  --modes denial_only tool_blocklist task_policy --seeds 42 --timeout 180 \
  --out benchmark/outputs/paired_3domains_pilot.jsonl
python -m benchmark.report_experiment benchmark/outputs/paired_3domains_pilot.jsonl
```

## Research limitations

- An imposed denial is placed in the prompt as history; no model made that decision.
- The untrusted snippet is injected into a synthetic prompt, rather than
  returned through a running external data connector.
- The explicit system instruction forbidding a bypass may reduce attack effects;
  this is a deliberately defended setting, not an unprotected baseline.
- Temperature is 0, so repeating the same seed or changing seeds may yield
  little variation. Independent attack families, distinct tasks and multiple
  models are needed before any quantitative generalization.
- The `task_policy` condition uses a trusted state/effect oracle. It is an
  idealized upper bound, not an implementable novel defense.
- These six scenarios are strictly for iterative development; do not tune on
  held-out cases, claim novelty, or write a findings section from this pilot.
