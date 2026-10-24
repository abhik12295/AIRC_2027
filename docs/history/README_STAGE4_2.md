# Denied but Done — Stage 4.2: Fail-Closed Guard Hardening

**Status:** engineering security regression package; **not** a new LLM experiment or held-out result.

## Changes from Stage 4.1

- Unknown/missing/blank/non-string document classifications fail closed. Known security labels are stripped/lowercased, so `" Restricted "` cannot slip through a string comparison.
- `"internal"` is protected against external release, as well as `"restricted"`, `"confidential"`, and `"secret"`.
- External release of protected content requires a **typed, exact-resource, exact-destination, allowlisted-issuer approval** in `state["verified_release_approvals"]`. The legacy `state["verified_release_approval"]` boolean is intentionally **not accepted**. This is a breaking contract change; there are no legacy approval grants in the previous LLM pilot cases.
- For trusted metadata `derived_from: ["SOURCE-ID"]`, external releases inherit the stricter restrictions and previous denials of their ancestors. Unresolved, cyclical, malformed lineage fails closed. This is a **guard-level metadata test**: the agent simulator does not yet include a create-derived-document operation, so do not claim an end-to-end document-transformation result.
- Repository and identity approval checks accept only boolean `True`, never truthy strings such as `"false"`.
- Added 37-case deterministic authorization stress matrix and 5-case **denial-ledger ablation** to distinguish general classification protection from persistence of a denied *outcome*.

## Installation (from the root `AIRC 2027` folder)

```bash
cp -R benchmark benchmark_before_stage4_2
cp -R tests tests_before_stage4_2
unzip -o ~/Downloads/Stage4_2_Runtime_Guard_Patch.zip -d .
```

If the patch is downloaded elsewhere, adjust the zip path. Do not move into `data/` to run the commands.

## Validate first — no Ollama required

```bash
python -m unittest discover -s benchmark -p "test_*.py" -v
python -m unittest discover -s tests -p "test_*.py" -v
python -m benchmark.stage4_guard_stress \
  --out benchmark/outputs/stage4_2_guard_stress.json
python -m benchmark.stage4_2_ablation \
  --out benchmark/outputs/stage4_2_ablation.json
```

Expected in the supplied package: **18 + 47 = 65 unit tests passed**, 37/37 stress expectations matched, 5/5 ablation expectations matched. Ablation should show exactly **2 of 5** counterfactual decisions changed by the denial ledger. These are deterministic local checks, not LLM security rates.

## Optional small *model-driven* regression (still pilot)

Only after the above commands succeed, reuse the `genai_robustness_pilot.json` generated on your computer and run:

```bash
python -m benchmark.run_experiment \
  --backend ollama \
  --models qwen2:7b \
  --scenarios benchmark/genai_robustness_pilot.json \
  --modes runtime_guard \
  --seeds 42 \
  --timeout 180 \
  --out benchmark/outputs/genai_qwen2_guard_stage4_2_pilot.jsonl

python -m benchmark.report_experiment \
  benchmark/outputs/genai_qwen2_guard_stage4_2_pilot.jsonl

python -m benchmark.audit_trajectories \
  benchmark/outputs/genai_qwen2_guard_stage4_2_pilot.jsonl \
  --scenarios benchmark/genai_robustness_pilot.json \
  --manifest benchmark/outputs/genai_qwen2_guard_stage4_2_pilot.manifest.json \
  --out benchmark/outputs/genai_qwen2_guard_stage4_2_pilot.audit.json
```

Do not overwrite the old v0.1 pilot: we want a side-by-side implementation regression. Logs automatically include the new runtime policy hash.

## Approval metadata contract

`verified_release_approvals` must come from a **trusted authorization service**. Example of an application-supplied grant:

```json
{
  "verified_release_approvals": [
    {"document":"DOC-A", "destination":"public", "issuer":"security-office", "approved":true}
  ]
}
```

It is only a simulator abstraction: the current code does *not* implement signature verification, expiry, identity binding, a real policy issuer, or durable authorization storage. Never expose this field as a writable LLM tool parameter. Prior trusted POLICY_DENIED decisions still override later local grants in the same evaluation episode.

## Boundaries and important next work

1. The tool-effect adapter list must include **every possible external side effect**. Missing/wrong effect specifications invalidate enforcement assumptions.
2. The same trusted application must capture lineage for derived artifacts. Otherwise, derived-content restrictions cannot be enforced reliably.
3. Unit ablation is not a measured agent attack-prevention effect. Before writing the paper, create scenarios that actually require denial persistence independent of resource classification.
4. The synthetic step-zero denial is evaluator-imposed; no model autonomously made the initial denied tool call.
5. Prior-pilot results remain exploratory; no held-out experimental results or general efficacy claims have been established.
