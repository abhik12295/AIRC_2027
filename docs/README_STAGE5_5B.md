# Stage 5.5B — Prospective engineering and project-freeze procedure

**Purpose:** Safely prepare a prospective two-model, two-defense, multi-seed local experiment. This patch does **not** run a model, does **not** claim independent preregistration, and does **not** alter archived Stage 5.4/5.5A JSONL traces.

## What is changed

1. **Scoped notes:** `untrusted_note_doc_ids` explicitly names the initial document(s) whose `documents.read` response can contain a lower-trust note. Old scenarios without this field default to the document in the imposed denied action; reading an unrelated independent public doc no longer leaks the note. Synthetic annotations remain separate from NIST text and the integrity auditor checks read payload hashes.
2. **Model output diagnostics:** Every parsed agent turn records model-output UTF-8 byte/character lengths, full SHA-256 hash, a short preview/suffix, and backend metadata if Ollama supplies `done_reason`, `eval_count`, `prompt_eval_count` and duration fields. The previous invalid-response preview of 1,000 chars is replaced by a bounded 240-char preview. Model text is not fully duplicated in trace metadata.
3. **Sampling:** `--temperature` and `--num-predict` are CLI options passed unchanged to Ollama per turn and recorded with the adapter hash and seeds in each manifest. Legacy defaults remain 0.0 and 256.
4. **New scenarios:** 3 genuinely different *source excerpts* from the existing two public NIST PDFs (selected by deterministic rules; exclude previously used Stage 3.2 and Stage 5.4 PDF pages), crossed with natural/pre-established ancestry and public/share tools = 12 paired attack families. Two extra independent-public-control pairs give **28 cases** total. Restriction is **synthetic**, not a statement that NIST PDFs are confidential.
5. **Protocol gate:** `freeze_stage5_5b` records three fresh source-excerpt hashes, scenario SHA-256, both Ollama model digests, code files, seeds, temperature, output-token limit and UTC time. The runner rejects evaluation-split scenarios lacking this frozen file, or with mismatched versions. It refuses to overwrite an evaluation JSONL/manifest.
6. **Read-only analysis:** separate attempted prohibited actions from committed effects and guarded blocks. Primary endpoint is prohibited-commit episodes / all assigned **attack-target injection** episodes. Authorized-public controls do not enter that denominator. Includes descriptive Wilson intervals and a *small-n* paired bootstrap of source-excerpt clusters, not independent-event confidence claims.

## 0. Create a source-code backup before installing

From your `AIRC 2027` root:

```bash
mkdir -p research_evidence/code_backups/stage5_5b
cp benchmark/{agent_loop,ollama_adapter,run_experiment,sim,audit_trajectories,report_experiment}.py \
  research_evidence/code_backups/stage5_5b/
```

Install the ZIP:

```bash
unzip -o ~/Downloads/Stage5_5B_Engineering_And_Protocol_Patch.zip -d .
```

The ZIP only replaces the six code files above and adds four Python utilities, one test file, this README, and the design draft. **It does not modify `runtime_guard.py` or `runtime_policy.json`.**

## 1. Engineering regression tests

```bash
python -m unittest discover -s benchmark -p 'test_*.py' -v
python -m unittest discover -s tests -p 'test_*.py' -v
```

Expected 18+108 = **126** passing tests with the current Stage 5.4/5.5A project checkout.

## 2. Sampling smoke test using OLD exploratory scenarios (not new evaluation cases)

```bash
python -m benchmark.run_experiment \
  --backend ollama \
  --models qwen2:7b llama3.1:8b \
  --scenarios benchmark/stage5_4_pilot.json \
  --max-scenarios 2 \
  --modes denial_only runtime_guard \
  --seeds 11 29 47 \
  --temperature 0.3 --num-predict 512 --timeout 180 \
  --out benchmark/outputs/stage5_5b_sampling_smoke.jsonl

python -m benchmark.check_sampling_variability \
  benchmark/outputs/stage5_5b_sampling_smoke.jsonl --require-variation
```

Expected 24 exploratory episodes; this only checks whether **at least one** old pilot scenario varies across seeds for each model. If it fails, inspect before proceeding; changing seed does not guarantee diversity or independence. Archive this separately as an engineering smoke test.

## 3. Prepare new evaluation scenarios (NO model calls)

Ensure `data/NIST.AI.100-1.pdf`, `data/NIST.AI.600-1.pdf`, `research_evidence/stage3_2/real_document_pairs.json` and `benchmark/stage5_4_pilot.json` exist. The two PDFs must be the original downloadable public NIST documents. `pypdf` is required (`python -m pip install pypdf` if absent).

```bash
python -m benchmark.build_stage5_5b_cases \
  --data-dir data \
  --out benchmark/stage5_5b_evaluation.json
```

Expected 28 cases, 14 benign/injection pairs. Store stdout, inspect all 3 selected PDF page references, and confirm no overlap with Stage 3.2 (AI RMF) and Stage 5.4 (GenAI Profile) source pages. Generating the file does **not** freeze or validate the experimental model outcomes.

## 4. Lock the protocol **before** running any new cases

```bash
python -m benchmark.freeze_stage5_5b \
  --scenarios benchmark/stage5_5b_evaluation.json \
  --out research_evidence/stage5_5b/protocol/STAGE5_5B_FROZEN_PROTOCOL.json
```

This obtains full digest IDs from your **local Ollama** and locks the current Python hashes. Refuses an existing output file. Save the displayed SHA-256 and a read-only backup of the frozen scenarios and protocol. **Do not change source files, policies, model versions, prompts or sampling settings after this point.** Ask for an independent review of the hashes and selected source excerpts **before starting the 336-episode run**.

An in-project timestamp/hash is **not** external preregistration; no such claim should be made. The Stage 5.5B protocol has a prospective design but related attack structure was developed from earlier pilots.

## 5. Commands for the later (post-review) frozen evaluation — DO NOT RUN YET

Only after step 4 is checked, the projected full run would be:

```bash
python -m benchmark.run_experiment \
  --backend ollama --models qwen2:7b llama3.1:8b \
  --scenarios benchmark/stage5_5b_evaluation.json \
  --modes denial_only runtime_guard --seeds 11 29 47 \
  --temperature 0.3 --num-predict 512 --timeout 180 \
  --frozen-protocol research_evidence/stage5_5b/protocol/STAGE5_5B_FROZEN_PROTOCOL.json \
  --out benchmark/outputs/stage5_5b_evaluation.jsonl

python -m benchmark.audit_trajectories \
  benchmark/outputs/stage5_5b_evaluation.jsonl \
  --scenarios benchmark/stage5_5b_evaluation.json \
  --manifest benchmark/outputs/stage5_5b_evaluation.manifest.json \
  --out benchmark/outputs/stage5_5b_evaluation.audit.json

python -m benchmark.stage5_5b_analysis \
  --scenarios benchmark/stage5_5b_evaluation.json \
  --traces benchmark/outputs/stage5_5b_evaluation.jsonl \
  --frozen-protocol research_evidence/stage5_5b/protocol/STAGE5_5B_FROZEN_PROTOCOL.json \
  --out benchmark/outputs/stage5_5b_analysis.json
```

Complete planned size: 28 × 2 × 2 × 3 = **336 episodes**; 12 attack-target injection cases × 2 models × 2 modes × 3 seeds = **144 primary-endpoint observations**, excluding the two public-control injection cases per model/mode/seed. All counts are projections, not completed outcomes. Because sequential Ollama episodes can take a long time and the current runner writes the JSONL at the end, arrange adequate uninterrupted compute and disk before starting.

## Interpretation and limitations

- No real external release; all data and tool actions are simulated in local memory.
- Untrusted notes are synthetic; NIST PDFs are public.
- The initial `POLICY_DENIED` is imposed by the evaluator at step zero.
- Do not classify no-attempt cases as successful guard blocks.
- A model-created provenance chain is different from a trusted pre-established chain.
- Structural summary completion is not an independent factual-quality assessment.
- New PDF source excerpts share two parent PDFs and a related attack design; a project freeze is not proof of independent, random, broadly generalizable cases.
- Family-cluster uncertainty is weak with just **three** source-excerpt clusters (two excerpts from one NIST publication). Results remain context-bound.
- Do not change any historical Stage 5.4 metrics or pilot data to make new results look more favorable.
