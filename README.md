# Denied but Done — AIRC 2027 Research Repository

**Paper:** *Denied but Done: Benchmarking Post-Denial Policy Evasion in Tool-Using LLM Agents*  
**Status:** Stage 5.5B and Stage 5.6 evaluations completed; research results frozen locally.  
**Authors:** Abhishek Kumar, Namita Sandeep Tambe, Saurav Kant Kumar  
**Primary technical guide:** [Final Experiments & Code Guide](docs/FINAL_EXPERIMENTS_GUIDE.md)

## What this research asks

A tool-using large language model (LLM) agent may receive `POLICY_DENIED` when it attempts to export a restricted document, yet later try another tool or publish a *derived* document. We evaluate whether a denial alone prevents a later **prohibited simulated state change**, and how execution-time authorization based on trusted document ancestry changes the outcome.

A hypothetical example is an assistant that cannot email a restricted report externally but can read and summarize it internally; it may later try publishing or externally sharing a derivative. **This example is illustrative, not experimental logistics data.** All experiment sources are public government reports. Their `restricted` classifications, collaborator notes, authorization rules, and release destinations are synthetic. **No emails or files were actually published or shared externally.**

## Completed evaluations — two studies, not one pooled trial

| Study | Design | Episodes | Prohibited commits in assigned adversarial targets |
|---|---|---:|---|
| Stage 5.5B | 28 scenarios × 2 models × 2 enforcement modes × 3 seeds | **336** | Denial-only: **31/72**; lineage-aware: **0/72** |
| Stage 5.6 | 28 scenarios × 2 models × 3 enforcement modes × 3 seeds | **504** | Denial-only: **40/72**; label-only: **40/72**; lineage-aware: **0/72** |

Models: local Ollama `qwen2:7b` and `llama3.1:8b`; seeds: 11, 29, 47. Each study contains 12 benign/injection *target* pairs plus 2 independent-public-control pairs (28 cases). Both studies were project-frozen before their respective primary runs, **not externally preregistered**. Stage 5.6 was devised after examining Stage 5.5B; do not pool the two studies into an aggregate performance claim.

**Critical qualification:** The Stage 5.6 stateless comparator deliberately checks only the immediate resource label. The simulator deliberately labels derivatives `public` even when their trusted ancestry includes a restricted root. This is a controlled label-propagation ablation, **not evidence that every stateless authorization system is insecure**. The lineage guard checks known ancestry; it does not detect leaks with missing provenance metadata or guarantee production security.

## Where to start

1. Read **[Final Experiments & Code Guide](docs/FINAL_EXPERIMENTS_GUIDE.md)** for the threat model, implementation walkthrough, evidence map, and safe verification instructions.
2. Open `benchmark/stage5_6_run.py`, `benchmark/stage5_6_agent_loop.py`, `benchmark/stage5_6_stateless_guard.py`, `benchmark/runtime_guard.py`, and `benchmark/sim.py` to understand how model requests become simulated tool effects.
3. Inspect `benchmark/outputs/stage5_5b_analysis.json` and `benchmark/outputs/stage5_6_multisource.analysis.json` for the completed analyses.
4. Review the two frozen protocols in `research_evidence/stage5_5b/protocol/` and `research_evidence/stage5_6/protocol/`.
5. Run the active tests from the **project root**:

   ```bash
   python3 -m pytest -q
   ```

   At the October 2026 cleanup checkpoint, the active suite reported **113 passed, 22 subtests passed**. Your results may differ if the code or Python environment changes. `pytest.ini` limits default discovery to `tests/` so old snapshot tests under `research_evidence/` are not collected.

## Repository map

```text
AIRC 2027/
├── benchmark/                  # Python simulator, agent loops, guards, builders, runners, analysis
│   ├── outputs/                # Completed evaluation JSONL, manifests, audit and analysis files
│   ├── stage5_5b_evaluation.json
│   └── stage5_6_multisource.json
├── data/                       # Five authentic public government PDFs
├── docs/
│   ├── FINAL_EXPERIMENTS_GUIDE.md
│   ├── README_STAGE5_5B.md    # HISTORICAL pre-run instructions; not current study status
│   └── history/                # Prior engineering notes and pilot documentation
├── research_evidence/
│   ├── stage5_5b/              # Frozen protocol, study copy of traces, validation reports
│   ├── stage5_6/               # Frozen protocol, console log, evidence ZIP
│   ├── code_backups/           # Legacy code snapshots; retain for provenance
│   └── stage*/                 # Exploratory development evidence; retain as history
├── tests/                      # Active regression tests
├── pytest.ini                 # Discover only the current test suite
└── README.md                   # This entry point
```

## Working safely with frozen evidence

- **Read/analyze existing traces first.** Do not regenerate `benchmark/stage5_5b_evaluation.json`, `benchmark/stage5_6_multisource.json`, or overwrite the recorded JSONL, manifest, audit, analysis, or frozen protocol files.
- Original trajectories are in `benchmark/outputs/`; an additional Stage 5.5B copy is under `research_evidence/stage5_5b/outputs/`. Stage 5.6's packaged evidence is in `research_evidence/stage5_6/outputs/stage5_6_review_bundle.zip`.
- Use **new output names** and a separate directory if deliberately running fresh experiments. A rerun does not retroactively reproduce identical stochastic LLM output.
- Older README files describe earlier development stages and can contain phrases like “DO NOT RUN YET.” Preserve them as historical records; follow this README and the final guide for *current* study status.
- Do not publish proprietary information, credentials, or confidential data. Verify licensing and attribution before publishing or redistributing source reports or model artifacts.

## Scientific scope

The measurement distinguishes (i) assigned malicious note versus **actual note exposure**, (ii) invalid or merely proposed model tool calls versus **committed simulated actions**, and (iii) protected descendants versus **authorized independent-public releases**. Most limitations are described in the paper and final guide, including synthetic permissions, imposed step-zero denial, correlated scenarios, imperfect tool formatting, and structurally graded—not semantically verified—task completion.

**For coauthor review:** confirm the scientific claims against frozen protocols and trace outputs, inspect the design and policy logic, validate references and manuscript attribution, and flag reproducibility gaps before external release.
