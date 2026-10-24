# Final Experiments & Code Guide — Denied but Done

**Audience:** Coauthors and technical reviewers of the AIRC 2027 paper  
**Purpose:** Explain what the completed benchmark measures, how the code is organized, where its evidence resides, and how to review it **without altering frozen runs**.  
**Status:** Both Stage 5.5B and Stage 5.6 experimental runs have completed. The older `docs/README_STAGE5_5B.md` and any historical `README_STAGE5_6.md` distributed with the engineering patch are **pre-run protocol notes**, not statements of current progress.

## 1. Scientific question and intended contribution

The central question is: **After a trusted tool denial, can an LLM agent nevertheless cause the same prohibited *simulated effect* using a derivative document or a substitute release tool?**

This is an empirical evaluation of **post-denial agent continuations**. The claim is not that execution mediation or information-flow provenance are new algorithms. Our distinctive evaluation choices are:

1. Every episode starts with the **same harness-imposed `POLICY_DENIED`** (the model did not independently deny itself).
2. The agent can still read and process the synthetically restricted source for authorized **internal** work.
3. A lower-trust synthetic collaborator note may encourage release through `pages.publish` or `drive.share` after the original denied `email.send`.
4. The simulator records **actual committed in-memory state changes**, rather than counting unsafe-looking prose as successful leakage.
5. Traces distinguish **note assignment from delivery/exposure**, natural model-created ancestry from pre-established ancestry, and authorized public controls from forbidden descendant releases.
6. The supplementary study tests a deliberately label-only guard against an ancestry-aware authorization boundary, without claiming that all stateless systems have that limitation.

**Not measured:** a model's self-generated initial refusal; causes of denial-conditioned behavior relative to a no-denial control; semantic confidentiality of free-form paraphrases; deployed servers; authentic enterprise access policies; real exfiltration; or general-purpose novelty of provenance-based controls.

## 2. Walkthrough of one simulated episode

The benchmark initializes a document store and synthetic authorization policy. The evaluator injects a trusted denial of an external `email.send` of source `d0` without mutating simulator state. The LLM then continues with available tools. Reading a targeted root may expose either a benign note or a synthetic injection note. Authorized internal operations may create `d1` and `d2` with trusted `derived_from` edges (`d0 -> d1 -> d2`). The agent may request public publication or external sharing of one of those documents.

The executor performs the configured authorization decision **before** mutating simulated state. An attempted action is not counted as a committed effect if it is malformed, rejected, or never proposed. A separate assessment predicate judges whether the resulting state violates the scenario's restriction. The independent-public controls allow unrelated public content to be released; indiscriminately blocking all publication would fail their purpose.

All source text comes from authentic, **public** NIST/GAO/DHS reports, while benchmark restriction labels and collaborator notes are **synthetic**. Internal derivation is allowed; external/public release of any restricted-root descendant is prohibited under the experiment's rules. Government agencies have not classified these excerpts as confidential for this research.

## 3. The three evaluated execution modes

| Mode | Mechanism | What it tests |
|---|---|---|
| `denial_only` | Trusted denial at step zero; no continuing release guard | Whether later agent proposals can commit a prohibited effect |
| `stateless_guard` (Stage 5.6) | Checks current resource label and destination, **not trusted ancestry** | A constructed blind spot when derivatives are labeled `public` |
| `runtime_guard` | Uses trusted ancestry and intended release destination to check before state mutation | Whether known protected descendants can be blocked without refusing all authorized operations |

The stateless comparator is **purposely narrow**: newly created derivatives may be labeled `public` despite restricted ancestors. Its observed failure does **not** establish superiority over independently implemented commercial or more comprehensive stateless solutions. The lineage-aware guard has privileged access to correct simulator ancestry; untracked copies and semantic rewordings are outside its tested guarantee.

## 4. Completed design and results (do not combine denominators)

| Item | Stage 5.5B | Stage 5.6 |
|---|---|---|
| Study status | Locally project-frozen, completed | Separately locally project-frozen, completed **after** 5.5B analysis |
| Source texts | Three excerpts from two NIST reports | Three excerpts: NIST SP 800-218A, GAO AI Accountability Framework, DHS AI Roadmap 2024 |
| Matched cases | 28 = 12 benign/injection target pairs + 2 independent-public-control pairs | Same factorial structure, new source excerpts |
| Models | `qwen2:7b`, `llama3.1:8b` | Same |
| Seeds | 11, 29, 47 | Same |
| Modes | `denial_only`, `runtime_guard` | `denial_only`, `stateless_guard`, `runtime_guard` |
| Total agent episodes | **336** | **504** |
| Assigned adversarial target episodes | 72 per defense | 72 per defense |
| Prohibited commit episodes | **31/72** denial-only, **0/72** lineage-aware | **40/72** denial-only, **40/72** label-only, **0/72** lineage-aware |
| Independently replayed source-read hashes | **668/668** | **1,055/1,055** |

For the 336-episode Stage 5.5B study, the guard permitted **861 executable authorized requests** without an observed false block. For the 504-episode Stage 5.6 study, it permitted **23/23** valid authorized external/public requests presented to it; structural task completion was 121/168 for denial-only, 120/168 for label-only, and 119/168 for lineage-aware enforcement. Those are action and *structural* completion counts, not proof of semantic utility or a low real-world false-positive rate.

**Do not claim:** that all 31 or 40 primary commits were necessarily *caused* by injected content. The first study recorded violations without actual note exposure. Stage 5.6 recorded exposure preceding its observed targeted commits, but exposure alone does not prove causation. Neither study contains a no-denial condition, so it cannot establish that receiving a denial *caused* later evasion.

The two stages share concepts, prompts/attack families, models, and seeds. Stage 5.6 was motivated by Stage 5.5B. **840 is a count of total model episodes, not a pooled effectiveness trial or independent confirmatory replication.**

### Tool-contract and reliability limitations

Stage 5.5B logged **437 invalid tool-response events**, all associated with Llama, and 27 horizon-exhausted episodes. Stage 5.6 logged **895 invalid response events** (781 Llama, 114 Qwen) and 56 horizon-exhausted episodes. These are important model-interface confounders; do not rank model-family security solely by observed prohibited-commit rates. Neither study recorded model-backend execution errors in the completed reporting.

## 5. Code orientation for coauthors

The working Python package is `benchmark/`. Read these modules in roughly this order; their names are grounded in the existing repository and the dependency audit, but the comments below are an architectural map rather than a line-by-line API specification.

| Module(s) | Role in the research |
|---|---|
| `sim.py`, `contracts.py` | In-memory document/tool state, scenario loading and tool-call contract definitions |
| `runtime_guard.py`, `runtime_policy.json` | Trusted authorization logic/policy for the ancestry-aware execution boundary |
| `agent_loop.py`, `ollama_adapter.py` | Original agent execution and local Ollama interface |
| `stage5_6_agent_loop.py`, `stage5_6_stateless_guard.py` | Supplementary agent continuation and intentionally label-only guard |
| `build_stage5_5b_cases.py`, `freeze_stage5_5b.py` | Original scenario construction and local protocol freeze |
| `run_experiment.py`, `stage5_5b_analysis.py` | Original model run entry point and results analysis |
| `stage5_6_build.py`, `stage5_6_protocol.py` | Supplementary scenario construction and protocol freeze |
| `stage5_6_run.py`, `stage5_6_analysis.py` | Supplementary run entry point and analysis |
| `audit_trajectories.py` | Trace-level integrity and policy/outcome auditing |
| `tests/test_stage5_5b.py`, `tests/test_stage5_6.py` | Stage-specific regression tests; other tests preserve older behavior |

Note the non-obvious dependencies: `stage5_5b_analysis.py` imports `stage5_4_diagnostics.py`; Stage 5.6 imports `build_stage5_5b_cases.py`, `sim.py`, `runtime_guard.py`, `ollama_adapter.py`, `audit_trajectories.py`, and other cross-stage modules. These older-looking files are **not disposable** merely because their names refer to earlier development.

### Typical investigative reading order

1. `benchmark/stage5_6_multisource.json` and `benchmark/stage5_5b_evaluation.json` — paired cases, source scope, and synthetic notes.
2. `benchmark/sim.py` — what document reads, internal derivation, sharing and publication mean in memory.
3. `benchmark/runtime_guard.py` and `benchmark/stage5_6_stateless_guard.py` — authorization decisions.
4. `benchmark/stage5_6_agent_loop.py` and `benchmark/agent_loop.py` — how an LLM tool request becomes a simulated tool action.
5. `benchmark/stage5_6_analysis.py` and `benchmark/stage5_5b_analysis.py` — definitions of scored outcomes and quality checks.
6. Frozen protocols, manifests, verification reports and raw JSONL traces — validate specific manuscript numbers.

## 6. Evidence locations and integrity

**Stage 5.5B**

- Frozen protocol: `research_evidence/stage5_5b/protocol/STAGE5_5B_FROZEN_PROTOCOL.json`
- Frozen scenario: `research_evidence/stage5_5b/scenarios/stage5_5b_evaluation.json`
- Working trace: `benchmark/outputs/stage5_5b_evaluation.jsonl`
- Evidence copies/reports: `research_evidence/stage5_5b/outputs/`, `research_evidence/stage5_5b/verification/`
- Working audit and report: `benchmark/outputs/stage5_5b_evaluation.audit.json`, `benchmark/outputs/stage5_5b_analysis.json`
- Original dataset and builder path: `benchmark/stage5_5b_evaluation.json`, `benchmark/build_stage5_5b_cases.py`

**Stage 5.6**

- Frozen protocol: `research_evidence/stage5_6/protocol/STAGE5_6_FROZEN_PROTOCOL.json`
- Scenario: `benchmark/stage5_6_multisource.json`
- Working trace: `benchmark/outputs/stage5_6_multisource.jsonl`
- Working manifest, audit, analysis: `benchmark/outputs/stage5_6_multisource.manifest.json`, `.audit.json`, `.analysis.json` (with the full `stage5_6_multisource` prefix)
- Consolidated evidence ZIP: `research_evidence/stage5_6/outputs/stage5_6_review_bundle.zip`
- Runtime console log: `research_evidence/stage5_6/run_logs/evaluation_console.log`

**Primary source reports in `data/`**

- `NIST.AI.100-1.pdf`, `NIST.AI.600-1.pdf` (Stage 5.5B)
- `NIST.SP.800-218A.pdf`, `GAO-21-519SP.pdf`, `DHS-AI-ROADMAP-2024.pdf` (Stage 5.6)

The completed study recorded source and protocol SHA-256 fingerprints. For Stage 5.5B the evaluation JSONL's separately confirmed SHA-256 is:

```text
ddffc3a94db20b996a895ecacc302b3a2908beda9fe157818f8b118f07ee62cc
```

Reviewers can compare it with their own local file:

```bash
shasum -a 256 benchmark/outputs/stage5_5b_evaluation.jsonl
shasum -a 256 research_evidence/stage5_5b/outputs/stage5_5b_evaluation.jsonl
unzip -t research_evidence/stage5_6/outputs/stage5_6_review_bundle.zip
```

The user previously verified the two Stage 5.5B trace copies match byte-for-byte. Keep all original frozen artifacts in place. The Stage 5.6 evidence ZIP includes a full study copy of the three additional federal PDFs, protocol, scenario, trace, manifest, audit, analysis, and run log.

**Remaining reproducibility gap:** the paper reports that three older executable dependencies were not independently rearchived byte-for-byte from Stage 5.6's execution environment. Find and archive those originals where possible; do not invent or replace their historic hashes.

## 7. Safe verification commands (no LLM reruns)

From the `AIRC 2027/` project root:

```bash
# Check the current working tree's active tests (does not require rerunning Ollama).
python3 -m pytest -q

# Confirm completed episode counts from JSONL line counts.
wc -l benchmark/outputs/stage5_5b_evaluation.jsonl \
  benchmark/outputs/stage5_6_multisource.jsonl

# Confirm baseline archive is readable and list the exact included evidence.
unzip -l research_evidence/stage5_6/outputs/stage5_6_review_bundle.zip
unzip -t research_evidence/stage5_6/outputs/stage5_6_review_bundle.zip

# View the small, existing structured study summaries.
python3 -m json.tool benchmark/outputs/stage5_5b_analysis.json | less
python3 -m json.tool benchmark/outputs/stage5_6_multisource.analysis.json | less
```

At the October 2026 cleanup checkpoint, **113 tests plus 22 subtests passed** when only `tests/` were collected. A broad pytest invocation previously failed by collecting archived files with duplicate test names; `pytest.ini` now specifies `testpaths = tests` and excludes `research_evidence` from automatic discovery.

**Avoid blindly following older commands** that rebuild or overwrite frozen scenarios, rerun the original experiment, or prepare a new freeze under the same filenames. To run a new independent study, create distinct output and protocol names, preserve hashes, and report it as a new experiment rather than modifying original trajectories.

### What to inspect, rather than execute, in historical instructions

- `docs/README_STAGE5_5B.md`: design and **pre-run** Stage 5.5B instructions; its “DO NOT RUN YET” and projected-count wording describes the historical preparation stage, not current status.
- `README_STAGE5_3.md`, `README_STAGE5_4.md`, `docs/history/`: legacy pilot procedures and research history.
- `research_evidence/code_backups/`: older implementation snapshots and retired test snapshots; do not delete because tests or forensic comparisons may still depend on them.

## 8. Coauthor scientific review checklist

- [ ] Confirm author names, affiliations, contributions, and final manuscript approval.
- [ ] Confirm that all paper numerators and denominators correspond to **assigned adversarial target episodes**, not the total 336 or 504 episodes.
- [ ] Confirm the study-specific sampling settings, model digests, source PDF pages, and exact scenario fingerprints against protocols and manifests.
- [ ] Inspect benign versus injected notes and actual note-exposure records; don't infer prompt-injection causality from assignment alone.
- [ ] Independently check how a prohibited *attempt* differs from a successful *simulator commit* and how authorized-public controls are handled.
- [ ] Check the deliberate derivative-label blind spot and the trusted lineage guard; avoid claims about arbitrary production access-control systems.
- [ ] Review invalid tool formats, horizon exhaustion, structurally graded utility, related-scenario dependence, and limitations.
- [ ] Preserve the study's original files and provenance before creating any external reproduction package.

## 9. What belongs in an eventual public repository

A publishable reproduction package should contain source code and license, clear Python/Ollama requirements, exact model digests and configurations, original scenario/protocol fingerprints, source links and hashes, evaluation JSONL/manifest/audit/analysis, and executable verification instructions with a clean-room test. It should not contain credentials or sensitive user data. Decide coauthor permissions and research artifact licensing before publishing. Stage 5.6's evidence bundle is a starting point, but a ZIP of traces alone is not full end-to-end executable reproduction.

---

**Research integrity note:** The benchmark's document restrictions and action effects are synthetic and all evaluated external operations occur in memory. The main finding is a bounded, auditable observation about **authorization persistence in a controlled workflow**, not proof of successful real-world exfiltration or a newly invented enforcement algorithm.
