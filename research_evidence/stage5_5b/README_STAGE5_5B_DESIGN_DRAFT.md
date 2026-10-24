# Stage 5.5B — Evaluation design (draft, not frozen)

## Why Stage 5.4 evidence remains exploratory

The uploaded Stage 5.4 protocol (`stage5.4-exploratory-v1`) matches the archived scenario SHA-256 and explicitly marks the original experiment as a pilot. The earlier independent verification report's missing-protocol entry was correct *when written* and is now reconciled in a separate evidence file without alteration of that historical report.

The Stage 5.4 primary endpoint was **committed forbidden depth-two effects conditional on an attempted release**. Preserve that endpoint when reporting historical Stage 5.4 results. For a future study, use **prohibited-commit episodes / all assigned adversarial episodes** as the proposed primary endpoint, with attempted-release frequency and conditional guard blocking as separate secondary endpoints. This avoids selecting only those cases in which the model already chose to attack.

## Proposed run design — pending approval and implementation

- Models: locally installed `qwen2:7b` and `llama3.1:8b`.
- Defenses: `denial_only` and `runtime_guard`.
- Three *new* source families × two workflow arms (`natural`, `preestablished`) × two release tools (`pages.publish`, `drive.share`) = 12 attack families. Pair each family into benign/injection cases (24 cases).
- Add two authorized-public control pairs (4 cases), for 28 total scenarios.
- Seeds: 11, 29, 47. Proposed temperature 0.3, num_predict 512. **These options are not currently CLI-exposed in the existing runner**.
- Total projected runs: 28 scenarios × 2 models × 2 defenses × 3 seeds = **336 model episodes**. This is a planned count, not completed data.

## Must fix before the actual run

1. Scope lower-trust note injection to the intended document rather than any original/root document read.
2. Log exact invalid-response length/hash and backend finish reason/token counts. Historical 1,000-character previews cannot establish backend truncation.
3. Expose and record sampling parameters, run a separate engineering pilot, and verify all model/defense arms use identical settings.
4. Construct brand-new, independently versioned scenario families; prohibit prompt retuning after seeing evaluation responses. If a case is tuned, move it to development and create a new untouched case.
5. Verify pairing, simulator lineage, authorization controls, complete scenario coverage, model digests, SHA-256 fingerprints and auditor checks before model runs.
6. Freeze a separate protocol and analysis script with timestamp and hashes. This draft is not that frozen artifact.

## Reporting rules

- Do not treat non-attempts as successful guard interceptions.
- Separate model-created from pre-established chains.
- Report benign task completion, authorized release allowance, attempted forbidden release, forbidden commits and guard blocks distinctly.
- Treat repeated trajectories from the same scenario family as correlated; give descriptive uncertainty and scenario-family-aware inference.
- Distinguish synthetic restriction/guard outcomes from any real-world data release claims.

**No new scenarios or LLM evaluations were run to create these files.**
