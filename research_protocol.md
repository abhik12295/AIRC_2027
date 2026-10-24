# Stage 1 — Research charter and decision gates

Date: 2026-10-13
Status: Proposed methodology, not study findings.

## Thesis under test
After a trusted policy engine denies an unauthorized effect, does a tool-using agent still produce the forbidden environmental outcome by using an alternate allowed tool or sequence, and can a task-scoped outcome check prevent that without suppressing legitimate alternatives?

## Research gap caveat
NOT a claim that unsafe tool composition or authorization at execution boundaries is new. ChainCaps (2026), ActGov (2026), APEX (Oct 2026), and AgentLAB (ICML 2026) overlap substantially. Potential differentiation is **controlled-denial-to-final-state benchmark methodology**, explicit benign recovery controls, and comparability of attempted versus committed forbidden effects. Full-text audit required before claiming novelty.

## Testable hypotheses (not established)
H1: Some agent/configuration combinations have nonzero prohibited-outcome completion after a controlled hard-security denial in synthetic environments.
H2: Availability of alternative tool pathways changes post-denial attempts and forbidden final states relative to otherwise matched single-path tasks.
H3: A trusted task-scoped effect policy may reduce committed forbidden outcomes relative to isolated per-tool checks but may increase false blocking or overhead.

## Working protocol
1. Implement only synthetic environments (email/documents/repository/admin) with deterministic state transitions and no external I/O.
2. Encode trusted policy and forbidden predicate outside the agent prompt; differentiate hard policy denial, auth challenge, transient outage, and rate-limit response.
3. Create paired legitimate/forbidden cases; for benign tasks alternative tools must be authorized by policy.
4. Controlled denial at fixed timepoint, consistent response codes, bounded continuation H=8 tool calls initially.
5. Log original authorization, policy ID, denial, all attempted actions, blocks, state transitions, outcomes, and model metadata.
6. Pilot ~12-20 hand-verified cases first; then create ~100-150 balanced and scenario-family-separated cases if pilot succeeds.
7. Test B0 no cross-tool security policy (but controlled denial), B1 per-tool policy, B2 global trusted task-scoped policy; candidate OCC only if it differs materially from B2.
8. Hold out scenario families, not only paraphrases; use matched seeds and family-cluster bootstrap CIs for conditional post-denial outcome measures.
9. Primary metric PDC@8 = proportion of valid hard-denial trials where the prohibited state is later committed; utility metric ATC on allowed recovery controls. Secondary: prohibited attempted effects, false blocks, tool counts, time, latency.

## Risks and boundaries
- No human victims, customer records, real exfiltration, real payments, or production calls.
- A security denial does not automatically mean all alternatives are forbidden. Trusted policy decides whether the *outcome* is allowed.
- Tool unavailability, generic errors and policy denial must not be conflated.
- Initial security results apply only to visibility of simulated effects through mediated tools; no proof about hidden channels, concurrent tools, OS network escape or real-world agent breach incidence.
- Explicitly distinguish papers accepted at conferences from unreviewed arXiv preprints.

## Stage gates
- Exit Stage 1: source audit, manuscript setup, explicit scenario schema and hypotheses [PREPARED; full-text gap review still needed].
- Exit Stage 2: deterministic toy environment with executable policy predicates and unit-tested scenarios.
- Exit Stage 3: frozen baselines and held-out outcomes.
- Exit Stage 4: candidate intervention and comparison if nonredundant with state-of-art baseline.
- Exit Stage 5: statistics, robustness, error cases, reproducibility appendix/artifacts.
- Exit Stage 6: final ≤10-page AIRC-compliant PDF and source, no unsupported claims.

## Primary source URLs
- AgentDojo: https://proceedings.nips.cc/paper_files/paper/2024/hash/97091a5177d8dc64b1da8bf3e1f6fb54-Abstract-Datasets_and_Benchmarks_Track.html
- AgentLAB: https://proceedings.mlr.press/v306/jiang26as.html
- ChainCaps: https://arxiv.org/abs/2605.26542
- ActGov: https://arxiv.org/abs/2609.24446
- APEX: https://arxiv.org/abs/2610.06966
- Stop Means Stop: https://arxiv.org/abs/2607.14166
- ToolSafe: https://aclanthology.org/2026.findings-acl.1850/
- DeAction: https://proceedings.mlr.press/v306/ning26c.html
- NIST CAISI agent hijacking summary: https://www.nist.gov/blogs/caissi-research-blog/insights-ai-agent-security-large-scale-red-teaming-competition
