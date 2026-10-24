# Prior-art comparison — Stage 1

Status: **Abstracts / authoritative landing pages verified; complete full-text methodology comparisons are still pending.** Avoid strong first/novelty claims until the pending work is finished.

| Research | Verified contribution | Overlap risk for Denied but Done | Precise differentiation to test |
|---|---|---|---|
| AgentDojo (NeurIPS 2024) | Tool-use prompt-injection attack and defense benchmark | Many realistic tasks, unsafe tool effects and utility metrics already present | Controlled explicit-denial checkpoint and follow-on outcome grading; determine whether AgentDojo already supports direct reuse |
| ToolEmu (ICLR 2024) | Simulated LM-agent tool-risk assessment | Emulated tools, safety evaluation and scenario generation already established | Do not present mock tools as an innovation; rely on denial-conditioned experimental controls |
| AgentLAB (ICML 2026) | Long-horizon attack benchmark incl. tool chaining and objective drift | Directly studies multi-step attack behavior | Focus on before/after adjudicated policy denial, not generic long-horizon attack success |
| ChainCaps (AIWILD 2026) | Capability attenuation across tool composition and permission laundering | Directly addresses forbidden composed effects | Treat as strong source/baseline; not novel to add a generic cross-tool effect check |
| ActGov (arXiv Sep 2026) | Task-scoped authorization per agent action, SMT-checked policy iteration | B2 and OCC are potentially equivalent in effect to parts of ActGov | Need behavior-level comparison of post-denial continuations, not claim a brand-new policy guard |
| APEX (arXiv Oct 2026) | Execution-boundary protection from task authorization contracts | Strongest overlap with proposed effect-boundary method | Benchmark focused on denial-conditioned paired outcomes; ideally compare actual APEX code if feasible |
| DeAction (ICML 2026) | Misaligned action detection plus correction | Corrective feedback and task utility overlap | Distinguish safety permission from task alignment; test multi-step alternate effects |
| ToolSafe (ACL Findings 2026) | Step-level unsafe tool invocation detection, guardrail feedback | Local action classification and feedback already studied | Compare action-level flags against state-based post-denial end-state outcomes |
| Stop Means Stop (arXiv 2026) | Framework rejection/cancellation and barrier semantics | 'Denial' language may incorrectly imply the same problem | Our threat is alternate tool pathways AFTER a hard authorization denial, not parallel execution while a run is paused |

## Decision rule for final contribution

- If prior art already measures denial-conditioned final states under paired benign/forbidden recovery controls, cite and extend transparently rather than asserting novelty.
- If outcome-consistency check merely replicates ActGov/APEX/ChainCaps, omit it as a claimed algorithmic contribution and emphasize benchmark design, rigorous evaluation, and comparative findings.
- If controlled benchmark cases fail to induce any measurable violations, publish the negative finding if methodologically convincing or revise the paper scope; do not fabricate positive performance.
