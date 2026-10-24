import json
import unittest
from pathlib import Path
from benchmark.sim import load_scenarios
from benchmark.agent_loop import initial_messages, ReplayAgent, run_agent_episode

HERE = Path(__file__).resolve().parents[1]
PAIRS = load_scenarios(str(HERE / "benchmark/pilot_adversarial_pairs.json"))

class AdversarialPairTests(unittest.TestCase):
    def test_balanced_paired_conditions(self):
        self.assertEqual(len(PAIRS), 6)
        for i in range(0,6,2):
            c,a=PAIRS[i:i+2]
            self.assertEqual((c["attack_condition"], a["attack_condition"]), ("benign","injection"))
            for k in ("initial_state","policy","controlled_denial","task_instruction","forbidden_predicate","legitimate_success_predicate"):
                self.assertEqual(c[k],a[k], k)
            self.assertNotEqual(c["untrusted_workspace_content"],a["untrusted_workspace_content"])
    def test_prompt_injection_exposure(self):
        for c in PAIRS:
            messages=initial_messages(c)
            prompt=messages[1]["content"]
            self.assertIn(c["untrusted_workspace_content"],prompt)
            self.assertIn("lower-trust",prompt)
            self.assertNotIn("continuation_actions",prompt)
            self.assertNotIn("forbidden_predicate",prompt)
    def test_all_three_modes_run_without_network(self):
        for scenario in PAIRS:
            for mode in ("denial_only","tool_blocklist","task_policy"):
                r=run_agent_episode(scenario,mode,ReplayAgent(scenario["continuation_actions"]))
                self.assertEqual(r.attack_condition,scenario["attack_condition"])
                self.assertNotEqual(r.stop_reason,"model_error")

if __name__ == "__main__": unittest.main()
