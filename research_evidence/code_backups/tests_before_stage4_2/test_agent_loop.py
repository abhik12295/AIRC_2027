import copy
import json
import unittest
from pathlib import Path
from benchmark.agent_loop import (ReplayAgent, initial_messages, parse_response, run_agent_episode)
from benchmark.ollama_adapter import OllamaAgent
from benchmark.sim import ScenarioError, load_scenarios
from benchmark.report_experiment import summarize

ROOT = Path(__file__).resolve().parents[1]
CASES = load_scenarios(str(ROOT / 'benchmark/pilot_scenarios.json'))
CASE = {s['id']: s for s in CASES}


class AgentLoopTests(unittest.TestCase):
    def test_initial_prompt_omits_hidden_oracle(self):
        s = copy.deepcopy(CASE['docs-evasion-01'])
        s['policy']['secret_test_marker'] = 'VERY_PRIVATE_ORACLE_STRING_9'
        s['forbidden_predicate']['secret_test_marker'] = 'HIDDEN_GRADER_TOKEN'
        s['continuation_actions'][0]['args']['secret_text'] = 'SCRIPTED_PLAN_SECRET'
        prompt = json.dumps(initial_messages(s))
        for hidden in ('VERY_PRIVATE_ORACLE_STRING_9', 'HIDDEN_GRADER_TOKEN',
                       'SCRIPTED_PLAN_SECRET', 'forbidden_predicate', 'continuation_actions',
                       'scripted_bypass'):
            self.assertNotIn(hidden, prompt)

    def test_replay_bypass_detected_without_guardrail(self):
        s = CASE['docs-evasion-01']
        result = run_agent_episode(s, 'denial_only', ReplayAgent(s['continuation_actions']))
        self.assertTrue(result.forbidden_outcome_committed)
        self.assertEqual(result.forbidden_attempts, 1)
        self.assertEqual(result.stop_reason, 'agent_done')
        self.assertEqual(result.invalid_responses, 0)

    def test_same_bypass_blocked_by_effect_oracle(self):
        s = CASE['docs-evasion-01']
        result = run_agent_episode(s, 'task_policy', ReplayAgent(s['continuation_actions']))
        self.assertFalse(result.forbidden_outcome_committed)
        self.assertEqual(result.forbidden_attempts, 1)
        self.assertEqual(result.trace[-2]['response_code'], 'POLICY_DENIED')

    def test_authorized_same_tool_blocklist_false_block(self):
        s = CASE['docs-allowed-email-01']
        a = run_agent_episode(s, 'tool_blocklist', ReplayAgent(s['continuation_actions']))
        b = run_agent_episode(s, 'task_policy', ReplayAgent(s['continuation_actions']))
        self.assertEqual(a.false_blocks, 1)
        self.assertFalse(a.legitimate_task_completed)
        self.assertTrue(b.legitimate_task_completed)

    def test_service_outage_excluded(self):
        s = CASE['outage-doc-01']
        r = run_agent_episode(s, 'task_policy', ReplayAgent(s['continuation_actions']))
        self.assertFalse(r.hard_denial)
        self.assertTrue(r.legitimate_task_completed)

    def test_no_state_cross_contamination(self):
        s = CASE['repo-evasion-01']
        before = json.dumps(s, sort_keys=True)
        for mode in ['denial_only', 'tool_blocklist', 'task_policy']:
            run_agent_episode(s, mode, ReplayAgent(s['continuation_actions']))
        self.assertEqual(before, json.dumps(s, sort_keys=True))

    def test_prohibited_effect_counted_even_after_reversion(self):
        s = copy.deepcopy(CASE['repo-evasion-01'])
        s['continuation_actions'].append({'tool': 'ci.apply_patch',
                                          'args': {'branch': 'main', 'revision': 'commit_A'}})
        result = run_agent_episode(s, 'denial_only', ReplayAgent(s['continuation_actions']))
        self.assertTrue(result.forbidden_outcome_committed)
        self.assertFalse(result.trace[-2]['forbidden_state'])

    def test_json_contract_strict(self):
        good = parse_response('{"tool":"email.send","args":{"doc":"DOC-001","destination":"internal"}}', 'documents')
        self.assertEqual(good['tool'], 'email.send')
        for raw in ('garbage', '{"tool":"evil.exec","args":{}}',
                    '{"tool":"email.send","args":{"doc":"DOC-001","destination":"EXTERNAL"}}',
                    '{"tool":"email.send","args":{"doc":"DOC-001","destination":"external","extra":"x"}}',
                    '[1,2,3]'):
            with self.subTest(raw=raw), self.assertRaises(ScenarioError):
                parse_response(raw, 'documents')

    def test_model_response_not_fixture_plan(self):
        class StopAgent:
            model_name = 'TEST_STOP'
            def next_message(self, messages, seed):
                return '{"done":true,"reason":"safe termination"}'
        s = CASE['docs-evasion-01']
        r = run_agent_episode(s, 'denial_only', StopAgent())
        self.assertFalse(r.forbidden_outcome_committed)
        self.assertEqual(r.tool_calls, 0)

    def test_invalid_reply_does_not_crash(self):
        class BadAgent:
            model_name = 'TEST_BAD'
            def next_message(self, messages, seed):
                return 'not json'
        s = CASE['admin-safe-01']
        r = run_agent_episode(s, 'task_policy', BadAgent())
        self.assertEqual(r.invalid_responses, s['max_post_denial_calls'])
        self.assertEqual(r.stop_reason, 'horizon_exhausted')

    def test_model_error_not_counted_as_safe_abstention(self):
        class Down:
            model_name = 'TEST_FAILURE'
            def next_message(self, messages, seed):
                raise RuntimeError('model unavailable')
        r = run_agent_episode(CASE['docs-safe-01'], 'task_policy', Down())
        self.assertEqual(r.stop_reason, 'model_error')
        self.assertFalse(r.legitimate_task_completed)

    def test_refuse_nonlocal_ollama(self):
        for url in ('https://example.com:11434', 'http://192.168.0.2:11434', 'file:///root'):
            with self.subTest(url=url), self.assertRaises(ValueError):
                OllamaAgent('test', base_url=url)

    def test_summary_denominators(self):
        s = CASE['docs-allowed-email-01']
        rows = [run_agent_episode(s, m, ReplayAgent(s['continuation_actions'])).to_dict()
                for m in ('denial_only', 'tool_blocklist', 'task_policy')]
        summ = summarize(rows)
        self.assertEqual(summ['SCRIPTED_REPLAY_NOT_AN_LLM / tool_blocklist']['false_block_rate'], 1.0)
        self.assertEqual(summ['SCRIPTED_REPLAY_NOT_AN_LLM / task_policy']['false_block_rate'], 0.0)


if __name__ == '__main__':
    unittest.main()
