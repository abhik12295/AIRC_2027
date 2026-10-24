import json
from pathlib import Path
import unittest
from benchmark.compare_defenses import summarize
from benchmark.audit_trajectories import audit
from benchmark.runtime_guard import RuntimeGuard

class Stage4AnalysisTests(unittest.TestCase):
    def test_incomplete_grid_is_rejected(self):
        scenario = {'id': 'a', 'attack_variant': 'example'}
        manifest = {'scenarios_sha256': 'abc', 'run_count': 0, 'seeds': [42],
                    'modes': ['runtime_guard'], 'model_digests': {'test': 'x'}, 'kind': 'ENGINEERING_REPLAY'}
        result = summarize([scenario], [], manifest, 'abc')
        self.assertEqual('FAIL', result['quality_gate'])
        self.assertTrue(any('incomplete experiment grid' in x for x in result['issues']))

    def test_invalid_policy_digest_fails_audit(self):
        root = Path(__file__).resolve().parents[1]
        scenarios = json.loads((root/'research_evidence/stage3_2/real_document_pairs.json').read_text())
        scenario = scenarios[0]
        doc = next(iter(scenario['initial_state']['documents'].values()))
        import hashlib
        note=scenario['untrusted_workspace_content']
        payload='BEGIN AUTHENTIC SOURCE EXCERPT\n'+doc['content']+'\nEND AUTHENTIC SOURCE EXCERPT'
        payload+='\nBEGIN SYNTHETIC COLLABORATOR NOTE (UNTRUSTED; NOT FROM SOURCE)\n'+note+'\nEND SYNTHETIC COLLABORATOR NOTE'
        h=hashlib.sha256(payload.encode()).hexdigest()
        row={'scenario_id':scenario['id'], 'attack_condition':'benign', 'defense':'runtime_guard',
             'forbidden_attempts':0, 'forbidden_outcome_committed':False, 'legitimate_task_completed':False,
             'invalid_responses':0, 'stop_reason':'agent_done',
             'trace':[{'event':'imposed_denial','state_hash_before':'a','state_hash_after':'a','effect_committed':False},
                      {'event':'tool_result','tool':'documents.read','response_code':'OK','valid_action':True,
                       'oracle_forbidden':False,'forbidden_state':False,'read_payload_sha256':h,
                       'guard_policy_sha256':'wrong', 'guard_reason':'allowed', 'guard_effect':'read'}]}
        report=audit([row],[scenario],manifest={'runtime_policy_sha256':RuntimeGuard().policy_sha256,
                              'modes':['runtime_guard'],'run_count':1, 'scenario_count':1,
                              'scenarios_sha256':'abc'}, actual_scenarios_sha='abc')
        self.assertEqual('FAIL', report['quality_gate'])
        self.assertTrue(any('Runtime policy digest mismatch' in x for x in report['issues']))

if __name__=='__main__':unittest.main()
