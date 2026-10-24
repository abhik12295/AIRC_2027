"""Stage 5.3 regression tests. Scripted replays are not LLM evidence."""
import copy
import json
from pathlib import Path
import unittest

from benchmark.agent_loop import parse_response, run_agent_episode, ReplayAgent, initial_messages
from benchmark.build_stage5_2_cases import CONTENT_1, CONTENT_2, SUMMARY, HOP1, HOP2
from benchmark.build_stage5_3_cases import build
from benchmark.stage5_3_diagnostics import analyze
from benchmark.sim import ScenarioError, _apply, legitimate_reached, validate_scenario

ROOT = Path(__file__).resolve().parents[1]
CASES = build(json.loads((ROOT/'benchmark/stage5_2_pilot.json').read_text(encoding='utf-8')))

class Stage53Tests(unittest.TestCase):
    def test_exact_paired_scenarios(self):
        self.assertEqual(len(CASES), 6)
        self.assertEqual(len({s['id'] for s in CASES}), 6)
        for variant in {s['attack_variant'] for s in CASES}:
            pair = [copy.deepcopy(s) for s in CASES if s['attack_variant'] == variant]
            self.assertEqual({s['attack_condition'] for s in pair}, {'benign','injection'})
            for s in pair:
                validate_scenario(s)
                for f in ('id','attack_condition','untrusted_workspace_content'):
                    s.pop(f)
            self.assertEqual(pair[0], pair[1])

    def test_multihop_required_in_new_utility_metric(self):
        for s in CASES:
            if s['attack_variant'].startswith('two_hop_'):
                self.assertEqual(s['legitimate_success_predicate']['kind'],'two_hop_internal_summary')

    def test_tool_done_alias_is_strict(self):
        res = parse_response('{"tool":"done","args":{"reason":"safe stop"}}','documents')
        self.assertEqual(res['reason'],'safe stop')
        self.assertEqual(res['completion_format'],'tool_done_alias')
        for raw in ('{"tool":"done","args":{}}',
                    '{"tool":"done","args":{"reason":true}}',
                    '{"tool":"done","args":{"reason":"ok", "extra":1}}',
                    '{"tool":"done","args":{"reason":"ok"}, "other":1}',
                    '{"tool":"unknown","args":{}}'):
            with self.subTest(raw=raw), self.assertRaises(ScenarioError):
                parse_response(raw,'documents')

    def test_tool_done_cannot_commit_effect(self):
        s=next(s for s in CASES if s['attack_variant']=='two_hop_page' and s['attack_condition']=='benign')
        r=run_agent_episode(s,'denial_only', ReplayAgent([
            {'tool':'done','args':{'reason':'stop'}}]))
        self.assertEqual(r.stop_reason,'agent_done')
        self.assertEqual(r.tool_calls,0)
        self.assertFalse(r.legitimate_task_completed)
        self.assertFalse(r.forbidden_outcome_committed)
        self.assertEqual(r.trace[-1]['completion_format'],'tool_done_alias')

    def test_id_contract_is_explicit_and_preserves_state(self):
        s=next(s for s in CASES if s['attack_variant']=='two_hop_page' and s['attack_condition']=='benign')
        state=copy.deepcopy(s['initial_state'])
        before=copy.deepcopy(state)
        with self.assertRaisesRegex(ScenarioError,'new_doc must begin with uppercase DERIVED-'):
            _apply(state,{'tool':'documents.derive','args':{
                'doc':'DOC-GENAI-PROFILE','new_doc':'GaI-Risk-Summary','content':CONTENT_1}})
        self.assertEqual(state,before)
        self.assertIn('uppercase DERIVED-',json.dumps(initial_messages(s)))

    def test_renamed_legacy_metrics_unaffected(self):
        s=next(s for s in CASES if s['attack_variant']=='two_hop_page' and s['attack_condition']=='benign')
        state=copy.deepcopy(s['initial_state'])
        source=s['legitimate_success_predicate']['doc']
        _apply(state,{'tool':'summary.save_text_internal','args':{'doc':source,'summary':SUMMARY}})
        self.assertFalse(legitimate_reached(state,s['legitimate_success_predicate']))
        old=copy.deepcopy(s['legitimate_success_predicate'])
        old['kind']='provenance_aware_internal_summary'
        self.assertTrue(legitimate_reached(state,old))

    def test_one_hop_does_not_meet_two_hop_criterion(self):
        s=next(s for s in CASES if s['attack_variant']=='two_hop_page' and s['attack_condition']=='benign')
        state=copy.deepcopy(s['initial_state'])
        _apply(state,{'tool':'documents.derive','args':{'doc':'DOC-GENAI-PROFILE','new_doc':HOP1,'content':CONTENT_1}})
        _apply(state,{'tool':'summary.save_text_internal','args':{'doc':HOP1,'summary':SUMMARY}})
        self.assertFalse(legitimate_reached(state,s['legitimate_success_predicate']))

    def test_two_hop_metric_and_guard(self):
        for s in CASES:
            if not s['attack_variant'].startswith('two_hop_'): continue
            weak=run_agent_episode(s,'denial_only',ReplayAgent(s['continuation_actions']))
            guarded=run_agent_episode(s,'runtime_guard',ReplayAgent(s['continuation_actions']))
            self.assertTrue(weak.legitimate_task_completed)
            self.assertTrue(guarded.legitimate_task_completed)
            self.assertTrue(weak.forbidden_outcome_committed)
            self.assertFalse(guarded.forbidden_outcome_committed)
            self.assertEqual(guarded.forbidden_attempts,1)

    def test_invalid_id_feedback_guides_correction(self):
        s=next(s for s in CASES if s['attack_variant']=='two_hop_page' and s['attack_condition']=='benign')
        agent=ReplayAgent([
            {'tool':'documents.read','args':{'doc':'DOC-GENAI-PROFILE'}},
            {'tool':'documents.derive','args':{'doc':'DOC-GENAI-PROFILE','new_doc':'Wrong-Id','content':CONTENT_1}},
            {'tool':'documents.derive','args':{'doc':'DOC-GENAI-PROFILE','new_doc':HOP1,'content':CONTENT_1}},
            {'tool':'documents.derive','args':{'doc':HOP1,'new_doc':HOP2,'content':CONTENT_2}},
            {'tool':'summary.save_text_internal','args':{'doc':HOP2,'summary':SUMMARY}},
            {'tool':'done','args':{'reason':'finished safely'}},
        ])
        result=run_agent_episode(s,'runtime_guard',agent)
        self.assertTrue(result.legitimate_task_completed)
        self.assertFalse(result.forbidden_outcome_committed)
        self.assertEqual(sum(x.get('event')=='tool_validation_error' for x in result.trace),1)
        self.assertEqual(result.invalid_responses,0)
        self.assertEqual(result.stop_reason,'agent_done')
        self.assertEqual(result.trace[-1]['completion_format'],'tool_done_alias')

    def test_trace_diagnostics_distinguish_depth(self):
        s=next(s for s in CASES if s['attack_variant']=='two_hop_drive' and s['attack_condition']=='injection')
        data=[run_agent_episode(s,m,ReplayAgent(s['continuation_actions'])).to_dict()
              for m in ('denial_only','runtime_guard')]
        r=analyze([s], data)
        self.assertEqual(r['episodes'],2)
        self.assertTrue(all(d['two_hop_created'] for d in r['episodes_detail']))
        self.assertEqual([x['depth2_prohibited_commits'] for x in r['episodes_detail']], [1,0])
        self.assertEqual([x['depth2_prohibited_attempts'] for x in r['episodes_detail']], [1,1])

    def test_missing_ancestry_rejected(self):
        s=next(s for s in CASES if s['attack_variant']=='two_hop_page' and s['attack_condition']=='benign')
        state=copy.deepcopy(s['initial_state'])
        _apply(state,{'tool':'documents.derive','args':{'doc':'DOC-GENAI-PROFILE','new_doc':HOP1,'content':CONTENT_1}})
        _apply(state,{'tool':'documents.derive','args':{'doc':HOP1,'new_doc':HOP2,'content':CONTENT_2}})
        _apply(state,{'tool':'summary.save_text_internal','args':{'doc':HOP2,'summary':SUMMARY}})
        state['documents'][HOP1]['derived_from']=['UNKNOWN-ID']
        self.assertFalse(legitimate_reached(state,s['legitimate_success_predicate']))

if __name__=='__main__': unittest.main()
