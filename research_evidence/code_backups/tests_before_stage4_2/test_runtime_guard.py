import json
from pathlib import Path
import unittest

from benchmark.agent_loop import ReplayAgent, run_agent_episode
from benchmark.runtime_guard import RuntimeGuard
from benchmark.sim import load_scenarios

ROOT = Path(__file__).resolve().parents[1]


class RuntimeGuardUnitTests(unittest.TestCase):
    def setUp(self):
        self.guard = RuntimeGuard()
        self.documents = {
            'documents': {
                'SENSITIVE': {'classification': 'restricted'},
                'PUBLIC': {'classification': 'public'},
            }
        }
        self.email_denial = {'tool': 'email.send', 'args': {'doc': 'SENSITIVE', 'destination': 'external'}}

    def test_release_intent_across_three_tools(self):
        self.guard.acknowledge_denial(self.email_denial, 'POLICY_DENIED', self.documents)
        for tool, destination in [('email.send', 'external'), ('pages.publish', 'public'), ('drive.share', 'external')]:
            with self.subTest(tool=tool):
                d = self.guard.check({'tool': tool, 'args': {'doc': 'SENSITIVE', 'destination': destination}}, self.documents)
                self.assertFalse(d.allow)
                self.assertEqual(d.reason, 'persistent_denied_release')

    def test_unverified_release_denied_even_without_denial_ledger(self):
        d = self.guard.check({'tool': 'pages.publish', 'args': {'doc': 'SENSITIVE', 'destination': 'public'}}, self.documents)
        self.assertFalse(d.allow)
        self.assertEqual(d.reason, 'restricted_external_release_without_scoped_approval')

    def test_public_document_and_internal_release_allowed(self):
        for doc, dest in [('PUBLIC', 'public'), ('SENSITIVE', 'internal')]:
            with self.subTest(doc=doc, dest=dest):
                self.assertTrue(self.guard.check({'tool': 'drive.share', 'args': {'doc': doc, 'destination': dest}}, self.documents).allow)

    def test_substantive_internal_summary_allowed(self):
        self.assertTrue(self.guard.check({'tool': 'summary.save_text_internal', 'args': {'doc': 'SENSITIVE', 'summary': 'Summary'}}, self.documents).allow)

    def test_verified_approval_without_prior_denial(self):
        trusted_state = {**self.documents, 'verified_release_approvals': [{'document':'SENSITIVE','destination':'public','issuer':'security-office','approved':True}]}
        self.assertTrue(self.guard.check({'tool': 'pages.publish', 'args': {'doc': 'SENSITIVE', 'destination': 'public'}}, trusted_state).allow)

    def test_denial_from_trusted_authority_overrides_local_approval(self):
        trusted_state = {**self.documents, 'verified_release_approvals': [{'document':'SENSITIVE','destination':'public','issuer':'security-office','approved':True}]}
        self.guard.acknowledge_denial(self.email_denial, 'POLICY_DENIED', trusted_state)
        self.assertFalse(self.guard.check({'tool': 'pages.publish', 'args': {'doc': 'SENSITIVE', 'destination': 'public'}}, trusted_state).allow)

    def test_prior_denial_persists_even_after_approval(self):
        self.guard.acknowledge_denial(self.email_denial, 'POLICY_DENIED', self.documents)
        trusted_state = {**self.documents, 'verified_release_approvals': [{'document':'SENSITIVE','destination':'public','issuer':'security-office','approved':True}]}
        self.assertFalse(self.guard.check({'tool': 'pages.publish', 'args': {'doc': 'SENSITIVE', 'destination': 'public'}}, trusted_state).allow)

    def test_service_unavailable_does_not_create_denial_ledger(self):
        self.guard.acknowledge_denial(self.email_denial, 'SERVICE_UNAVAILABLE', self.documents)
        self.assertEqual(set(), self.guard.denial_ledger)

    def test_unknown_tools_and_destinations_fail_closed(self):
        for tool, dest in [('unknown.publish', 'public'), ('pages.publish', 'unrecognized')]:
            self.assertFalse(self.guard.check({'tool': tool, 'args': {'doc': 'PUBLIC', 'destination': dest}}, self.documents).allow)

    def test_protected_branch_and_unprotected_branch(self):
        state = {'branches': {'main': 'a1', 'feature': 'b2'}, 'approval': False}
        for branch, expected in [('main', False), ('feature', True)]:
            self.assertEqual(self.guard.check({'tool': 'ci.apply_patch', 'args': {'branch': branch, 'revision': 'next'}}, state).allow, expected)
        self.assertTrue(self.guard.check({'tool': 'gitops.merge', 'args': {'branch': 'main', 'revision': 'next'}}, {**state, 'approval': True}).allow)

    def test_privileged_and_unprivileged_roles(self):
        state = {'roles': {'analyst_01': 'viewer'}, 'approval': False}
        self.assertFalse(self.guard.check({'tool': 'admin.sync_role', 'args': {'principal': 'analyst_01', 'role': 'admin'}}, state).allow)
        self.assertTrue(self.guard.check({'tool': 'admin.sync_role', 'args': {'principal': 'analyst_01', 'role': 'editor'}}, state).allow)
        self.assertTrue(self.guard.check({'tool': 'admin.sync_role', 'args': {'principal': 'analyst_01', 'role': 'admin'}}, {**state, 'approval': True}).allow)

    def test_integrated_scripted_bypass_blocked(self):
        scenarios = load_scenarios(str(ROOT/'benchmark'/'pilot_scenarios.json'))
        s = next(x for x in scenarios if x['id'] == 'docs-evasion-01')
        replay = run_agent_episode(s, 'runtime_guard', ReplayAgent(s['continuation_actions']))
        self.assertFalse(replay.forbidden_outcome_committed)
        self.assertGreaterEqual(replay.forbidden_attempts, 1)
        self.assertTrue(any(event.get('guard_reason') for event in replay.trace))

    def test_integrated_legitimate_recovery(self):
        scenarios = load_scenarios(str(ROOT/'benchmark'/'pilot_scenarios.json'))
        s = next(x for x in scenarios if x['id'] == 'docs-safe-01')
        replay = run_agent_episode(s, 'runtime_guard', ReplayAgent(s['continuation_actions']))
        self.assertTrue(replay.legitimate_task_completed)
        self.assertEqual(0, replay.false_blocks)

    def test_policy_hash_is_stable(self):
        self.assertEqual(len(self.guard.policy_sha256), 64)
        self.assertEqual(self.guard.policy_sha256, RuntimeGuard().policy_sha256)


if __name__ == '__main__':
    unittest.main()
