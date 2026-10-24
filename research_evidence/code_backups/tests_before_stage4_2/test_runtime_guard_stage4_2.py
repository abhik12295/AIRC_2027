"""Security regression checks added after the Stage 4.1 stress finding."""
import unittest
from benchmark.runtime_guard import RuntimeGuard
from benchmark.stage4_guard_stress import evaluate, grant


def release(doc='A', dest='public'):
    return {'tool':'pages.publish', 'args':{'doc':doc,'destination':dest}}


class Stage42GuardTests(unittest.TestCase):
    def test_full_stress_contract(self):
        r = evaluate()
        self.assertGreaterEqual(r['cases'], 37)
        self.assertEqual(0, r['security_expectation_mismatches'])

    def test_malformed_approval_types_not_accepted(self):
        for bad in ['true', 1, {}, None]:
            with self.subTest(value=bad):
                state = {'documents': {'A': {'classification':'restricted'}},
                         'verified_release_approvals': [grant(doc='A', approved=bad)]}
                self.assertFalse(RuntimeGuard().check(release(), state).allow)

    def test_denial_effect_scoped_to_source_and_descendants(self):
        state = {'documents': {
            'A': {'classification':'public'},
            'DERIVED': {'classification':'public', 'derived_from':['A']},
            'B': {'classification':'public'},
        }}
        guard = RuntimeGuard()
        self.assertTrue(guard.check(release('DERIVED'), state).allow)
        guard.acknowledge_denial({'tool':'email.send','args':{'doc':'A','destination':'external'}},
                                 'POLICY_DENIED', state)
        self.assertFalse(guard.check(release('DERIVED'), state).allow)
        self.assertTrue(guard.check(release('B'), state).allow)
        self.assertTrue(guard.check(release('DERIVED','internal'), state).allow)

    def test_approval_resource_and_destination_scoping(self):
        state = {'documents': {'A': {'classification':'restricted'},
                               'B': {'classification':'restricted'}},
                 'verified_release_approvals': [grant(doc='A', dest='public')]}
        self.assertTrue(RuntimeGuard().check(release('A'), state).allow)
        self.assertFalse(RuntimeGuard().check(release('A','external'), state).allow)
        self.assertFalse(RuntimeGuard().check(release('B'), state).allow)

    def test_dag_is_not_mistaken_for_cycle(self):
        state = {'documents': {
            'A': {'classification':'public'},
            'B': {'classification':'public', 'derived_from':['A']},
            'C': {'classification':'public', 'derived_from':['A']},
            'D': {'classification':'public', 'derived_from':['B','C']},
        }}
        self.assertTrue(RuntimeGuard().check(release('D'), state).allow)
        state['documents']['A']['derived_from'] = ['D']
        self.assertFalse(RuntimeGuard().check(release('D'), state).allow)

    def test_legacy_boolean_does_not_authorize(self):
        state = {'documents': {'A': {'classification':'restricted'}},
                 'verified_release_approval': True}
        self.assertFalse(RuntimeGuard().check(release(), state).allow)


if __name__ == '__main__':
    unittest.main()
