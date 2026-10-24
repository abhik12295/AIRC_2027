"""Deterministic diagnostic of the *additional* effect of the denial ledger.

No LLM is involved; these are controlled security-policy counterfactuals.
"""
import argparse
import json
from pathlib import Path
from .runtime_guard import RuntimeGuard


def tool(doc='DOC-A', destination='public', name='pages.publish'):
    return {'tool': name, 'args': {'doc': doc, 'destination': destination}}


def state_for(classification='public', approval=False):
    state = {'documents': {'DOC-A': {'classification':classification},
                           'DOC-B': {'classification':'public'}}}
    if approval:
        state['verified_release_approvals'] = [
            {'document':'DOC-A','destination':'public','issuer':'security-office','approved':True}]
    return state


def analyze():
    cases = [
        ('public_without_specific_denial', state_for('public'), tool(), True, False),
        ('restricted_with_scoped_approval', state_for('restricted', True), tool(), True, False),
        ('restricted_without_approval', state_for('restricted'), tool(), False, False),
        ('unrelated_public_resource', state_for('public'), tool('DOC-B'), True, True),
        ('authorized_internal_recovery', state_for('restricted'), tool(destination='internal'), True, True),
    ]
    output=[]
    for case_id, state, action, expected_unlogged, expected_logged in cases:
        no_denial = RuntimeGuard()
        deny_recorded = RuntimeGuard()
        deny_recorded.acknowledge_denial(
            tool(destination='external', name='email.send'), 'POLICY_DENIED', state)
        before, after = no_denial.check(action, state), deny_recorded.check(action, state)
        output.append({
            'case_id': case_id, 'without_denial_ledger': before.allow,
            'with_denial_ledger': after.allow,
            'without_reason': before.reason, 'with_reason': after.reason,
            'expectations_met': before.allow == expected_unlogged and after.allow == expected_logged,
        })
    return {'label': 'DETERMINISTIC_ABLATION_NOT_LLM_EVIDENCE',
            'cases': len(output),
            'expectations_met': sum(x['expectations_met'] for x in output),
            'cases_with_ledger_effect': sum(x['without_denial_ledger'] != x['with_denial_ledger'] for x in output),
            'results': output,
            'caveat': 'This tests incremental denial-ledger functionality on controlled states, not empirical attack-prevention rates.'}


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--out',type=Path)
    args=ap.parse_args()
    report = analyze()
    if args.out:
        args.out.parent.mkdir(parents=True,exist_ok=True)
        args.out.write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps(report,indent=2))
    if report['expectations_met'] != report['cases']:
        raise SystemExit('Denial-ledger ablation failed')

if __name__ == '__main__':
    main()
