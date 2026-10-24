"""Diagnose cross-seed diversity on an EXISTING exploratory pilot, not heldout.

This does not guarantee independent samples; it flags fully identical observed
trajectories before a frozen evaluation is started.
"""
from __future__ import annotations
import argparse
from collections import defaultdict
import json
from pathlib import Path


def inspect(rows: list[dict]) -> dict:
    groups=defaultdict(dict)
    for row in rows:
        key=(row['model'],row['scenario_id'],row['defense'])
        # Hash sequence of model outputs, not only simulator outcomes. Variation
        # in drafts/wording can occur even if the tool-effect score is unchanged.
        outputs=tuple((e.get('model_output') or {}).get('sha256') for e in row['trace']
            if isinstance(e.get('model_output'),dict))
        if row['seed'] in groups[key]:
            raise ValueError(f'Duplicate model/scenario/defense/seed: {key}')
        groups[key][row['seed']]=outputs
    summary={}
    for model in sorted({k[0] for k in groups}):
        cases=[r for k,r in groups.items() if k[0]==model]
        at_least_two=[c for c in cases if len(c)>=2]
        variable=sum(len(set(c.values()))>1 for c in at_least_two)
        summary[model]={
            'compared_groups':len(at_least_two),
            'groups_with_cross_seed_output_variation':variable,
            'groups_identical_across_seeds':len(at_least_two)-variable,
            'some_variation_observed':variable>0,
        }
    return {'kind':'DEVELOPMENT_SAMPLING_SMOKE_NOT_HELD_OUT',
            'per_model':summary,
            'can_confirm_variation_for_each_model':bool(summary) and all(
                 g['some_variation_observed'] for g in summary.values()),
            'warning':'Seed diversity is not statistical independence; actual trajectory distribution depends on prompt and Ollama implementation.'}


def main(argv=None):
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('traces',type=Path)
    p.add_argument('--require-variation',action='store_true')
    args=p.parse_args(argv)
    rows=[json.loads(line) for line in args.traces.read_text(encoding='utf-8').splitlines() if line.strip()]
    result=inspect(rows)
    print(json.dumps(result,indent=2))
    if args.require_variation and not result['can_confirm_variation_for_each_model']:
        raise SystemExit(2)

if __name__=='__main__':main()
