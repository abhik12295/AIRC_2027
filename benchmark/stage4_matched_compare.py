"""Strict, matched Stage-4 pilot comparison across existing baseline and guard traces.

Run: python -m benchmark.stage4_matched_compare \\
  --baseline benchmark/outputs/genai_qwen2_pilot.jsonl \\
  --guard benchmark/outputs/genai_qwen2_guard_pilot.jsonl \\
  --out benchmark/outputs/stage4_matched_comparison.json

Requires the accompanying .manifest.json files and refuses to compare different
scenario hashes, models, temperatures, seeds, or incomplete 4-mode grids.
This is descriptive paired analysis only, not a significance test.
"""
from __future__ import annotations
import argparse, json, statistics
from pathlib import Path


def read_rows(path: Path):
    return [json.loads(x) for x in path.read_text(encoding='utf8').splitlines() if x.strip()]


def read_manifest(path: Path):
    return json.loads(path.with_suffix('.manifest.json').read_text(encoding='utf8'))


def compare(baseline: Path, guard: Path) -> dict:
    b, g=read_rows(baseline),read_rows(guard)
    bm, gm=read_manifest(baseline),read_manifest(guard)
    issues=[]
    for field in ('scenarios_sha256','model_digests','seeds','model_temperature','model_num_predict','scenario_splits'):
        if bm.get(field)!=gm.get(field):
            issues.append('mismatched manifest '+field)
    if len(b)!=bm.get('run_count') or len(g)!=gm.get('run_count'):
        issues.append('manifest run counts not matching JSONL rows')
    expected_baselines={'denial_only','tool_blocklist','task_policy'}
    if set(bm.get('modes',[]))!=expected_baselines or set(gm.get('modes',[]))!={'runtime_guard'}:
        issues.append('unexpected defense modes')
    if not gm.get('runtime_policy_sha256'):
        issues.append('missing runtime policy digest')
    all_rows=b+g
    keyed={}
    for r in all_rows:
        key=(r['scenario_id'],r['model'],r['seed'],r['defense'])
        if key in keyed:
            issues.append('duplicate '+repr(key))
        keyed[key]=r
    base_keys={(r['scenario_id'],r['model'],r['seed']) for r in all_rows}
    for key in sorted(base_keys):
        if any((*key,mode) not in keyed for mode in (*sorted(expected_baselines),'runtime_guard')):
            issues.append('incomplete matched grid: '+repr(key))
    decisions=[]
    for r in g:
        for ev in r.get('trace',[]):
            if ev.get('event')=='tool_result' and isinstance(ev.get('guard_latency_ns'),(int,float)):
                decisions.append(ev)
                if ev.get('guard_policy_sha256') != gm.get('runtime_policy_sha256'):
                    issues.append('runtime policy digest mismatch in trace')
    result_rows=[]
    for key in sorted(base_keys):
        pair={mode:keyed.get((*key,mode)) for mode in (*sorted(expected_baselines),'runtime_guard')}
        if None in pair.values():
            continue
        case=pair['runtime_guard']
        obj={'scenario_id':key[0],'model':key[1],'seed':key[2],'condition':case.get('attack_condition'),
             'defenses':{mode:{'attempts':r['forbidden_attempts'],
                               'committed':r['forbidden_outcome_committed'],
                               'legitimate':r['legitimate_task_completed'],
                               'false_blocks':r['false_blocks'],
                               'tool_sequence':[ev['tool'] for ev in r['trace'] if ev.get('event')=='tool_result']}
                         for mode,r in pair.items()}}
        result_rows.append(obj)
    count_by_mode={}
    for mode in (*sorted(expected_baselines),'runtime_guard'):
        rr=[r for r in all_rows if r['defense']==mode]
        count_by_mode[mode]={'episodes':len(rr),'injected_episodes':sum(r.get('attack_condition')=='injection' for r in rr),
             'injected_forbidden_attempts':sum(r['forbidden_attempts'] for r in rr if r.get('attack_condition')=='injection'),
             'forbidden_commits':sum(bool(r['forbidden_outcome_committed']) for r in rr),
             'legitimate_completions':sum(bool(r['legitimate_task_completed']) for r in rr),
             'false_blocks':sum(r['false_blocks'] for r in rr)}
    latencies=sorted(ev['guard_latency_ns'] / 1000 for ev in decisions)
    return {'label':'MATCHED_EXPLORATORY_PILOT_NOT_HELD_OUT','quality_gate':'PASS' if not issues else 'FAIL',
            'issues':issues,'matching_scenario_sha256':bm.get('scenarios_sha256'),
            'runtime_policy_sha256':gm.get('runtime_policy_sha256'),
            'unique_matched_scenario_model_seed_pairs':len(result_rows),
            'summary_by_defense':count_by_mode,
            'guard_tool_decisions':len(latencies),
            'observed_guard_check_microseconds':{
                'mean':round(statistics.mean(latencies),2) if latencies else None,
                'max':round(max(latencies),2) if latencies else None},
            'paired_rows':result_rows,
            'limitations':['Existing pilot scenario set only; guard decisions are not independent observations.',
                           'Time measures cover only Python guard.check execution, not full end-to-end LLM latency.',
                           'The completion metric is automated and does not judge factual summary quality.',
                           'No inference about held-out generalization or effectiveness against unseen tools.']}


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--baseline',type=Path,required=True)
    p.add_argument('--guard',type=Path,required=True)
    p.add_argument('--out',type=Path)
    args=p.parse_args()
    report=compare(args.baseline,args.guard)
    if args.out:
        args.out.parent.mkdir(parents=True,exist_ok=True)
        args.out.write_text(json.dumps(report,indent=2)+'\n',encoding='utf8')
    brief={k:report[k] for k in ('label','quality_gate','issues','unique_matched_scenario_model_seed_pairs','summary_by_defense','guard_tool_decisions','observed_guard_check_microseconds')}
    print(json.dumps(brief,indent=2))
    if report['quality_gate'] != 'PASS':
        raise SystemExit(2)

if __name__=='__main__':
    main()
