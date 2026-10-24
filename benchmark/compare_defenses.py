"""Paired, descriptive Stage-4 experiment comparison (never statistical inference)."""
from __future__ import annotations
import argparse
from collections import defaultdict
from hashlib import sha256
import json
from pathlib import Path


def summarize(scenarios: list[dict], rows: list[dict], manifest: dict, raw_sha256: str) -> dict:
    scenario_by_id = {s['id']: s for s in scenarios}
    issues = []
    if manifest.get('scenarios_sha256') != raw_sha256:
        issues.append('scenario hash differs from manifest')
    if len(rows) != manifest.get('run_count'):
        issues.append('run count differs from manifest')
    grouped = defaultdict(list)
    seen = set()
    for r in rows:
        key = (r['scenario_id'], r['model'], r['seed'], r['defense'])
        if key in seen:
            issues.append(f'duplicate run {key}')
        seen.add(key)
        s = scenario_by_id.get(r['scenario_id'])
        if s is None:
            issues.append(f'unknown scenario {r["scenario_id"]}')
            continue
        variant = s.get('attack_variant', 'default')
        grouped[(r['model'], variant, r['attack_condition'], r['defense'])].append(r)
    expected = {(s['id'], model, seed, mode)
                for s in scenarios
                for model in manifest.get('model_digests', {})
                for seed in manifest['seeds']
                for mode in manifest['modes']}
    if seen != expected:
        issues.append(f'incomplete experiment grid: missing {len(expected-seen)}, extra {len(seen-expected)}')
    summary = []
    for (model, variant, condition, defense), items in sorted(grouped.items()):
        delays = [e['guard_latency_ns']/1000 for r in items for e in r.get('trace', [])
                  if e.get('event') == 'tool_result' and e.get('valid_action')
                  and isinstance(e.get('guard_latency_ns'), (int, float))]
        summary.append({
            'model': model, 'variant': variant, 'condition': condition, 'defense': defense,
            'episodes': len(items), 'forbidden_attempts': sum(r['forbidden_attempts'] for r in items),
            'forbidden_commits': sum(bool(r['forbidden_outcome_committed']) for r in items),
            'legitimate_completions': sum(bool(r['legitimate_task_completed']) for r in items),
            'false_blocks': sum(r['false_blocks'] for r in items),
            'invalid_responses': sum(r['invalid_responses'] for r in items),
            'guard_decisions': len(delays),
            'mean_guard_latency_microseconds': round(sum(delays)/len(delays), 2) if delays else None,
        })
    return {'label': manifest['kind'], 'quality_gate': 'PASS' if not issues else 'FAIL',
            'issues': issues, 'paired_rows': summary,
            'caveat': 'Exploratory paired scenarios, not independent incidents or population rates; runtime_guard is an explicit rule-based engineering baseline.'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--scenarios', type=Path, required=True)
    parser.add_argument('--traces', type=Path, required=True)
    parser.add_argument('--manifest', type=Path)
    parser.add_argument('--out', type=Path)
    a = parser.parse_args()
    cases = json.loads(a.scenarios.read_text(encoding='utf-8'))
    rows = [json.loads(line) for line in a.traces.read_text(encoding='utf-8').splitlines() if line.strip()]
    manifest_path = a.manifest or a.traces.with_suffix('.manifest.json')
    manifest = json.loads(manifest_path.read_text(encoding='utf-8'))
    report = summarize(cases, rows, manifest, sha256(a.scenarios.read_bytes()).hexdigest())
    raw = json.dumps(report, indent=2, ensure_ascii=False)
    if a.out:
        a.out.parent.mkdir(parents=True, exist_ok=True)
        a.out.write_text(raw + '\n', encoding='utf-8')
    print(raw)
    if report['quality_gate'] != 'PASS':
        raise SystemExit(2)


if __name__ == '__main__':
    main()
