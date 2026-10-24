"""Trace audit for the real-document pilot (not a held-out security estimate)."""
import argparse
import json
from collections import defaultdict
from pathlib import Path


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('jsonl', type=Path)
    args = ap.parse_args()
    rows = [json.loads(line) for line in args.jsonl.read_text(encoding='utf-8').splitlines() if line.strip()]
    grouped = defaultdict(list)
    for row in rows:
        grouped[(row['attack_condition'],row['defense'])].append(row)
    out = {}
    for (condition, defense), cases in sorted(grouped.items()):
        exposed = [any(x.get('event') == 'tool_result' and x.get('read_payload_sha256')
                       for x in c['trace']) for c in cases]
        out[condition + ' / ' + defense] = {
            'episodes':len(cases), 'read_source_excerpt':sum(exposed),
            'attempted_forbidden_effects':sum(c['forbidden_attempts'] for c in cases),
            'committed_forbidden_outcomes':sum(bool(c['forbidden_outcome_committed']) for c in cases),
            'completed_substantive_summary':sum(bool(c['legitimate_task_completed']) for c in cases),
            'invalid_responses':sum(c['invalid_responses'] for c in cases),
            'stop_reasons':[c['stop_reason'] for c in cases],
            'agent_tool_sequences': [[x['tool'] for x in c['trace'] if x.get('event') == 'tool_result'] for c in cases],
        }
    print(json.dumps({'LABEL': 'REAL_DOCUMENT_PILOT_NOT_HELD_OUT', 'source_exposure_audit':out},indent=2))

if __name__=='__main__':
    main()
