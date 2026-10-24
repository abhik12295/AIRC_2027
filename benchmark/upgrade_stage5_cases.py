"""Create versioned Stage 5.1 pilot scenarios without changing visible tasks.

Changes only trusted scoring metadata and scenario IDs/regime. Existing
pilot traces remain immutable and must not be re-labelled as confirmatory.
"""
from __future__ import annotations
import argparse
from copy import deepcopy
import json
from pathlib import Path
from .sim import validate_scenario


def upgrade(rows: list[dict]) -> list[dict]:
    if not isinstance(rows, list) or not rows:
        raise ValueError("expected a nonempty list of Stage 5 pilot scenarios")
    output = []
    for item in rows:
        if item.get("regime") != "stage5_derived_document_pilot":
            raise ValueError("not a Stage 5 derived-document scenario")
        if item.get("legitimate_success_predicate", {}).get("kind") != "substantive_internal_summary":
            raise ValueError("expected the historical strict source-ID success predicate")
        s = deepcopy(item)
        s["id"] = s["id"].replace("stage5-", "stage5v51-", 1)
        if s["id"] == item["id"]:
            raise ValueError("unexpected Stage 5 scenario ID")
        s["regime"] = "stage5_1_derived_document_pilot"
        s["legitimate_success_predicate"]["kind"] = "provenance_aware_internal_summary"
        # The LLM-facing task_instruction, sources, lower-trust payload, and
        # tool set remain byte-for-byte unchanged.
        validate_scenario(s)
        output.append(s)
    if len({s["id"] for s in output}) != len(output):
        raise ValueError("duplicate versioned scenario IDs")
    return output


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--input', type=Path, default=Path('benchmark/stage5_derived_pilot.json'))
    p.add_argument('--out', type=Path, default=Path('benchmark/stage5_1_derived_pilot.json'))
    a = p.parse_args(argv)
    if a.input.resolve() == a.out.resolve():
        p.error('refusing to overwrite original scenarios')
    old = json.loads(a.input.read_text(encoding='utf-8'))
    rows = upgrade(old)
    a.out.parent.mkdir(parents=True,exist_ok=True)
    if a.out.exists():
        p.error('output exists; choose a new versioned filename')
    a.out.write_text(json.dumps(rows,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    print(json.dumps({
        'status':'prepared', 'label':'EXPLORATORY_PILOT_NOT_HELD_OUT',
        'scoring':'provenance_aware_internal_summary',
        'scenarios':len(rows), 'out':str(a.out),
        'historical_results_unchanged':True,
        'note':'Scoring definition was revised after observing Stage 5 pilot outcomes; exploratory only.'
    },indent=2))

if __name__ == '__main__':
    main()
