"""Stage5.6 offline Ollama runner, hash-locked and non-overwriting.

Adds stateless_guard in a SEPARATE agent module without changing frozen Stage5.5B
code. No real APIs, emails, pages or cloud services are invoked by the agent.
"""
from __future__ import annotations
import argparse
from datetime import datetime,timezone
from hashlib import sha256
import json
from pathlib import Path
from .ollama_adapter import OllamaAgent
from .stage5_6_agent_loop import run_agent_episode,ReplayAgent
from .stage5_6_protocol import (MODELS,MODES,SEEDS,SAMPLING,ROOT,hash_file,
                                validate_dataset)


def main(argv=None):
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--backend',choices=['ollama','replay'],default='ollama')
    p.add_argument('--scenarios',type=Path,default=Path('benchmark/stage5_6_multisource.json'))
    p.add_argument('--data-dir',type=Path,default=Path('data'))
    p.add_argument('--frozen-protocol',type=Path)
    p.add_argument('--max-scenarios',type=int)
    p.add_argument('--models',nargs='+',default=MODELS)
    p.add_argument('--modes',nargs='+',choices=MODES,default=MODES)
    p.add_argument('--seeds',type=int,nargs='+',default=SEEDS)
    p.add_argument('--temperature',type=float,default=SAMPLING['temperature'])
    p.add_argument('--num-predict',type=int,default=SAMPLING['num_predict'])
    p.add_argument('--ollama-url',default='http://127.0.0.1:11434')
    p.add_argument('--timeout',type=int,default=180)
    p.add_argument('--out',type=Path,required=True)
    a=p.parse_args(argv)
    cases=json.loads(a.scenarios.read_text(encoding='utf-8'))
    if a.backend=='ollama':
        if a.frozen_protocol is None or a.max_scenarios is not None:
            raise ValueError('LLM evaluation needs complete dataset and frozen protocol')
        lock=json.loads(a.frozen_protocol.read_text(encoding='utf-8'))
        if lock.get('status')!='PROJECT_FROZEN_NOT_EXTERNALLY_PREREGISTERED' or lock.get('version')!='stage5.6-supplementary-v1':
            raise ValueError('Incorrect Stage5.6 project lock')
        if hash_file(a.scenarios)!=lock['dataset_sha256'] or len(cases)!=lock['scenario_count']:
            raise ValueError('Dataset fingerprint or count mismatch')
        if (a.models!=lock['models'] or a.modes!=lock['defenses'] or a.seeds!=lock['seeds'] or
            dict(temperature=a.temperature,num_predict=a.num_predict)!=lock['sampling']):
            raise ValueError('Frozen models/defenses/seeds/sampling mismatch')
        for f,expected in lock['code_sha256'].items():
            if hash_file(ROOT/f)!=expected:raise ValueError(f'Frozen code fingerprint mismatch: {f}')
        if validate_dataset(cases,a.data_dir)!=lock['pdf_by_publisher']:
            raise ValueError('PDF provenance drift')
        provenance={m:OllamaAgent(m,base_url=a.ollama_url,timeout=a.timeout,
                       temperature=a.temperature,num_predict=a.num_predict).check_model() for m in a.models}
        if provenance!=lock['model_digests']:raise ValueError('Model digest mismatch')
        models=a.models
        scenarios=cases
    else:
        if a.frozen_protocol is not None:raise ValueError('Replay is engineering-only; do not give a research lock')
        models=['SCRIPTED_REPLAY_NOT_AN_LLM']; provenance={}
        scenarios=cases[:a.max_scenarios] if a.max_scenarios is not None else cases
    if not scenarios:raise ValueError('No scenarios')
    if a.out.exists() or a.out.with_suffix('.manifest.json').exists():
        raise ValueError('Output/manifest exists; never overwrite research evidence')
    a.out.parent.mkdir(parents=True,exist_ok=True)
    timestamp=datetime.now(timezone.utc).isoformat()
    rows=[]
    for model in models:
        for s in scenarios:
            for seed in a.seeds:
                for mode in a.modes:
                    agent=(ReplayAgent(s['continuation_actions']) if a.backend=='replay' else
                           OllamaAgent(model,base_url=a.ollama_url,timeout=a.timeout,
                                       temperature=a.temperature,num_predict=a.num_predict))
                    rows.append(run_agent_episode(s,mode,agent,seed).to_dict())
    # All episodes are buffered before writing, like the original runner.
    with a.out.open('x',encoding='utf-8') as f:
        for row in rows:f.write(json.dumps(row,ensure_ascii=False)+'\n')
    from .runtime_guard import RuntimeGuard
    manifest=dict(kind=('SUPPLEMENTARY_PROJECT_FROZEN_NOT_EXTERNALLY_REGISTERED' if a.backend=='ollama' else
                        'ENGINEERING_REPLAY_NOT_AN_LLM'),back_end=a.backend,timestamp_utc=timestamp,
                  scenarios_sha256=hash_file(a.scenarios),scenario_count=len(scenarios),
                  model_digests=provenance,modes=a.modes,seeds=a.seeds,model_temperature=a.temperature,
                  model_num_predict=a.num_predict,run_count=len(rows),
                  frozen_protocol_sha256=(hash_file(a.frozen_protocol) if a.frozen_protocol else None),
                  runtime_policy_sha256=RuntimeGuard().policy_sha256,
                  original_stage5_5b_data_untouched=True,
                  denial_step_zero='Imposed by evaluator, not independently selected by LLM')
    out_manifest=a.out.with_suffix('.manifest.json')
    out_manifest.write_text(json.dumps(manifest,indent=2)+'\n',encoding='utf-8')
    print(json.dumps(dict(status=manifest['kind'],rows=len(rows),
                          jsonl=str(a.out),manifest=str(out_manifest)),indent=2))

if __name__=='__main__':main()
