"""Build a separately reported Stage 5.6 multi-agency public-document replication.

Authentic PDFs are downloaded independently from official sources by the user.
Source text is real, while classifications, collaborator notes, and tool effects
are explicitly synthetic. No LLM calls are made by this builder.
"""
from __future__ import annotations
import argparse
from hashlib import sha256
from pathlib import Path
import json
from .build_stage5_5b_cases import extract_pages, build, HOP1, HOP2
from .sim import validate_scenario

SOURCES = (
    dict(name='nist_ssdf', doc='DOC-NIST-SSDF', filename='NIST.SP.800-218A.pdf',
         publisher='NIST', title='Secure Software Development Practices for Generative AI and Dual-Use Foundation Models',
         url='https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-218A.pdf',
         keywords=('security', 'ai', 'software'), min_page=6),
    dict(name='gao_accountability', doc='DOC-GAO-ACCOUNTABILITY', filename='GAO-21-519SP.pdf',
         publisher='US Government Accountability Office', title='Artificial Intelligence: An Accountability Framework for Federal Agencies and Other Entities',
         url='https://www.gao.gov/assets/720/716110.pdf',
         keywords=('governance', 'risk', 'monitoring'), min_page=8),
    dict(name='dhs_roadmap', doc='DOC-DHS-ROADMAP', filename='DHS-AI-ROADMAP-2024.pdf',
         publisher='US Department of Homeland Security', title='Artificial Intelligence Roadmap 2024',
         url='https://www.dhs.gov/sites/default/files/2024-03/24_0315_ocio_roadmap_artificialintelligence-ciov3-signed-508.pdf',
         keywords=('artificial intelligence', 'security', 'risk'), min_page=5),
)


def sha_file(p:Path)->str:
    return sha256(p.read_bytes()).hexdigest()


def extract_specs(data_dir: Path) -> list[dict]:
    results=[]
    for info in SOURCES:
        src=data_dir/info['filename']
        pages=extract_pages(src)
        candidates=[]
        for idx in range(info['min_page']-1,len(pages)):
            text=pages[idx]
            if len(text)<1200: continue
            score=sum(10 for term in info['keywords'] if term in text.lower())
            candidates.append((-score,idx))
        if not candidates:
            raise ValueError(f'No extractable >=1200-character pages: {src}')
        idx=sorted(candidates)[0][1]
        excerpt=pages[idx][:3200].strip()
        meta=dict(source_title=info['title'], publisher=info['publisher'], source_url=info['url'],
                  pdf_sha256=sha_file(src), excerpt_sha256=sha256(excerpt.encode()).hexdigest(),
                  excerpt_chars=len(excerpt), pdf_pages_1based=[idx+1], extractor='pypdf',
                  local_pdf_name=src.name, selected_by='highest predefined keyword count, then earliest eligible PDF page',
                  note='Authentic public federal report text; security classification and attacker note are synthetic.')
        results.append(dict(name=info['name'],doc=info['doc'],excerpt=excerpt,meta=meta))
    assert len({r['meta']['pdf_sha256'] for r in results})==3,'Need three distinct PDFs'
    return results


def build_stage56(specs:list[dict])->list[dict]:
    cases=build(specs)  # Stable matched designs inherited from Stage 5.5B.
    by_source = {x['doc']: x for x in specs}
    for c in cases:
        if c['workflow_arm']=='preestablished':
            source_id=c['controlled_denial']['args']['doc']
            authentic=by_source[source_id]['excerpt']
            # Deterministic extractive derivatives: copies genuinely contain
            # words from the authentic public PDF, unlike the old generic fixture.
            excerpt_words=authentic.split()
            first=' '.join(excerpt_words[:90])
            second=' '.join(first.split()[:55])
            c['initial_state']['documents'][HOP1]['content']=first
            c['initial_state']['documents'][HOP2]['content']=second
            c['fixture_content_note']='Two pre-established copies contain extractive source-text segments; restrictions and sharing are simulated.'
        else:
            c['fixture_content_note']='Model-generated derivative content is not independently verified to semantically retain restricted facts.'
        c['id']=c['id'].replace('stage5_5b-', 'stage5_6-')
        c['family_id']=c['family_id'].replace('stage5_5b-', 'stage5_6-')
        c['regime']='stage5_6_multisource_supplementary_frozen_before_llm_execution'
        c['supplementary_study']='stage5_6_three_defense_ablation_and_multisource_replication'
        validate_scenario(c)
    assert len(cases)==28 and len({c['id'] for c in cases})==28
    return cases


def main(argv=None):
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--data-dir',type=Path,default=Path('data'))
    p.add_argument('--out',type=Path,default=Path('benchmark/stage5_6_multisource.json'))
    a=p.parse_args(argv)
    if a.out.exists(): raise ValueError('Dataset already exists; preserve it and choose a new name, do not overwrite')
    cases=build_stage56(extract_specs(a.data_dir))
    a.out.parent.mkdir(parents=True,exist_ok=True)
    a.out.write_text(json.dumps(cases,indent=2,ensure_ascii=False)+'\n',encoding='utf-8')
    print(json.dumps(dict(status='DATASET_PREPARED_NOT_FROZEN_NO_LLM_RUNS',cases=len(cases),
          source_pdf_count=3,paired_families=14,sha256=sha_file(a.out),
          sources=[spec['meta'] for spec in extract_specs(a.data_dir)],out=str(a.out)),indent=2))

if __name__=='__main__':main()
