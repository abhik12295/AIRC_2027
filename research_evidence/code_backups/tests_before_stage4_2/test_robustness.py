import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from benchmark.build_robustness_cases import make_cases,select_excerpt,VARIANTS
from benchmark.audit_trajectories import expected_read_hash, audit


class RobustnessTests(unittest.TestCase):
    def setUp(self):
        self.spec={'id':'example','pdf':'example.pdf','title':'Example Government Publication',
                   'publisher':'Public Agency','url':'https://example.com/public.pdf',
                   'required_terms':['risk','control'],'search_terms':['risk','control']}
        self.path=None

    def test_select_excerpt_is_source_text(self):
        pages=['Intro '*40,'control and risk '+'public '*500,'third '*600]
        excerpt,pages=select_excerpt(pages,['risk','control'])
        self.assertIn('control and risk',excerpt)
        self.assertEqual(pages[0],2)

    def test_attacks_are_genuinely_distinct(self):
        self.assertEqual(len(VARIANTS),4)
        self.assertEqual(len(set(VARIANTS.values())),4)

    def test_paired_cases_valid_and_unchanged_except_note(self):
        with TemporaryDirectory() as td:
            path=Path(td)/'test.pdf';path.write_bytes(b'%PDF-FAKE FOR HASH ONLY')
            scenarios=make_cases(self.spec,path,('risk and control ' * 60),[1,2],list(VARIANTS))
        self.assertEqual(len(scenarios),8)
        for a,b in zip(scenarios[::2],scenarios[1::2]):
            diffs={k for k in a if a[k]!=b[k]}
            self.assertEqual(diffs,{'id','attack_condition','untrusted_workspace_content'})
            self.assertNotEqual(expected_read_hash(a),expected_read_hash(b))

    def test_auditor_flags_mismatched_source(self):
        with TemporaryDirectory() as td:
            p=Path(td)/'test.pdf'; p.write_bytes(b'%PDF-FAKE FOR HASH ONLY')
            a,b=make_cases(self.spec,p,'risk control '*80,[1],['connector_reframe'])
        a['source_document']['excerpt_sha256']='broken'
        out=audit([], [a,b])
        self.assertEqual(out['quality_gate'],'FAIL')
        self.assertTrue(any('digest' in x.lower() for x in out['issues']))


if __name__=='__main__':unittest.main()
