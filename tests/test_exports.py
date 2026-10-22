import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

SOURCE=Path(__file__).resolve().parents[1]/'tools/ghidra/validate_exports.py'
spec=importlib.util.spec_from_file_location('validate_exports',SOURCE)
module=importlib.util.module_from_spec(spec); spec.loader.exec_module(module)

class ExportValidationTests(unittest.TestCase):
    def fixture(self,root):
        rows={'functions.jsonl':[{'name':'function'}],'calls.jsonl':[],
              'decompiled.jsonl':[{'completed':True}],
              'strings.jsonl':[{'loaded_memory':False,'elf_va':None}]}
        artifacts={}
        for name,values in rows.items():
            data=''.join(json.dumps(row)+'\n' for row in values).encode()
            (root/name).write_bytes(data)
            artifacts[name]={'bytes':len(data),'sha256':hashlib.sha256(data).hexdigest()}
        summary=dict(export_schema_version=2,export_completed=True,sha256='0'*64,run_id='current-run',
                     functions=1,strings=1,decompile_attempted=1,decompile_completed=1,
                     matched_functions=1,decompile_omitted_by_budget=0,artifacts=artifacts)
        (root/'summary.json').write_text(json.dumps(summary))
        return summary

    def test_valid_generation(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp); self.fixture(root)
            module.validate_export(root,'0'*64,'current-run')

    def test_stale_generation_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp); self.fixture(root)
            with self.assertRaisesRegex(ValueError,'stale'):
                module.validate_export(root,'0'*64,'other-run')

    def test_same_size_artifact_tamper_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp); self.fixture(root)
            path=root/'functions.jsonl'; data=path.read_bytes().replace(b'function',b'FUNCTION')
            path.write_bytes(data)
            with self.assertRaisesRegex(ValueError,'integrity'):
                module.validate_export(root)

    def test_partial_export_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp); summary=self.fixture(root)
            summary['export_completed']=False
            (root/'summary.json').write_text(json.dumps(summary))
            with self.assertRaisesRegex(ValueError,'completed'):
                module.validate_export(root)

    def test_missing_artifact_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp); self.fixture(root); (root/'calls.jsonl').unlink()
            with self.assertRaises(FileNotFoundError): module.validate_export(root)

if __name__=='__main__': unittest.main()
