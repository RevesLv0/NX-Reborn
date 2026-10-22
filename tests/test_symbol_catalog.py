import importlib.util
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

spec = importlib.util.spec_from_file_location('symbol_catalog', Path(__file__).resolve().parents[1] / 'tools/firmware/symbol_catalog.py')
catalog = importlib.util.module_from_spec(spec)
spec.loader.exec_module(catalog)


@unittest.skipUnless(shutil.which('cc'), 'Host compiler required for synthetic ELF fixture')
class SymbolCatalogTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        (self.root / 'test.c').write_text('extern int foreign(void); int public_api(void){return foreign();} static int local_api(void){return 3;} int helper(void){return local_api();}')
        (self.root / 'versions.map').write_text('TEST_1 { global: public_api; local: *; };')
        self.library = self.root / 'libtest.so'
        subprocess.run(['cc', '-shared', '-fPIC', str(self.root / 'test.c'), '-Wl,--version-script=' + str(self.root / 'versions.map'), '-o', str(self.library)], check=True, capture_output=True)

    def tearDown(self):
        self.temp.cleanup()

    def test_versioned_export_local_symbol_and_undefined_import(self):
        rows, info = catalog.inspect(self.library)
        exported = next(r for r in rows if r['name'] == 'public_api' and r['table'] == '.dynsym')
        self.assertTrue(exported['dynamic_export_candidate'])
        self.assertEqual(exported['version']['name'], 'TEST_1')
        imported = next(r for r in rows if r['name'] == 'foreign' and r['table'] == '.dynsym')
        self.assertFalse(imported['defined'])
        self.assertFalse(imported['dynamic_export_candidate'])
        local = next(r for r in rows if r['name'] == 'local_api')
        self.assertEqual(local['binding'], 'STB_LOCAL')
        self.assertFalse(local['dynamic_export_candidate'])
        self.assertIn('.symtab', info['tables'])

    def test_duplicate_source_content_and_tampered_bytes(self):
        sha = catalog.sha256(self.library)
        row = dict(sha256=sha, partition='rootfs', original_path='/libtest.so', elf={"type": "ET_DYN"})
        result = catalog.catalog([row, dict(row, original_path='/alias.so')], {'rootfs': self.root}, self.root / 'out')
        # Sorting selects /alias.so; absent declared input must be reported, not silently skipped.
        self.assertFalse(result['completed'])
        shutil.copyfile(self.library, self.root / 'alias.so')
        result = catalog.catalog([row, dict(row, original_path='/alias.so')], {'rootfs': self.root}, self.root / 'out')
        self.assertEqual(result['cataloged_unique_elf_contents'], 1)
        self.assertTrue(result['completed'])
        self.library.write_bytes(self.library.read_bytes() + b'changed')
        result = catalog.catalog([row], {'rootfs': self.root}, self.root / 'out')
        self.assertFalse(result['completed'])
        self.assertFalse((self.root / 'out/named_symbols.jsonl').exists())
        self.assertFalse(json.loads((self.root / 'out/symbol_summary.json').read_text())['completed'])

    def test_symlink_source_and_parent_traversal_rejected(self):
        (self.root / 'link').symlink_to(self.library)
        for name in ['/link', '/../libtest.so', 'libtest.so']:
            with self.assertRaises(ValueError):
                catalog.source_path(self.root, name)

    def test_required_symbol_version_retains_provider(self):
        source = self.root / 'consumer.c'
        source.write_text('extern int public_api(void); int consume(void){return public_api();}')
        consumer = self.root / 'consumer.so'
        subprocess.run(['cc', '-shared', '-fPIC', str(source), '-L' + str(self.root), '-ltest', '-o', str(consumer)], check=True, capture_output=True)
        rows, _ = catalog.inspect(consumer)
        imported = next(r for r in rows if r['name'] == 'public_api' and r['table'] == '.dynsym')
        self.assertFalse(imported['defined'])
        self.assertEqual(imported['version']['name'], 'TEST_1')
        self.assertEqual(imported['version']['provider'], 'libtest.so')
        self.assertEqual(imported['version']['kind'], 'required')
