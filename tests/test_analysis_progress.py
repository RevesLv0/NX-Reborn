"""Behavioral fixtures for coverage accounting, independent of firmware/Ghidra."""
import hashlib
import importlib.util
import json
import shutil
from pathlib import Path
import tempfile
import unittest

MODULE = Path(__file__).resolve().parents[1] / 'tools/firmware/analysis_progress.py'
spec = importlib.util.spec_from_file_location('analysis_progress', MODULE)
progress = importlib.util.module_from_spec(spec)
spec.loader.exec_module(progress)


class LedgerFixture(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.sha = hashlib.sha256(b'fixture source bytes').hexdigest()
        self.inventory = self.root / 'inventory.json'
        self.write(self.inventory, [dict(partition='rootfs', original_path=path, elf={'type': 'ET_DYN'},
            sha256=self.sha, extracted_bytes=20, source_sha256=self.sha, source_bytes_match_extracted=True)
            for path in ('/usr/lib/libcapture.so', '/duplicate/libcapture.so')])

    def write(self, path, data):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(data))

    def generation(self, name='run', analysis=True, importing=True, successful=True,
                   timed_out=False, addresses=('0x10',), failed_decomp=False):
        run = self.root / name
        output = run / 'outputs/ghidra/fixture'
        output.mkdir(parents=True)
        runid = name.replace('/', '-')
        functions = [dict(elf_va=va, external=False, abi_verified=False) for va in addresses]
        decomp = [dict(elf_va=va, completed=not failed_decomp, error='timeout' if failed_decomp else '') for va in addresses]
        data = {'functions.jsonl': functions, 'calls.jsonl': [], 'decompiled.jsonl': decomp, 'strings.jsonl': []}
        artifacts = {}
        for filename, rows in data.items():
            payload = ''.join(json.dumps(r)+'\n' for r in rows).encode()
            (output / filename).write_bytes(payload)
            artifacts[filename] = dict(bytes=len(payload), sha256=hashlib.sha256(payload).hexdigest())
        summary = dict(program='fixture', sha256=self.sha, export_schema_version=2, export_completed=True,
            run_id=runid, artifacts=artifacts, functions=len(functions), strings=0, decompile_attempted=len(decomp),
            decompile_completed=0 if failed_decomp else len(decomp), matched_functions=len(decomp), decompile_omitted_by_budget=0,
            auto_analysis_enabled_this_run=analysis, auto_analysis_timed_out=timed_out)
        self.write(output / 'summary.json', summary)
        command = ['headless', '-import' if importing else '-process', 'input']
        if not analysis:
            command.append('-noanalysis')
        self.write(run / 'logs/receipt.json', dict(run_id=runid, completed=successful, returncode=0 if successful else 1, command=command))
        if importing:
            self.write(run / 'input-manifest.json', [dict(sha256=self.sha, partition='rootfs', path='/usr/lib/libcapture.so')])
        return run, output

    def stage(self, report, name):
        return report['stages'][name]['numerator_unique_elf_contents']

    def test_deduplicates_content_paths_generations_and_original_addresses(self):
        run, _ = self.generation(addresses=('0x10', '0x20'))
        self.generation('run/followup', analysis=False, importing=False, addresses=('0x10', '0x30'))
        report = progress.build(self.inventory, [run])
        self.assertEqual(report['inventory']['elf_paths'], 2)
        self.assertEqual(report['inventory']['unique_elf_contents'], 1)
        self.assertEqual(report['totals']['valid_export_generations'], 2)
        self.assertEqual(report['totals']['unique_selected_decompile_completed'], 3)
        self.assertEqual(report['totals']['unique_exported_functions'], 3)
        self.assertEqual(self.stage(report, 'imported_with_success_receipt'), 1)
        self.assertEqual(report['semantic_completion']['percent'], None)

    def test_restored_noanalysis_export_is_not_measured_import_or_analysis(self):
        run, _ = self.generation(analysis=False, importing=False)
        report = progress.build(self.inventory, [run])
        self.assertEqual(self.stage(report, 'loaded_program_export_validated'), 1)
        self.assertEqual(self.stage(report, 'imported_with_success_receipt'), 0)
        self.assertEqual(self.stage(report, 'auto_analysis_completed_with_success_receipt'), 0)
        self.assertIsNone(self.stage(report, 'reviewed_static_findings'))

    def test_failed_receipt_never_contributes_export_or_decompile_coverage(self):
        run, _ = self.generation(successful=False)
        report = progress.build(self.inventory, [run])
        self.assertEqual(self.stage(report, 'loaded_program_export_validated'), 0)
        self.assertEqual(report['totals']['unique_selected_decompile_completed'], 0)
        self.assertEqual(report['totals']['run_receipts_failed'], 1)
        self.assertIn('failed', report['validation_errors'][0]['reason'])

    def test_artifact_mutation_and_stale_runid_are_rejected(self):
        run, output = self.generation()
        (output / 'functions.jsonl').write_text('{}\n')
        report = progress.build(self.inventory, [run])
        self.assertEqual(self.stage(report, 'loaded_program_export_validated'), 0)
        self.assertIn('integrity', report['validation_errors'][0]['reason'])
        rejected = report['export_generations'][0]
        self.assertNotEqual(rejected['artifacts']['functions.jsonl']['sha256'], rejected['observed_artifacts']['functions.jsonl']['sha256'])
        run2, output2 = self.generation('stale')
        summary = progress.load(output2 / 'summary.json')
        summary['run_id'] = 'previous-generation'
        self.write(output2 / 'summary.json', summary)
        report = progress.build(self.inventory, [run2])
        self.assertIn('stale', report['validation_errors'][0]['reason'])

    def test_timeout_is_partial_export_and_failure_attempt_history_survives(self):
        run, _ = self.generation(timed_out=True, failed_decomp=True)
        report = progress.build(self.inventory, [run])
        self.assertEqual(self.stage(report, 'loaded_program_export_validated'), 1)
        self.assertEqual(self.stage(report, 'auto_analysis_completed_with_success_receipt'), 0)
        self.assertEqual(report['totals']['unique_selected_decompile_completed'], 0)
        self.assertEqual(report['programs'][0]['decompile_failed_attempts'][0]['error'], 'timeout')
        self.assertEqual(len(report['programs'][0]['analysis_timeouts']), 1)

    def test_declared_import_without_matching_source_manifest_is_rejected(self):
        run, _ = self.generation()
        (run / 'input-manifest.json').unlink()
        report = progress.build(self.inventory, [run])
        self.assertIn('input manifest', report['validation_errors'][0]['reason'])
        self.assertEqual(self.stage(report, 'imported_with_success_receipt'), 0)

    def test_staged_input_hash_mismatch_is_not_coverage(self):
        run, _ = self.generation()
        staged = run / 'input'
        staged.write_bytes(b'changed source')
        self.write(run / 'input-manifest.json', [dict(sha256=self.sha, path='/usr/lib/libcapture.so', staged_path=str(staged))])
        report = progress.build(self.inventory, [run])
        self.assertIn('Staged input', report['validation_errors'][0]['reason'])
        self.assertEqual(report['totals']['valid_export_generations'], 0)

    def test_copied_generation_is_preserved_but_not_counted_twice(self):
        run, _ = self.generation()
        copy = self.root / 'copy'
        shutil.copytree(run, copy)
        report = progress.build(self.inventory, [run, copy])
        self.assertEqual(report['totals']['valid_export_generations'], 1)
        self.assertEqual(report['totals']['duplicate_export_generations_excluded'], 1)
        self.assertEqual(report['totals']['unique_selected_decompile_completed'], 1)

    def test_legacy_nested_duplicates_are_not_discovered(self):
        run, _ = self.generation()
        self.generation('run/cache/old/archive/legacy', importing=False, analysis=False)
        report = progress.build(self.inventory, [run])
        self.assertEqual(report['totals']['valid_export_generations'], 1)

    def test_explicit_review_units_require_evidence_and_keep_semantic_completion_unknown(self):
        run, _ = self.generation()
        evidence = self.root / 'evidence.md'
        evidence.write_text('location-backed observation with limits')
        ledger = self.root / 'review.json'
        unit = dict(id='fixture-1', source_sha256=self.sha, original_elf_va='0x10', evidence=str(evidence),
            method='static call inspection', limitations='no runtime observation', unresolved_questions=['Which caller supplies this flag?'])
        self.write(ledger, [unit])
        report = progress.build(self.inventory, [run], [ledger])
        self.assertEqual(report['totals']['reviewed_static_units'], 1)
        self.assertEqual(self.stage(report, 'reviewed_static_findings'), 1)
        self.assertIsNone(report['semantic_completion']['percent'])
        self.assertEqual(report['programs'][0]['unresolved_questions'], unit['unresolved_questions'])
        unit['evidence_sha256'] = progress.digest(evidence)
        self.write(ledger, {'reviewed_findings': [unit]})
        self.assertEqual(progress.build(self.inventory, [run], [ledger])['totals']['reviewed_static_units'], 1)
        evidence.write_text('changed after review')
        self.assertIn('stale', progress.build(self.inventory, [run], [ledger])['validation_errors'][0]['reason'])
        evidence.unlink()
        rejected = progress.build(self.inventory, [run], [ledger])
        self.assertEqual(rejected['totals']['reviewed_static_units'], 0)
        self.assertIn('unavailable', rejected['validation_errors'][0]['reason'])


if __name__ == '__main__':
    unittest.main()
