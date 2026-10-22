#!/usr/bin/env python3
"""Build an offline, SHA-deduplicated stage ledger; never estimate semantic completion."""
import argparse
from collections import defaultdict
import hashlib
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'ghidra'))
from validate_exports import ARTIFACTS, validate_export
from coverage import classify


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def load(path):
    return json.loads(Path(path).read_text())


def discover_run_dirs(roots):
    """Only output-bearing run roots and two levels of explicit child runs.

    Never recurse into archived databases, duplicate legacy output trees, or caches.
    Followups may be nested below a subsystem run (run003/capture/followup).
    """
    found = set()
    for root in map(Path, roots):
        for pattern in ('outputs/ghidra', '*/outputs/ghidra', '*/*/outputs/ghidra'):
            for output in root.glob(pattern):
                found.add(output.parent.parent)
    return sorted(found)


def read_rows(path):
    return [json.loads(line) for line in path.read_text().splitlines()]


def original_va(row):
    value = row.get('elf_va')
    if value is None:
        return None
    # Schema-v2 ELF addresses are explicitly hexadecimal, unlike host offsets.
    return hex(int(value, 16))


def nearest_manifest(directory):
    for parent in (directory, *directory.parents):
        candidate = parent / 'input-manifest.json'
        if candidate.is_file():
            return candidate
    return None


def build(inventory, roots, review_ledgers=()):
    inventory = Path(inventory)
    source = load(inventory)
    elfs = [r for r in source if r.get('elf') and r.get('sha256')]
    by_sha = defaultdict(list)
    for row in elfs:
        by_sha[row['sha256']].append(row)
    programs = {}
    for sha, rows in sorted(by_sha.items()):
        paths = sorted([{'partition': r['partition'], 'original_path': r['original_path']} for r in rows], key=lambda p: (p['partition'], p['original_path']))
        programs[sha] = dict(sha256=sha, paths=paths, bytes=rows[0]['extracted_bytes'],
            source_verified_all_paths=all(r.get('source_sha256') == sha and r.get('source_bytes_match_extracted') is True for r in rows),
            subsystem_label_hints=sorted(set(h for r in rows for h in classify(r['original_path']))),
            valid_exports=[], import_receipts=[], auto_analysis_completed_receipts=[],
            noanalysis_export_receipts=[], function_addresses=set(), attempted_addresses=set(),
            completed_addresses=set(), abi_unverified_addresses=set(), reviewed_units=[],
            decompile_failed_attempts=[], analysis_timeouts=[], selection_omissions=[])
    exports, receipts, errors = [], [], []
    seen_generations = {}
    for directory in discover_run_dirs(roots):
        receipt_by_id = {}
        for path in sorted((directory / 'logs').glob('*.json')):
            try:
                receipt = load(path)
                if 'run_id' not in receipt or 'command' not in receipt:
                    continue
                receipt = dict(receipt, receipt_path=str(path), receipt_sha256=digest(path))
                receipt_by_id[receipt['run_id']] = receipt
                receipts.append(receipt)
            except (OSError, ValueError, TypeError) as exc:
                errors.append(dict(path=str(path), reason=str(exc)))
        manifest_path = nearest_manifest(directory)
        manifest = load(manifest_path) if manifest_path else []
        manifest_sha = {r['sha256']: r for r in manifest}
        for path in sorted((directory / 'outputs/ghidra').glob('*/summary.json')):
            record = {'summary_path': str(path), 'summary_sha256': digest(path)}
            try:
                raw = load(path)
                record.update(source_sha256=raw.get('sha256'), run_id=raw.get('run_id'),
                    auto_analysis_timed_out=raw.get('auto_analysis_timed_out'), artifacts=raw.get('artifacts'))
                sha = raw['sha256']
                if sha not in programs:
                    raise ValueError('Export source SHA256 is outside inventory denominator')
                receipt = receipt_by_id.get(raw.get('run_id'))
                if not receipt:
                    raise ValueError('No matching run-id receipt in this run directory (stale/unassociated export)')
                record['receipt_path'] = receipt['receipt_path']
                record['receipt_sha256'] = receipt['receipt_sha256']
                if receipt.get('completed') is not True or receipt.get('returncode') != 0:
                    raise ValueError('Run receipt is incomplete or failed; not coverage')
                command = receipt['command']
                analysis_enabled = '-noanalysis' not in command
                if raw.get('auto_analysis_enabled_this_run') is not analysis_enabled:
                    raise ValueError('Summary analysis flag disagrees with run command')
                summary = validate_export(path.parent, sha, receipt['run_id'])
                identity = (sha, receipt['run_id'])
                artifact_identity = json.dumps(summary['artifacts'], sort_keys=True)
                if identity in seen_generations:
                    previous, previous_artifacts = seen_generations[identity]
                    if artifact_identity != previous_artifacts:
                        raise ValueError('Conflicting artifact hashes for same source SHA256 and run ID')
                    record.update(valid=True, duplicate_generation_of=previous, excluded_from_counts=True)
                    exports.append(record)
                    continue
                input_record = manifest_sha.get(sha)
                importing = '-import' in command
                if importing and not input_record:
                    raise ValueError('Import run source SHA256 absent from input manifest')
                if input_record:
                    staged = next((input_record[k] for k in ('staged_path', 'local_input', 'input') if input_record.get(k)), None)
                    if staged and (not Path(staged).is_file() or digest(staged) != sha):
                        raise ValueError('Staged input bytes unavailable or SHA256 mismatch')
                    expected_path = input_record.get('path', input_record.get('original_path'))
                    partition = input_record.get('partition', input_record.get('inventory_entry', {}).get('partition'))
                    if not any(p['original_path'] == expected_path and (not partition or p['partition'] == partition) for p in programs[sha]['paths']):
                        raise ValueError('Input manifest path/SHA does not match source inventory')
                rows = read_rows(path.parent / 'functions.jsonl')
                decomp = read_rows(path.parent / 'decompiled.jsonl')
                addresses = {original_va(r) for r in rows if not r.get('external') and original_va(r) is not None}
                attempted = {original_va(r) for r in decomp if original_va(r) is not None}
                completed = {original_va(r) for r in decomp if r.get('completed') is True and original_va(r) is not None}
                if not attempted <= addresses:
                    raise ValueError('Decompiled original ELF VA is not in function export')
                record.update(valid=True, program=summary['program'], input_manifest=str(manifest_path) if input_record else None,
                    input_manifest_sha256=digest(manifest_path) if input_record else None,
                    input_bytes_sha256_rechecked=bool(input_record and staged),
                    input_association='manifest_sha_and_inventory_path' if input_record else 'restored_process_receipt_and_inventory_sha_only',
                    import_this_run=importing, auto_analysis_enabled_this_run=analysis_enabled,
                    function_records=len(rows), mapped_nonexternal_functions=len(addresses),
                    unmapped_or_external_function_records=len(rows)-len(addresses),
                    decompile_attempted=len(decomp), decompile_completed=summary['decompile_completed'],
                    decompile_omitted_by_budget=summary['decompile_omitted_by_budget'],
                    exporter_sha256=receipt.get('exporter_sha256'), artifacts=summary['artifacts'])
                seen_generations[identity] = (str(path), artifact_identity)
                p = programs[sha]
                p['valid_exports'].append(str(path))
                if importing:
                    p['import_receipts'].append(receipt['receipt_path'])
                if analysis_enabled and summary.get('auto_analysis_timed_out') is False:
                    p['auto_analysis_completed_receipts'].append(receipt['receipt_path'])
                if not analysis_enabled:
                    p['noanalysis_export_receipts'].append(receipt['receipt_path'])
                if summary.get('auto_analysis_timed_out') is True:
                    p['analysis_timeouts'].append(str(path))
                p['function_addresses'].update(addresses)
                p['attempted_addresses'].update(attempted)
                p['completed_addresses'].update(completed)
                p['abi_unverified_addresses'].update(original_va(r) for r in rows if r.get('abi_verified') is not True and original_va(r) is not None and not r.get('external'))
                p['decompile_failed_attempts'].extend(dict(summary_path=str(path), original_elf_va=original_va(r), error=r.get('error', '')) for r in decomp if r.get('completed') is not True)
                p['selection_omissions'].append(dict(summary_path=str(path), pattern=summary.get('decompile_pattern'), omitted_by_budget=summary['decompile_omitted_by_budget']))
            except (KeyError, OSError, ValueError, TypeError) as exc:
                record.update(valid=False, validation_error=str(exc))
                record['observed_artifacts'] = {name: dict(bytes=(path.parent/name).stat().st_size, sha256=digest(path.parent/name))
                    for name in ARTIFACTS if (path.parent/name).is_file()}
                errors.append(dict(path=str(path), reason=str(exc)))
            exports.append(record)
    review_sources = []
    review_ids = set()
    for path in map(Path, review_ledgers):
        review_sources.append(dict(path=str(path), sha256=digest(path)))
        review_data = load(path)
        review_items = review_data.get('reviewed_findings') if isinstance(review_data, dict) else review_data
        if not isinstance(review_items, list):
            errors.append(dict(path=str(path), reason='Review ledger must be a list or contain a reviewed_findings list'))
            continue
        for item in review_items:
            try:
                required = ('id', 'source_sha256', 'evidence', 'method', 'limitations', 'unresolved_questions')
                if any(key not in item for key in required) or not (item.get('original_elf_va') is not None or item.get('file_offset') is not None):
                    raise ValueError('Reviewed unit requires id, source SHA, location, evidence, method, limitations and unresolved questions')
                if item['source_sha256'] not in programs or not Path(item['evidence']).is_file():
                    raise ValueError('Reviewed unit source/evidence is unavailable')
                if item['id'] in review_ids:
                    raise ValueError('Duplicate reviewed unit ID')
                if item.get('original_elf_va') is not None:
                    if int(str(item['original_elf_va']), 16) < 0:
                        raise ValueError('Negative original ELF VA')
                if item.get('file_offset') is not None:
                    offset = int(str(item['file_offset']), 0) if isinstance(item['file_offset'], str) else item['file_offset']
                    if not isinstance(offset, int) or not 0 <= offset < programs[item['source_sha256']]['bytes']:
                        raise ValueError('Reviewed file offset is outside source ELF bytes')
                evidence_sha = digest(item['evidence'])
                if item.get('evidence_sha256') and item['evidence_sha256'] != evidence_sha:
                    raise ValueError('Reviewed evidence SHA256 is stale')
                review_ids.add(item['id'])
                programs[item['source_sha256']]['reviewed_units'].append(dict(item, evidence_sha256=evidence_sha))
            except (KeyError, ValueError, TypeError) as exc:
                errors.append(dict(path=str(path), reason=str(exc), reviewed_unit_id=item.get('id')))
    backlog = []
    for sha, p in programs.items():
        p['stages'] = dict(source_verified=p['source_verified_all_paths'],
            imported_with_success_receipt=bool(p['import_receipts']), loaded_program_export_validated=bool(p['valid_exports']),
            auto_analysis_completed_with_success_receipt=bool(p['auto_analysis_completed_receipts']),
            selected_decompilation_completed=bool(p['completed_addresses']), reviewed_static_findings=bool(p['reviewed_units']))
        p['function_counts'] = dict(mapped_nonexternal_exported=len(p.pop('function_addresses')),
            selected_attempted_unique=len(p.pop('attempted_addresses')), selected_completed_unique=len(p.pop('completed_addresses')),
            abi_unverified_unique=len(p.pop('abi_unverified_addresses')))
        for key in ('import_receipts', 'auto_analysis_completed_receipts', 'noanalysis_export_receipts'):
            p[key] = sorted(set(p[key]))
        pending = []
        if not p['stages']['loaded_program_export_validated']:
            pending.append('Import, analyze and validate export; no measured Ghidra export yet')
        elif not p['stages']['auto_analysis_completed_with_success_receipt']:
            pending.append('Obtain measured successful auto-analysis receipt; process/noanalysis export cannot establish it')
        if not p['stages']['selected_decompilation_completed']:
            pending.append('Select and decompile relevant functions; global function denominator unknown')
        pending.append('Resolve ABI/types and indirect/runtime call behavior with independent evidence')
        if not p['reviewed_units']:
            pending.append('Create explicit location-backed reviewed static finding units; no reviewed units registered')
        p['pending_work_units'] = pending
        p['unresolved_questions'] = [q for unit in p['reviewed_units'] for q in unit['unresolved_questions']]
        # This is only a deterministic navigation queue, not inferred product importance.
        hint = any(h != 'unclassified' for h in p['subsystem_label_hints'])
        score = (20 if hint else 0) + (10 if not p['valid_exports'] else 0) + (5 if p['valid_exports'] and not p['reviewed_units'] else 0)
        backlog.append(dict(sha256=sha, priority_score=score, rank_basis='filename_hint_then_unexported_then_unreviewed; heuristic only',
            representative_path=p['paths'][0]['original_path'], subsystem_label_hints=p['subsystem_label_hints'], pending_work_units=pending))
    backlog.sort(key=lambda r: (-r['priority_score'], r['representative_path'], r['sha256']))
    for rank, row in enumerate(backlog, 1):
        row['rank'] = rank
    count = len(programs)
    stages = {}
    for stage in next(iter(programs.values()))['stages'] if programs else ():
        numerator = sum(p['stages'][stage] for p in programs.values())
        stages[stage] = dict(numerator_unique_elf_contents=numerator, denominator_unique_elf_contents=count,
            percent_unique_elf_contents=round(100*numerator/count, 6) if count else None)
    if not review_ledgers:
        stages['reviewed_static_findings']['numerator_unique_elf_contents'] = None
        stages['reviewed_static_findings']['percent_unique_elf_contents'] = None
        stages['reviewed_static_findings']['status'] = 'unmeasured_no_explicit_review_ledger'
    return dict(schema_version=1, inventory=dict(path=str(inventory), sha256=digest(inventory), elf_paths=len(elfs), unique_elf_contents=count),
        scope='Offline filesystem ELF content only; kernel images, resources, configs and boot sections are separate units. No target execution.',
        semantic_completion=dict(percent=None, status='not_measurable_from_import_analysis_exports_or_selected_decompilation',
            reason='No established total semantic work-unit/function denominator; static findings do not demonstrate device behavior.'),
        definitions=dict(source_verified='Inventory source-inode bytes match extraction; same debugfs implementation, not an independent parser.',
            imported_with_success_receipt='Validated schema-v2 export, same-run successful -import receipt and inventory-matched input manifest.',
            loaded_program_export_validated='Validated schema-v2 artifact hashes/counts and matching successful run receipt; includes restored -process -noanalysis.',
            auto_analysis_completed_with_success_receipt='Validated export generated during same-run enabled auto-analysis, success receipt and explicit no-timeout flag. Conservative matched-generation evidence, not a count of every historical analysis; process/noanalysis exports can preserve previously analyzed programs.',
            selected_decompilation_completed='At least one completed selected function; not whole-program decompilation or understanding.',
            reviewed_static_findings='At least one accepted explicit reviewed unit names this SHA as its primary source. Additional-source anchors stay attached to the finding; they do not silently create more reviewed units or primary-source counts.',
            function_counts='Deduplicated by source SHA256 + original ELF VA; exported mapped nonexternal function records only, not all firmware functions.',
            subsystem_label_hints='Overlapping filename substrings from coverage.py; navigation hints, never semantic subsystem assignments.',
            ranking='Deterministic heuristic navigation queue; not a measure of user value, risk or semantic completion.'),
        stages=stages, totals=dict(run_receipts_completed=sum(r.get('completed') is True and r.get('returncode') == 0 for r in receipts),
            run_receipts_failed=sum(r.get('returncode') is not None and r.get('returncode') != 0 for r in receipts),
            run_receipts_incomplete=sum(r.get('completed') is not True and r.get('returncode') is None for r in receipts),
            valid_export_generations=sum(e['valid'] and not e.get('excluded_from_counts') for e in exports),
            duplicate_export_generations_excluded=sum(bool(e.get('duplicate_generation_of')) for e in exports), invalid_export_generations=sum(not e['valid'] for e in exports),
            exported_without_matching_auto_analysis_generation=sum(bool(p['valid_exports']) and not p['auto_analysis_completed_receipts'] for p in programs.values()),
            unique_exported_functions=sum(p['function_counts']['mapped_nonexternal_exported'] for p in programs.values()),
            unique_selected_decompile_attempted=sum(p['function_counts']['selected_attempted_unique'] for p in programs.values()),
            unique_selected_decompile_completed=sum(p['function_counts']['selected_completed_unique'] for p in programs.values()),
            unique_abi_unverified_functions=sum(p['function_counts']['abi_unverified_unique'] for p in programs.values()),
            reviewed_static_units=len(review_ids) if review_ledgers else None),
        run_roots=list(map(str, roots)), run_receipts=receipts, export_generations=exports, validation_errors=errors,
        review_ledgers=review_sources, programs=list(programs.values()), backlog=backlog)


def markdown(report):
    inv, totals = report['inventory'], report['totals']
    lines = ['# Measured offline analysis progress', '',
        f"The filesystem corpus contains **{inv['unique_elf_contents']:,} unique ELF contents across {inv['elf_paths']:,} paths**. Content coverage uses SHA-256, so duplicate paths and followup exports never increase the denominator or numerator.", '',
        '**Semantic completion percentage is unknown.** Import, automated analysis, export, selected decompilation and reviewed static findings are separate stages. These counts do not prove feature behavior on a camera.', '',
        '| Stage | Unique ELF numerator / denominator | Content coverage |', '|---|---:|---:|']
    for name, stage in report['stages'].items():
        n = stage['numerator_unique_elf_contents']
        lines.append(f"| {name.replace('_', ' ')} | {n if n is not None else 'unmeasured'} / {inv['unique_elf_contents']} | {str(round(stage['percent_unique_elf_contents'], 3))+'%' if n is not None else 'unmeasured'} |")
    lines += ['', f"Validated export generations: {totals['valid_export_generations']}; rejected generations: {totals['invalid_export_generations']}. Deduplicated mapped nonexternal function entries: {totals['unique_exported_functions']:,}. Selected function attempts: {totals['unique_selected_decompile_attempted']:,}; completed: {totals['unique_selected_decompile_completed']:,}. There is no whole-corpus function denominator. ABI-unverified mapped entries: {totals['unique_abi_unverified_functions']:,}.", '',
        'Successful `-import` receipts count only when their input manifest SHA and firmware path agree with the source inventory. Restored `-process -noanalysis` exports establish a loaded program and valid export; they do not establish a newly measured import or completed auto-analysis. Artifact bytes, SHA-256, row counts, run IDs and receipt exit state are checked on every rebuild. Failed runs and stale exports remain visible as errors and do not count as coverage.', '',
        f"{totals['exported_without_matching_auto_analysis_generation']} exported contents lack a matching successful auto-analysis export generation in the scanned records. The restored run001 exports were generated with `-process -noanalysis` from previously documented analyzed programs. This conservative stage count does not mean those programs were never analyzed, and it does not erase earlier work; the matching current-generation evidence is simply an export receipt, not an auto-analysis receipt. Earlier narrative/log history is distinct from the validated-generation numerator.", '',
        'Function counts deduplicate source SHA-256 plus original ELF virtual address. External/unmapped entries are reported per generation separately. Analyzer timeouts, decompiler failures/errors, budget omissions, signatures with unverified ABI, and explicit reviewed-unit unresolved questions remain in the JSON ledger. Repeated failures are attempt history, not additional analyzed functions.', '',
        'The JSON contains a reproducible per-SHA backlog, pending work units and overlapping filename-based subsystem hints. Its ranking is only a navigation heuristic; it assigns no semantic subsystem ownership or completeness. Source verification uses debugfs extraction and source-inode dumps from the same implementation; it is not an independent filesystem parser or runtime observation. Non-ELF firmware sections, kernel images, resources and configuration require separate denominators.', '',
        'Reproduce from the repository root:', '', '```sh',
        'python tools/firmware/analysis_progress.py \\',
        '  --inventory .work/full/inventory/full_filesystem_inventory.json \\',
        '  '+ ' '.join('--run-root '+str(p) for p in report['run_roots'])+' \\',
        *['  --review-ledger '+r['path']+' \\' for r in report['review_ledgers']],
        '  --output manifests/analysis-progress.json --markdown docs/ANALYSIS_PROGRESS.md', '```', '',
        'Review counts are unmeasured unless explicit `--review-ledger` inputs are provided. Review inputs accept a list or a manifest containing `reviewed_findings`. Each reviewed unit must record a stable ID, inventory source SHA, original ELF VA or file offset, existing evidence path, method, limitations and unresolved questions. Prose reports and generated pseudocode are never silently classified as reviewed findings.', '',
        f"Registered reviewed static units: {totals['reviewed_static_units'] if totals['reviewed_static_units'] is not None else 'unmeasured'}. Review content coverage counts primary source SHA associations only; extra source anchors stay attached to each unit. It does not measure the fraction of semantics understood.", '',
        f"Inventory SHA-256: `{inv['sha256']}`. All source SHA, original paths, export artifact hashes, receipt locations and per-SHA work units are preserved in [the ledger](../manifests/analysis-progress.json).", '']
    if report['validation_errors']:
        lines += ['Validation errors at generation time:', '']
        lines += [f"- `{e['path']}`: {e['reason']}" for e in report['validation_errors']]
        lines.append('')
    return '\n'.join(lines)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--inventory', required=True, type=Path)
    parser.add_argument('--run-root', action='append', default=[], type=Path)
    parser.add_argument('--review-ledger', action='append', default=[], type=Path)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--markdown', type=Path)
    args = parser.parse_args()
    report = build(args.inventory, args.run_root, args.review_ledger)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2)+'\n')
    if args.markdown:
        args.markdown.parent.mkdir(parents=True, exist_ok=True)
        args.markdown.write_text(markdown(report))
    print(json.dumps({key: report[key] for key in ('inventory', 'stages', 'totals', 'validation_errors')}, indent=2))


if __name__ == '__main__':
    main()
