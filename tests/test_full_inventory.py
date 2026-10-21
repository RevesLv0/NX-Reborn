import importlib.util
import contextlib
import io
import os
from pathlib import Path
import tempfile
import unittest

PATH = Path(__file__).resolve().parents[1] / 'tools/firmware/full_inventory.py'
SPEC = importlib.util.spec_from_file_location('full_inventory', PATH)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def elf_row(path, soname=None, needed=(), partition='rootfs', runpath=None):
    return dict(partition=partition, original_path=path, runtime_path=path, type='regular', sha256='a'*64,
                elf=dict(machine='EM_ARM', elf_class=32, little_endian=True,
                         soname=soname, needed=list(needed), runpath=runpath, rpath=None))


class FullInventoryTests(unittest.TestCase):
    def test_source_join_rejects_same_size_content_tamper(self):
        row = dict(partition='rootfs', original_path='/file', runtime_path='/file',
                   type='regular', extracted_bytes=4, sha256='a'*64)
        source = [dict(path='/file', mode=0o100644, inode=12, uid=0, gid=0, size=4,
                       sha256='b'*64, byte_verification='native_debugfs_dump_by_source_inode_matches_rdump_file')]
        rows, errors = MODULE.join_source_tree([row], source, 'rootfs')
        self.assertFalse(rows[0]['source_bytes_match_extracted'])
        self.assertEqual(errors[0]['error'], 'source_inode_sha256_mismatch')

    def test_source_join_rejects_same_size_symlink_target_change(self):
        row = dict(partition='rootfs', original_path='/link', runtime_path='/link',
                   type='symlink', extracted_bytes=3, target='one')
        source = [dict(path='/link', mode=0o120777, inode=12, uid=0, gid=0, size=3, link='two')]
        rows, errors = MODULE.join_source_tree([row], source, 'rootfs')
        self.assertFalse(rows[0]['source_link_matches_extracted'])
        self.assertEqual(errors[0]['error'], 'source_symlink_target_mismatch')

    def test_source_metadata_preserves_missing_device_nodes_but_fails_missing_regular(self):
        source = [dict(path='/dev/null', mode=0o20666, inode=12, uid=0, gid=0, size=0),
                  dict(path='/regular', mode=0o100644, inode=13, uid=0, gid=0, size=10)]
        rows, errors = MODULE.join_source_tree([], source, 'rootfs')
        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[0]['type'], 'char_device')
        self.assertFalse(rows[0]['extracted'])
        self.assertEqual(errors, [dict(partition='rootfs', path='/regular', stage='source_join',
                                      error='missing_extracted_path')])

    def test_content_and_host_inode_counts_do_not_imply_source_inode_count(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            rootfs = root / 'rootfs'; rootfs.mkdir()
            opt = root / 'opt'; opt.mkdir()
            (rootfs / 'one').write_text('shared bytes')
            (rootfs / 'two').write_text('shared bytes')
            os.link(rootfs / 'one', rootfs / 'three')
            with contextlib.redirect_stdout(io.StringIO()):
                result = MODULE.inventory(rootfs, opt, root / 'output')
            self.assertEqual(result['regular_file_paths'], 3)
            self.assertEqual(result['unique_regular_content_sha256'], 1)
            self.assertEqual(result['unique_extracted_regular_inodes'], 2)
            self.assertFalse(result['source_inode_inventory_complete'])

    def test_tree_does_not_follow_links_and_labels_inode_provenance(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / 'root'; root.mkdir()
            outside = Path(temporary) / 'outside'; outside.mkdir()
            (outside / 'secret').write_text('not firmware')
            (root / 'escape').symlink_to(outside, target_is_directory=True)
            (root / 'regular').write_text('fixture')
            os.link(root / 'regular', root / 'hardlink')
            os.mkfifo(root / 'fifo')
            rows, errors = MODULE.scan_tree(root, 'rootfs')
            self.assertFalse(errors)
            self.assertEqual(len(rows), 4)
            found = {row['original_path']:row for row in rows}
            self.assertNotIn('sha256', found['/escape'])
            self.assertNotIn('sha256', found['/fifo'])
            self.assertEqual(found['/regular']['extracted_inode'], found['/hardlink']['extracted_inode'])
            self.assertEqual(found['/regular']['inode_provenance'], 'host_extracted_tree_only')

    def test_virtual_links_stay_in_firmware_and_cycles_are_reported(self):
        rows = [dict(runtime_path='/usr/lib/x', type='symlink', target='../../lib/x'),
                dict(runtime_path='/lib/x', type='regular'),
                dict(runtime_path='/loop', type='symlink', target='/loop')]
        namespace = {row['runtime_path']:row for row in rows}
        self.assertEqual(MODULE.resolve_virtual('/usr/lib/x', namespace), ('/lib/x', None))
        self.assertEqual(MODULE.resolve_virtual('/loop', namespace), (None, 'symlink_cycle'))

    def test_exact_loader_path_beats_soname_ambiguity(self):
        rows = [elf_row('/bin/app', needed=['libx.so']), elf_row('/lib/libx.so', soname='libx.so'),
                elf_row('/elsewhere/libx.so', soname='libx.so')]
        edge = MODULE.dependency_edges(rows)[0]
        self.assertEqual(edge['status'], 'resolved_static_default_search')
        self.assertEqual(edge['target'], '/lib/libx.so')
        self.assertEqual(len(edge['static_candidates']), 2)

    def test_soname_only_candidates_are_never_claimed_resolved(self):
        rows = [elf_row('/bin/app', needed=['libx.so']), elf_row('/a/libx.so', soname='libx.so'),
                elf_row('/b/libx.so', soname='libx.so')]
        self.assertEqual(MODULE.dependency_edges(rows)[0]['status'], 'ambiguous_soname_candidates')
        rows.pop()
        self.assertEqual(MODULE.dependency_edges(rows)[0]['status'], 'soname_candidate_outside_search')

    def test_origin_runpath_and_architecture_are_checked(self):
        rows = [elf_row('/app/bin/app', needed=['libx.so'], runpath='$ORIGIN/../lib'),
                elf_row('/app/lib/libx.so', soname='libx.so')]
        self.assertEqual(MODULE.dependency_edges(rows)[0]['target'], '/app/lib/libx.so')
        rows[1]['elf']['machine'] = 'EM_X86_64'
        self.assertEqual(MODULE.dependency_edges(rows)[0]['status'], 'unresolved')


if __name__ == '__main__': unittest.main()
