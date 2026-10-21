import importlib.util
from pathlib import Path
import stat
import sys
import tempfile
import unittest
from unittest.mock import patch
import hashlib

DIRECTORY = Path(__file__).resolve().parents[1]/'tools/firmware'
sys.path.insert(0, str(DIRECTORY))
SPEC = importlib.util.spec_from_file_location('native_ext4', DIRECTORY/'native_ext4.py')
native = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(native)


class NativeExt4Tests(unittest.TestCase):
    def test_listing_keeps_source_inode_owner_and_ignores_deleted_slots(self):
        text = ('debugfs: ls -p <2>\n/2/040755/0/0/.//\n/0/000000/0/0//0/\n'
                '/12/100600/5000/23/private file/17/\n/14/020666/0/0/null/0/\n')
        rows = native.list_entries(text)[2]
        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[0]['uid'], 5000)
        self.assertEqual(rows[0]['name'], 'private file')
        self.assertEqual(rows[1]['mode'], stat.S_IFCHR | 0o666)

    def test_unparsed_listings_are_rejected_instead_of_silently_truncated(self):
        for text in ('debugfs: ls -p <2>\ncorrupt listing\n', '/2/040755/0/0/name//\n'):
            with self.assertRaises(ValueError):
                native.list_entries(text)

    def test_special_omission_recorded_and_external_symlink_not_followed(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root/'link').symlink_to('/does-not-exist-on-host')
            rows = [dict(path='/link', type=stat.S_IFLNK, size=23, link='/does-not-exist-on-host'),
                    dict(path='/null', type=stat.S_IFCHR, size=0)]
            rows[0]['size'] = len(rows[0]['link'])
            report = native.check_tree(rows, root)
            self.assertTrue(report['all_regular_directory_symlink_paths_match'])
            self.assertFalse(report['all_paths_types_sizes_match'])
            self.assertEqual(report['unmaterialized_special_paths'], ['/null'])
            self.assertFalse(report['byte_hashes_verified'])

    def test_missing_regular_file_and_wrong_symlink_target_are_errors(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root/'link').symlink_to('wrong')
            rows = [dict(path='/missing', type=stat.S_IFREG, size=0),
                    dict(path='/link', type=stat.S_IFLNK, size=5, link='right')]
            report = native.check_tree(rows, root)
            self.assertFalse(report['all_regular_directory_symlink_paths_match'])
            self.assertEqual(report['missing_materializable'], ['/missing'])
            self.assertEqual(report['errors'][0]['error'], 'symlink_target_mismatch')

    def test_native_stat_preserves_symlink_size_and_device_identity(self):
        rows = [dict(inode=12, type=stat.S_IFLNK), dict(inode=13, type=stat.S_IFCHR)]
        output = ('debugfs: stat <12>\nInode: 12   Type: symlink\nUser: 0 Group: 0 Size: 7\n'
                  'Fast link dest: "/target"\ndebugfs: stat <13>\nInode: 13   Type: character special\n'
                  'User: 0 Group: 0 Size: 0\nDevice major/minor number: 01:03 (hex 01:03)\n')
        with patch.object(native, 'run_debugfs', return_value=output):
            native.enrich_metadata(rows, None, None, {})
        self.assertEqual(rows[0]['link'], '/target')
        self.assertEqual(rows[1]['device_major'], 1)
        self.assertEqual(rows[1]['device_minor'], 3)

    def test_same_size_source_inode_readback_mismatch_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root/'file').write_bytes(b'wrong')
            rows = [dict(path='/file', type=stat.S_IFREG, inode=12, size=5)]
            def source_dump(debugfs, image, commands, env):
                Path(commands[0].rsplit(' ', 1)[1]).write_bytes(b'right')
                return ''
            with patch.object(native, 'run_debugfs', side_effect=source_dump), self.assertRaises(ValueError):
                native.verify_regular_bytes(rows, root, None, None, {})
            self.assertNotIn('sha256', rows[0])


if __name__ == '__main__':
    unittest.main()
