import importlib.util
from pathlib import Path
import tempfile
import unittest

SPEC = importlib.util.spec_from_file_location('boot_catalog', Path(__file__).parents[1] / 'tools/firmware/boot_catalog.py')
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class BootCatalogTests(unittest.TestCase):
    def test_continuation_comments_repeated_keys_and_line_addresses(self):
        text = '# preamble\n[Unit]\nAfter=a.service \\\n# intervening comment\n b.service\n# comment\nRequires=c.service\nRequires=d.service\n[Service]\nExecStart=/bin/true\n'
        rows = MODULE.parse_unit(text)
        self.assertEqual(rows[0], dict(section='Unit', key='After', value='a.service  b.service', line=3))
        self.assertEqual([row['value'] for row in rows if row['key'] == 'Requires'], ['c.service', 'd.service'])
        self.assertEqual(rows[-1]['section'], 'Service')

    def test_symlink_directory_never_reads_host_or_duplicates_unit(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / 'root'
            units = root / 'usr/lib/systemd/system'
            units.mkdir(parents=True)
            (units / 'sample.service').write_text('[Unit]\nAfter=dbus.service\n[Service]\nExecStart=/camera\n')
            outside = Path(tmp) / 'outside'
            outside.mkdir()
            (outside / 'secret.service').write_text('[Unit]\nAfter=secret\n')
            (units / 'escape').symlink_to(outside, target_is_directory=True)
            (units / 'alias.service').symlink_to('sample.service')
            result = MODULE.catalog(root)
            self.assertEqual(len(result['units']), 1)
            self.assertEqual(len(result['symlinks']), 2)
            self.assertEqual(result['declared_unit_edges'][0]['target'], 'dbus.service')
            self.assertNotIn('secret', str(result))

    def test_binary_selected_file_is_not_fabricated_text(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            path = root / 'fw'
            path.write_bytes(b'\x7fELF\0payload')
            result = MODULE.file_record(root, path)
            self.assertNotIn('lines', result)
            self.assertEqual(result['bytes'], 12)


if __name__ == '__main__':
    unittest.main()
