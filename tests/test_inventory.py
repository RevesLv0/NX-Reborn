import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

SCRIPT=Path(__file__).resolve().parents[1]/'tools/firmware/inventory.py'


class InventoryIntegrityTests(unittest.TestCase):
    def fixture(self, root):
        inputs=root/'inputs'; legacy=root/'legacy'
        inputs.mkdir(); legacy.mkdir()
        data=b'known firmware fixture\n'
        (inputs/'config').write_bytes(data)
        manifest={'items':[{'partition':'rootfs','original_path':'/config','archive_path':'config',
            'bytes':len(data),'sha256':hashlib.sha256(data).hexdigest()}]}
        (inputs/'EVIDENCE_MANIFEST.json').write_text(json.dumps(manifest))
        row={'path':'/unavailable','inode':12,'type':32768,'mode':'0o100644','size':123}
        (legacy/'rootfs_tree.json').write_text(json.dumps([row]))
        (legacy/'opt_tree.json').write_text('[]')
        return inputs,legacy

    def run_inventory(self,root,inputs,legacy):
        return subprocess.run([sys.executable,str(SCRIPT),'--input',str(inputs),'--legacy',str(legacy),
            '--output',str(root/'out')],capture_output=True,text=True,env=os.environ.copy())

    def test_same_size_tamper_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp); inputs,legacy=self.fixture(root)
            data=bytearray((inputs/'config').read_bytes()); data[0]^=1
            (inputs/'config').write_bytes(data)
            result=self.run_inventory(root,inputs,legacy)
            self.assertNotEqual(result.returncode,0)
            self.assertIn('Input mismatch',result.stderr)
            self.assertFalse((root/'out/selected_inventory.json').exists())

    def test_truncation_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp); inputs,legacy=self.fixture(root)
            (inputs/'config').write_bytes(b'known')
            self.assertNotEqual(self.run_inventory(root,inputs,legacy).returncode,0)

    def test_inherited_listing_does_not_become_verified_bytes(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp); inputs,legacy=self.fixture(root)
            result=self.run_inventory(root,inputs,legacy)
            self.assertEqual(result.returncode,0,result.stderr)
            summary=json.loads((root/'out/inventory_summary.json').read_text())
            self.assertFalse(summary['original_zip_revalidated'])
            self.assertFalse(summary['whole_firmware_semantically_analyzed'])
            self.assertEqual(summary['filesystem_listings']['rootfs']['verification'],'inherited_not_reextracted')
            listing=json.loads((root/'out/filesystem_inventory.json').read_text())
            self.assertEqual(listing[0]['byte_status'],'not_yet_reextracted')

    def test_escaping_paths_are_rejected(self):
        for value in ('../outside','/etc/hosts'):
            with self.subTest(value=value), tempfile.TemporaryDirectory() as tmp:
                root=Path(tmp); inputs,legacy=self.fixture(root)
                manifest=json.loads((inputs/'EVIDENCE_MANIFEST.json').read_text())
                manifest['items'][0]['archive_path']=value
                (inputs/'EVIDENCE_MANIFEST.json').write_text(json.dumps(manifest))
                result=self.run_inventory(root,inputs,legacy)
                self.assertNotEqual(result.returncode,0)
                self.assertIn('Unsafe archive_path',result.stderr)

    def test_symlink_source_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp); inputs,legacy=self.fixture(root)
            (inputs/'config').rename(inputs/'real-config')
            (inputs/'config').symlink_to('real-config')
            result=self.run_inventory(root,inputs,legacy)
            self.assertNotEqual(result.returncode,0)
            self.assertIn('Symlinks',result.stderr)

    def test_duplicate_identity_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp); inputs,legacy=self.fixture(root)
            manifest=json.loads((inputs/'EVIDENCE_MANIFEST.json').read_text())
            manifest['items'].append(manifest['items'][0].copy())
            (inputs/'EVIDENCE_MANIFEST.json').write_text(json.dumps(manifest))
            result=self.run_inventory(root,inputs,legacy)
            self.assertNotEqual(result.returncode,0)
            self.assertIn('Duplicate',result.stderr)


if __name__=='__main__': unittest.main()
