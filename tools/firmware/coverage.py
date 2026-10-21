#!/usr/bin/env python3
"""Produce path coverage; path categories are navigation hints, not verified functions."""
import argparse
from collections import Counter
import csv
import json
from pathlib import Path

GROUPS = [
    ('boot_update_recovery', ('/boot','recovery','upgrade','/systemd/','/init','/modules/')),
    ('capture_af_lens', ('capture','/libsif','mm-photo','lens','autofocus','/libface','/libpalm')),
    ('video_audio_display', ('camcorder','video','movie','audio','sound','display','hdmi')),
    ('storage_media', ('storage','/libdcm','filelist','media','sqlite','/dbspace')),
    ('connectivity', ('network','allshare','dlna','wifi','bluetooth','nfc','mtp','usb','sap-')),
    ('power_thermal', ('power','thermal','battery','sysman','hibernat','/hib_')),
    ('ui_configuration', ('camera-app','elementary','/edje','/evas','prefman','vconf','/config','/locale')),
]

def classify(path):
    return [name for name, hints in GROUPS if any(x in path.lower() for x in hints)] or ['unclassified']

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--inventory',type=Path,required=True)
    p.add_argument('--output',type=Path,required=True)
    args=p.parse_args(); args.output.mkdir(parents=True,exist_ok=True)
    tree=json.loads((args.inventory/'filesystem_inventory.json').read_text())
    available=json.loads((args.inventory/'selected_inventory.json').read_text())
    by_path={(r['partition'],r['original_path']):r for r in available}
    summary=Counter()
    with (args.output/'file_coverage.csv').open('w',newline='') as f:
        w=csv.DictWriter(f,fieldnames=['partition','path','inode','type','size','navigation_groups','bytes_status','sha256','analysis_status'])
        w.writeheader()
        for item in tree:
            found=by_path.get((item['partition'],item['path']))
            groups=classify(item['path'])
            summary.update(groups)
            w.writerow(dict(partition=item['partition'],path=item['path'],inode=item['inode'],type=hex(item['type']),
                size=item['size'],navigation_groups='|'.join(groups),bytes_status='verified_selected' if found else 'inherited_listing_only',
                sha256=found['measured_sha256'] if found else '',analysis_status='pending'))
    (args.output/'coverage_summary.json').write_text(json.dumps(dict(entries=len(tree),overlapping_path_hints=dict(summary),
        warning='Groups are overlapping filename hints. Pending remains pending after import; no full-firmware completion claim.'),indent=2)+'\n')
    print((args.output/'coverage_summary.json').read_text())

if __name__=='__main__': main()
