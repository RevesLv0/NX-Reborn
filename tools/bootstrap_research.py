#!/usr/bin/env python3
"""Install pinned offline-analysis tools into ignored workspace storage."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import urllib.request
import zipfile

GHIDRA='ghidra_12.1.4_PUBLIC'
JDK='jdk-21.0.12.1+1'
ASSETS=[
    ('ghidra_12.1.4_PUBLIC_20260921.zip',
     'https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_12.1.4_build/ghidra_12.1.4_PUBLIC_20260921.zip',
     'ddac49f903da9d5bac833e5cc79395098b9c33cfd3279be5f31bd00387d2d4db'),
    ('temurin21.tar.gz',
     'https://github.com/adoptium/temurin21-binaries/releases/download/jdk-21.0.12.1%2B1/OpenJDK21U-jdk_x64_linux_hotspot_21.0.12.1_1.tar.gz',
     'ce79869e1307ed8ee1e2baa86a412b1eb5b75d10a01006d788a6f968bcfaee94'),
]

def digest(path):
    h=hashlib.sha256()
    with path.open('rb') as f:
        for chunk in iter(lambda:f.read(1024*1024),b''): h.update(chunk)
    return h.hexdigest()

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--work',type=Path,default=Path('.work'))
    parser.add_argument('--check-only',action='store_true')
    args=parser.parse_args(); root=Path(__file__).resolve().parents[1]
    work=args.work.resolve(); tools=work/'tools'
    tools.mkdir(parents=True,exist_ok=True)
    receipts=[]
    for name,url,expected in ASSETS:
        archive=tools/name
        if not archive.exists():
            if args.check_only: raise SystemExit(f'Missing archive: {name}')
            partial=tools/(name+'.partial')
            with urllib.request.urlopen(url,timeout=120) as response, partial.open('wb') as output:
                shutil.copyfileobj(response,output)
            if digest(partial)!=expected: raise SystemExit(f'Download integrity mismatch: {name}')
            partial.replace(archive)
        if digest(archive)!=expected: raise SystemExit(f'Archive integrity mismatch: {name}')
        receipts.append(dict(name=name,url=url,sha256=expected,bytes=archive.stat().st_size))
    if not (tools/GHIDRA/'support/analyzeHeadless').exists():
        if args.check_only: raise SystemExit('Missing Ghidra installation')
        with zipfile.ZipFile(tools/ASSETS[0][0]) as z:
            for item in z.infolist():
                target=(tools/item.filename).resolve()
                if not target.is_relative_to(tools): raise ValueError('Unsafe archive path')
            z.extractall(tools)
            for item in z.infolist():
                if not item.is_dir():
                    mode=(item.external_attr>>16)&0o777
                    if mode: (tools/item.filename).chmod(mode)
    if not (tools/JDK/'bin/javac').exists():
        if args.check_only: raise SystemExit('Missing full JDK installation')
        with tarfile.open(tools/ASSETS[1][0]) as archive:
            archive.extractall(tools,filter='data')
    props=(tools/GHIDRA/'Ghidra/application.properties').read_text()
    if 'application.version=12.1.4\n' not in props: raise SystemExit('Unexpected Ghidra version')
    subprocess.run([str(tools/JDK/'bin/javac'),'-version'],check=True)
    if not args.check_only:
        subprocess.run([sys.executable,'-m','pip','install','--target',str(work/'python'),
                        '-r',str(root/'tools/requirements-research.txt')],check=True)
    env=os.environ.copy(); env['PYTHONPATH']=str(work/'python')
    subprocess.run([sys.executable,'-c','import elftools,capstone; assert elftools.__version__=="0.32"; assert capstone.__version__=="5.0.6"'],env=env,check=True)
    (work/'bootstrap-receipt.json').write_text(json.dumps(dict(assets=receipts,ghidra=str(tools/GHIDRA),jdk=str(tools/JDK),check_only=args.check_only),indent=2)+'\n')
    print('Pinned research toolchain verified')

if __name__=='__main__': main()
