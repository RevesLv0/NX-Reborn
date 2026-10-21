#!/usr/bin/env python3
"""Query saved Ghidra address references, preserving a bounded run receipt."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import shutil
import time


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--ghidra',type=Path,required=True)
    ap.add_argument('--jdk',type=Path,required=True)
    ap.add_argument('--project-dir',type=Path,required=True)
    ap.add_argument('--project',required=True)
    ap.add_argument('--input',type=Path,required=True)
    ap.add_argument('--work',type=Path,required=True)
    ap.add_argument('targets',nargs='+')
    args = ap.parse_args()
    assert args.input.is_file() and args.input.read_bytes()[:4] == b'\x7fELF'
    for target in args.targets:
        assert int(target,16) >= 0
    work = args.work.resolve()
    assert not (work/'receipt.json').exists(), 'Use a new work directory to preserve prior attempts'
    for name in ['config','cache','tmp']:
        (work/name).mkdir(parents=True,exist_ok=True)
    env = os.environ.copy()
    env['JAVA_HOME'] = str(args.jdk.resolve())
    env['PATH'] = str(args.jdk.resolve()/'bin') + os.pathsep + env.get('PATH','')
    env['XDG_CONFIG_HOME'] = str(work/'config')
    env['XDG_CACHE_HOME'] = str(work/'cache')
    env['GHIDRA_HEADLESS_MAXMEM'] = '1024M'
    env['GHIDRA_HEADLESS_JAVA_OPTIONS'] = f'-Dapplication.settingsdir={work}/config -Dapplication.cachedir={work}/cache -Dapplication.tempdir={work}/tmp'
    script = Path(__file__).resolve().parent/'ExportAddressReferences.java'
    shutil.copy2(script,work/script.name)
    command = [str(args.ghidra.resolve()/'support/analyzeHeadless'),str(args.project_dir.resolve()),args.project,
               '-process',args.input.name,'-recursive','-noanalysis','-max-cpu','1','-scriptPath',str(script.parent),
               '-postScript',script.name,str(work/'references.json'),*args.targets]
    receipt = dict(started_unix=time.time(),command=command,source_path=str(args.input),
                   source_sha256=digest(args.input),script_sha256=digest(script),
                   runner_sha256=digest(__file__),max_memory='1024M',max_cpu=1,completed=False)
    (work/'receipt.json').write_text(json.dumps(receipt,indent=2)+'\n')
    with (work/'console.log').open('w') as out:
        rc = subprocess.call(command,env=env,stdout=out,stderr=subprocess.STDOUT)
    receipt.update(returncode=rc,finished_unix=time.time())
    if rc == 0:
        result = json.loads((work/'references.json').read_text())
        assert result['source_sha256'].lower() == receipt['source_sha256']
        assert len(result['targets']) == len(args.targets)
        receipt.update(completed=True,output_sha256=digest(work/'references.json'))
    (work/'receipt.json').write_text(json.dumps(receipt,indent=2)+'\n')
    print(json.dumps(receipt))
    raise SystemExit(rc)


if __name__ == '__main__':
    main()
