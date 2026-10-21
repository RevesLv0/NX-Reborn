#!/usr/bin/env python3
"""Run offline Ghidra, keeping its database, caches and logs outside tracked state."""
import argparse
import os
from pathlib import Path
import subprocess
import hashlib
import json
import time
import uuid
from validate_exports import validate_export

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--ghidra', required=True, type=Path)
parser.add_argument('--input', required=True, type=Path)
parser.add_argument('--work', required=True, type=Path)
parser.add_argument('--project', default='NX500_FW112')
parser.add_argument('--project-dir', type=Path, help='Ghidra rejects project paths with dot-prefixed components')
parser.add_argument('--jdk', type=Path, help='Full JDK, not a Java runtime only')
parser.add_argument('--timeout', default=300, type=int)
parser.add_argument('--decompile-budget', default=35, type=int)
parser.add_argument('--pattern')
parser.add_argument('--process',action='store_true',help='Export an already imported program')
parser.add_argument('--skip-analysis',action='store_true')
args = parser.parse_args()
args.work = args.work.resolve()
project_dir=(args.project_dir or Path(__file__).resolve().parents[2]/'ghidra-projects').resolve()
project_dir.mkdir(parents=True,exist_ok=True)
for sub in ('projects','outputs/ghidra','logs','config','cache','tmp'):
    (args.work/sub).mkdir(parents=True,exist_ok=True)
env=os.environ.copy()
if args.jdk:
    env['JAVA_HOME']=str(args.jdk.resolve())
    env['PATH']=str(args.jdk.resolve()/'bin')+os.pathsep+env.get('PATH','')
env['XDG_CONFIG_HOME']=str(args.work/'config')
env['XDG_CACHE_HOME']=str(args.work/'cache')
env['GHIDRA_HEADLESS_MAXMEM']='3G'
env['GHIDRA_HEADLESS_JAVA_OPTIONS']=f'-Dapplication.settingsdir={args.work}/config -Dapplication.cachedir={args.work}/cache -Dapplication.tempdir={args.work}/tmp'
scripts=Path(__file__).resolve().parent
run_id=str(uuid.uuid4())
pattern=args.pattern or '(?i)(captureSaveDone|SIFListener|runFromCapture|UI_Capture_File_Write_Done|UI_BT_Send_Contents|DMS|SendFileThruGet|RetriveFilePath|GetFilePathFromURI|DlnaGetContentUri|StartHTTPServer|createFileTransfer|jpegResize|WiFi.*(Start|Stop)|Wifi.*(Start|Stop)|fw_upgrade)'
command=[str(args.ghidra.resolve()/'support/analyzeHeadless'),str(project_dir),args.project,
         '-process' if args.process else '-import',('*' if args.input.is_dir() else args.input.name) if args.process else str(args.input.resolve()),'-analysisTimeoutPerFile',str(args.timeout),'-max-cpu','2',
         '-scriptPath',str(scripts),'-postScript','ExportEvidence.java',str(args.work/'outputs/ghidra'),
         pattern,str(args.decompile_budget),run_id,'-log',str(args.work/'logs'/f'{args.project}.log'),
         '-scriptlog',str(args.work/'logs'/f'{args.project}-script.log')]
if args.input.is_dir(): command+=['-recursive']
if args.skip_analysis: command+=['-noanalysis']
started=time.time()
receipt=args.work/'logs'/f'{args.project}-{run_id}.json'
metadata=dict(run_id=run_id,started_unix=started,command=command,
              exporter_sha256=hashlib.sha256((scripts/'ExportEvidence.java').read_bytes()).hexdigest(),completed=False)
receipt.write_text(json.dumps(metadata,indent=2)+'\n')
result=subprocess.call(command,env=env)
if result==0:
    inputs=[args.input] if args.input.is_file() else [p for p in args.input.rglob('*') if p.is_file() and p.open('rb').read(4)==b'\x7fELF']
    if not inputs: raise SystemExit('No ELF inputs found for export validation.')
    for source in inputs:
        sha=hashlib.sha256(source.read_bytes()).hexdigest()
        summary=args.work/'outputs/ghidra'/f'{source.name}-{sha[:12]}'/'summary.json'
        validate_export(summary.parent,sha,run_id)
metadata.update(completed=result==0,returncode=result,finished_unix=time.time())
receipt.write_text(json.dumps(metadata,indent=2)+'\n')
raise SystemExit(result)
