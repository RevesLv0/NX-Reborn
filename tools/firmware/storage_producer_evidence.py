#!/usr/bin/env python3
"""Reproduce RUN005 bounded storage callback evidence from original ARM ELF bytes."""
import argparse, hashlib, json, struct
from pathlib import Path
from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM
from elftools.elf.elffile import ELFFile

HASHES = {'libsif.so': '9790fc02fe5b9793fc09da7eb5fd9453c730a55880654c84caf02dd3d1001109', 'libmm-photo.so': 'ea4ae65608a6f9ea0761e35c18764401cf7b876652f7949c322e880fa9f68ca9'}
WINDOWS = {
 'libsif.so': [(0xfab8,64),(0x123c4,76),(0x38d4c,112),(0x38e20,48),(0x3c680,112),(0x3e378,96),(0x7cef0,112),(0x86eb0,32),(0x88234,136),(0x89e00,240),(0x2cc34,64),(0x2d2f8,72),(0x338e0,36),(0x89d74,60),(0x313d0,88),(0x5a1e4,96),(0x5ad4c,80),(0x5a858,104)],
 'libmm-photo.so': [(0x96684,32),(0x96750,52),(0x98bb4,120),(0x96f10,88),(0x97308,112),(0x97fd0,84),(0x98358,24),(0x983f0,28),(0x98d0c,40),(0x8e0f8,72),(0x81ca4,392),(0x9efb0,68),(0x9f080,68),(0x9f520,32),(0xa098c,28),(0x93b50,64),(0x90874,148)]}
# Each proof resolves a literal GOT base and offset from the original ELF.
GOT = {
 'libsif.so': [('SaveExifImage callback',0x86ec8,0x87e20,0x8808c,'_ZN8DscImage10JpegDoneExEjjj')],
 'libmm-photo.so': [('runFromCapture listener',0x9669c,0x97560,0x97568,'_ZN14ImageGenerator11SIFListenerEiii'),('runFromCapture status queue',0x9669c,0x97560,0x98ffc,'StorageStateQueue'),('SIFListener idle function',0x9f09c,0xa0068,0xa033c,'_ZN14ImageGenerator15captureSaveDoneEv')]}

def digest(p): return hashlib.sha256(p.read_bytes()).hexdigest()
def collect(root, name):
 path=root/'usr/lib'/name
 assert digest(path)==HASHES[name], path
 with path.open('rb') as stream:
  elf=ELFFile(stream)
  def offset(va,size=4):
   seg=next(s for s in elf.iter_segments() if s['p_type']=='PT_LOAD' and s['p_vaddr']<=va and va+size<=s['p_vaddr']+s['p_filesz'])
   return seg['p_offset']+va-seg['p_vaddr']
  def word(va):
   stream.seek(offset(va)); return struct.unpack('<I',stream.read(4))[0]
  out={'path':'/usr/lib/'+name,'sha256':HASHES[name],'windows':[],'relocations':[],'got_literal_proofs':[]}
  for va,size in WINDOWS[name]:
   off=offset(va,size);stream.seek(off);data=stream.read(size)
   instructions=[{'original_elf_va':hex(i.address),'file_offset':hex(off+i.address-va),'bytes':i.bytes.hex(),'mnemonic':i.mnemonic,'operands':i.op_str} for i in Cs(CS_ARCH_ARM,CS_MODE_ARM).disasm(data,va)]
   out['windows'].append({'original_elf_va':hex(va),'file_offset':hex(off),'requested_bytes':size,'raw_bytes':data.hex(),'decoded_bytes':sum(len(bytes.fromhex(i['bytes'])) for i in instructions),'instructions':instructions,'limitation':'Bounded linear ARM disassembly; bytes are authoritative, control-flow recovery is not implied. Known trailing literals excluded from JpegDoneEx, afterStorageException, file destructor and status helper windows.'})
  syms=elf.get_section_by_name('.dynsym')
  out['selected_symbols']=[{'symbol':s.name,'original_elf_va':hex(s['st_value']),'size':s['st_size'],'section':s['st_shndx']} for s in syms.iter_symbols() if any(k in s.name for k in ['StorageStateQueue','SIFListener','JpegDoneEx','captureSaveDone','m_pFileSaveDoneNotification','m_fileSaveDoneParam','m_SIFMsgRemainCount'])]
  rels={}
  for sec in elf.iter_sections():
   if sec['sh_type']!='SHT_REL':continue
   tab=elf.get_section(sec['sh_link'])
   for rel in sec.iter_relocations():
    sym=tab.get_symbol(rel['r_info_sym']);addr=rel['r_offset']
    row={'original_elf_va':hex(addr),'file_offset':hex(offset(addr)),'type':rel['r_info_type'],'symbol':sym.name,'symbol_value':hex(sym['st_value'])}
    rels[addr]=row
    if any(k in sym.name for k in ['StorageStateQueue','SIFListener','JpegDoneEx','captureSaveDone','captureNotify','mm_photo_capture_callback','NotifyE','SaveExifImage','m_pFileSaveDoneNotification','m_fileSaveDoneParam','fclose','fwrite']):out['relocations'].append(row)
  for label,pc,base_lit,off_lit,symbol in GOT[name]:
   base=(pc+8+word(base_lit))&0xffffffff;addr=(base+word(off_lit))&0xffffffff
   assert rels[addr]['symbol']==symbol,(label,hex(addr))
   out['got_literal_proofs'].append({'label':label,'pc_add_instruction':hex(pc),'base_literal_va':hex(base_lit),'base_literal_word':hex(word(base_lit)),'computed_got_base':hex(base),'offset_literal_va':hex(off_lit),'offset_literal_word':hex(word(off_lit)),'computed_slot':hex(addr),'relocation':rels[addr]})
  return out

def main():
 ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--root',type=Path,required=True);ap.add_argument('--work',type=Path,default=Path('.work/run005/storage'));ap.add_argument('--output',type=Path,required=True);args=ap.parse_args()
 result={'schema_version':1,'scope':'Offline static only; runtime bindings and execution order unobserved','method':'Original source SHA verification, PT_LOAD file mapping, Capstone ARM byte windows, ELF GOT relocation arithmetic; Ghidra C separately retained with provenance','sources':[collect(args.root,n) for n in HASHES],'selected_decompilation':[],'queue_push_direct_call_candidates':[]}
 for generation in ['initial','binding','notify','status']:
  for f in sorted((args.work/generation/'outputs/ghidra').glob('*/decompiled.jsonl')):
   summary=json.load((f.parent/'summary.json').open())
   for r in map(json.loads,f.open()):
    result['selected_decompilation'].append({'generation':generation,'artifact':str(f),'artifact_sha256':digest(f),'source_sha256':summary['sha256'],**{k:v for k,v in r.items() if k!='instructions'}})
 # Reuse the completed RUN003 JPEG body; preserve its provenance, not a new completion.
 old=Path('.work/run003/jpeg-expanded/outputs/ghidra/libsif.so-9790fc02fe5b/decompiled.jsonl')
 for r in map(json.loads,old.open()):
  if r['name']=='DscJPEG::taskMain':
   lines=r['c'].splitlines();result['inherited_jpeg_excerpt']={'artifact':str(old),'artifact_sha256':digest(old),'source_sha256':HASHES['libsif.so'],'original_elf_va':r['elf_va'],'completed':r['completed'],'c_ranges':[{'first_line':a,'last_line':b,'c':'\n'.join(lines[a-1:b])} for a,b in [(609,642),(1434,1467)]],'limitation':'Inherited successful RUN003 decompilation; original bytes independently reproduced in RUN005 windows. Function body recovery extent unresolved.'}
 calls=args.work/'initial/outputs/ghidra/libmm-photo.so-ea4ae65608a6/calls.jsonl'
 for r in map(json.loads,calls.open()):
  if r['caller'].startswith('ImageGenerator::') and 'queue<StorageState' in r['callee'] and r['callee'].endswith('::push'):result['queue_push_direct_call_candidates'].append(r)
 result['queue_push_search']={'artifact':str(calls),'sha256':digest(calls),'limitation':'Direct exported calls only; does not exclude inlined, indirect, external or aliased mutations.'}
 args.output.write_text(json.dumps(result,indent=2)+'\n')
 print(json.dumps({'sources':len(result['sources']),'selected_decompilation':len(result['selected_decompilation']),'windows':sum(len(s['windows']) for s in result['sources']),'output_sha256':digest(args.output)}))
if __name__=='__main__':main()
