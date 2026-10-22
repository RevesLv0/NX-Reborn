#!/usr/bin/env python3
"""Offline original-ELF transfer callback evidence. Run with PYTHONPATH=.work/python."""
import hashlib,json,re
from pathlib import Path
from capstone import Cs,CS_ARCH_ARM,CS_MODE_ARM
from elftools.elf.elffile import ELFFile
ROOT=Path(__file__).resolve().parents[2]
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def mapped(e,va,n):
 for s in e.iter_segments():
  if s['p_type']=='PT_LOAD' and s['p_vaddr']<=va and va+n<=s['p_vaddr']+s['p_filesz']:return s['p_offset']+va-s['p_vaddr']
 raise ValueError(hex(va))
W={
 'libdi-network-dlna-api.so':[(0x411f8,8),(0x41328,60),(0x435e4,60),(0x41e30,40),(0x4edd8,52),(0x4ee94,24),(0x59068,40),(0x40d5c,32),(0x213a8,44),(0x16148,24),(0x4c15c,48),(0x4c28c,52),(0x4d400,36),(0x4bcd8,100),(0x43328,88),(0x42d30,48),(0x430a0,48),(0x55ae4,20),(0x41890,40),(0x47e6c,56)],
 'smart-wifi-app':[(0x59464,12),(0x5a368,64),(0x5a1dc,40),(0x58300,88),(0x58418,24),(0x4a0c4,28),(0x4cd30,56),(0x810c8,16),(0x81220,40),(0x7b0bc,4),(0x64068,36)]}
result={'schema_version':1,'static_only':True,'address_convention':'Original ELF link-time VAs; offsets independently mapped through PT_LOAD. Ghidra API instructions/C use VA +0x10000; APP same VA.','sources':[],'decompiled_selections':[],'limitations':['No target execution, live symbol binding, device I/O or receiver durability observations.','Default-visible dynamic symbols can be interposed. Relocations establish intended link references, not observed runtime resolution.','Inferred types and object fields need ABI validation.']}
inputs=json.loads((ROOT/'.work/run002/input-manifest.json').read_text())
for name,windows in W.items():
 item=next(x for x in inputs if Path(x['path']).name==name);p=ROOT/item['staged_path'];original=ROOT/'.work/full/extracted/rootfs'/item['path'].lstrip('/')
 assert sha(p)==item['sha256']==sha(original)
 with p.open('rb') as f:
  e=ELFFile(f);data=p.read_bytes();out={'firmware_path':item['path'],'staged_path':item['staged_path'],'source_sha256':sha(p),'original_sha256':sha(original),'windows':[],'relocations':[],'dynamic_tags':[],'resolved_literals':[]}
  for va,n in windows:
   off=mapped(e,va,n);b=data[off:off+n];ins=list(Cs(CS_ARCH_ARM,CS_MODE_ARM).disasm(b,va));assert sum(i.size for i in ins)==n
   out['windows'].append({'original_elf_va':hex(va),'file_offset':hex(off),'bytes':n,'instructions':[{'va':hex(i.address),'bytes':i.bytes.hex(),'mnemonic':i.mnemonic,'operands':i.op_str} for i in ins]})
  for sec in e.iter_sections():
   if sec['sh_type'] not in ('SHT_REL','SHT_RELA'):continue
   table=e.get_section(sec['sh_link'])
   for r in sec.iter_relocations():
    sym=table.get_symbol(r['r_info_sym']);nm=sym.name
    if (name.startswith('libdi') and (0x81340<=r['r_offset']<0x81380 or any(x in nm for x in ('gSelectivePushCallback','SNPushClientNotificationCallback','SPClientManager11setCallback','_ZTV15SPClientManager','_ZTV12SPFileStream','fopen64','fread','fclose','__fxstat64','fileno','SPHTTPClientHandlerC1','SPFileStreamC1')))) or (name=='smart-wifi-app' and any(x in nm for x in ('DlnaSelective_NPush_Initialize','g_idle_add'))):
     off=mapped(e,r['r_offset'],4);out['relocations'].append({'section':sec.name,'original_elf_va':hex(r['r_offset']),'file_offset':hex(off),'type_number':r['r_info_type'],'stored_addend_u32':hex(int.from_bytes(data[off:off+4],'little')),'symbol':nm,'symbol_value':hex(sym['st_value']),'symbol_binding':sym['st_info']['bind'],'symbol_visibility':sym['st_other']['visibility'],'defined':sym['st_shndx']!='SHN_UNDEF'})
  def u32(va):return int.from_bytes(data[mapped(e,va,4):mapped(e,va,4)+4],'little')
  if name.startswith('libdi'):
   for label,base,l1,l2,expected in [('manager_vtable_got',0x4133c,0x41378,0x4137c,0x820e4),('file_vtable_got',0x435f8,0x43620,0x43624,0x82038),('registered_client_callback_got',0x58fb4,0x590bc,0x590e0,0x820e0),('set_ui_callback_global_got',0x16158,0x16160,0x16164,0x82100),('dispatch_ui_callback_global_got',0x213c0,0x214e4,0x214e8,0x82100)]:
    value=(base+u32(l1)+u32(l2))&0xffffffff;assert value==expected
    out['resolved_literals'].append({'label':label,'pc_base':hex(base),'literal_1_va':hex(l1),'literal_1_u32':hex(u32(l1)),'literal_2_va':hex(l2),'literal_2_u32':hex(u32(l2)),'computed_got_va':hex(value)})
   va=(0x43340+u32(0x43590))&0xffffffff;off=mapped(e,va,4)
   assert data[off:off+3]==b'rb\0'
   out['resolved_literals'].append({'label':'fopen64_mode','pc_base':'0x43340','literal_va':'0x43590','resolved_string_va':hex(va),'value':'rb'})
  else:
   for va,expected in [(0x5952c,0x5a368),(0x58498,0x49fb0)]:
    assert u32(va)==expected
    out['resolved_literals'].append({'literal_va':hex(va),'pointer_value':hex(u32(va))})
  dyn=e.get_section_by_name('.dynamic')
  if dyn:
   for tag in dyn.iter_tags():
    if tag.entry.d_tag in ('DT_NEEDED','DT_SYMBOLIC','DT_FLAGS','DT_FLAGS_1'):out['dynamic_tags'].append(str(tag))
  result['sources'].append(out)
needed={'SelectivePushSendEventToUI','SPClientManager::setCallback','SPClientManager::SPClientManager','SPFileStream::SPFileStream','SPFileStream::Open','SPFileStream::GetData','SPFileStream::Close','SNPushStart','DlnaSelective_NPush_Initialize','DlnaSelectivePushSetCallback','CSNetworkAPI::handleSmartphoneLink','CSNetworkAPI::responseToUI','CSNetworkAPI::ConvertNetworkToUiEventId','CSNetworkAPI::ConvertNetworkToUiEventStatus','UI_Event_Send_Manager','CAPPUIApplication::dispatch','CAPPNetworkSmartphoneLinkState::handleNetworkEvent','CAPPNetworkSmartphoneLinkState::handle'}
for stage in ['transfer','transfer-consumer','transfer-binding','transfer-outcome','transfer-dispatch']:
 for p in sorted((ROOT/'.work/run004'/stage/'outputs/ghidra').glob('*/decompiled.jsonl')):
  for line in p.read_text().splitlines():
   d=json.loads(line)
   if d['name'] not in needed:continue
   lines=d['c'].splitlines();selected=[]
   if len(lines)<55:selected=[{'line':i+1,'text':s} for i,s in enumerate(lines)]
   else:
    ix=set()
    for i,s in enumerate(lines):
     if re.search(r'Callback|callback|g_idle_add|param_1 == 0x700|case 0x49|case 0x4[a-d]|case 0x76[0-3]|case 0x13|case 0x12|return 0x76[c-f]|return 0x770|fopen64|fread\(|fclose\(|fileno\(|__fxstat64|\+ 0x18|setCallback|SNPushStart\(|\+ 0x10|\+ 0x78',s):ix.update(range(max(0,i-2),min(len(lines),i+4)))
    selected=[{'line':i+1,'text':lines[i]} for i in sorted(ix)]
   result['decompiled_selections'].append({'artifact':str(p.relative_to(ROOT)),'artifact_sha256':sha(p),'name':d['name'],'original_elf_va':d['elf_va'],'completed':d['completed'],'error':d['error'],'selected_c':selected})
(ROOT/'analysis/evidence/transfer-callbacks-run004.json').write_text(json.dumps(result,indent=2)+'\n')
print(json.dumps({'sources':len(result['sources']),'windows':sum(len(s['windows']) for s in result['sources']),'decompiled_selections':len(result['decompiled_selections'])}))
