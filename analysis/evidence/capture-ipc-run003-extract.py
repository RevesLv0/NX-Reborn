from pathlib import Path
from elftools.elf.elffile import ELFFile
from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM, CS_MODE_THUMB, CS_MODE_LITTLE_ENDIAN
import hashlib,json
selection={
 'libuser-spec.so': ['_Z20get_virtual_address_jjiPjS_','pref_rtos_get_fd','pref_rtos_get_bytes','pref_rtos_set_bytes','_Z39User_Spec_Get_Rtos_Pref_Next_Shot_Readyv','_Z33User_Spec_Get_Rtos_Pref_Lens_Infov'],
 'libmulticore-bridge.so': ['_ZN7CSender4SendEtttPh','_ZN6CFrame5BuildEP13stFrameHeaderPh','_ZN6CFrame4SendEv','_ZN13CIPCCDriverIf4SendEPhj','_ZN13CIPCCDriverIf7ReceiveEPhj','_ZN13CIPCCDriverIf4OpenEv','_ZN16CMulticoreBridge4sendEtttPh','_ZN7CSender11createFrameEtttPh','_ZN9CReceiver15checkInitPacketEv'],
 'libprefman.so':['pref_get_bytes','pref_set_bytes','pref_lock_sync','pref_unlock_sync'],
 'libdi-sensor.so':['_ZN14csensor_module12sendDfmsMsgqEPKcll'],
 'libudd5.so':['ipcc_read_pkt','ipcc_write_pkt','ipcc_open','ipcc_raw_send_interrupt'],
 'libdiosal.so':['_msgqueue_send','_msgqueue_trysend']}
rows=[]
for name,names in selection.items():
 p=Path('.work/run003/capture/inputs')/name
 with p.open('rb') as f:
  e=ELFFile(f);syms=e.get_section_by_name('.dynsym'); lookup={s.name:s for s in syms.iter_symbols()}
  plt=e.get_section_by_name('.plt');rel=e.get_section_by_name('.rel.plt')
  # Resolve ARM PLT add/add/ldr sequences to relocation GOT slots. Thumb veneers
  # make fixed 12-byte-entry indexing incorrect for mixed ARM/Thumb libraries.
  got_names={r['r_offset']:syms.get_symbol(r['r_info_sym']).name for r in rel.iter_relocations()}
  plt_names={};pb=plt.data()
  def imm_rot(w):
   v=w&255;n=((w>>8)&15)*2
   return ((v>>n)|(v<<(32-n)))&0xffffffff if n else v
  for pos in range(0,len(pb)-11,4):
   a,b,c=[int.from_bytes(pb[pos+k:pos+k+4],'little') for k in (0,4,8)]
   if (a&0xfffff000)==0xe28fc000 and (b&0xfffff000)==0xe28cc000 and (c&0xfffff000)==0xe5bcf000:
    va=plt['sh_addr']+pos;got=va+8+imm_rot(a)+imm_rot(b)+(c&0xfff)
    if got in got_names:
     plt_names[hex(va)]=got_names[got]
     if pos>=4 and pb[pos-4:pos]==bytes.fromhex('7847c046'):plt_names[hex(va-4)]=got_names[got]
  for name in names:
   s=lookup[name];encoded=s['st_value'];va=encoded&~1;thumb=bool(encoded&1);sec=e.get_section(s['st_shndx']);off=sec['sh_offset']+va-sec['sh_addr'];f.seek(off);data=f.read(s['st_size']);cs=Cs(CS_ARCH_ARM,(CS_MODE_THUMB if thumb else CS_MODE_ARM)|CS_MODE_LITTLE_ENDIAN)
   ins=[]
   for i in cs.disasm(data,va):
    r={'original_elf_va':hex(i.address),'file_offset':hex(off+i.address-va),'instruction':i.mnemonic+' '+i.op_str}
    if i.mnemonic in ['b','bl','blx'] and i.op_str.startswith('#0x'):r['plt_symbol']=plt_names.get(i.op_str[1:])
    ins.append(r)
   rows.append({'firmware_path':'/usr/lib/'+p.name,'sha256':hashlib.sha256(p.read_bytes()).hexdigest(),'symbol':name,'symbol_st_value':hex(encoded),'original_elf_va':hex(va),'file_offset':hex(off),'symbol_bytes':s['st_size'],'mode':'Thumb' if thumb else 'ARM','instructions':ins})
Path('.work/run003/capture/capstone-targets.json').write_text(json.dumps({'method':'pyelftools dynsym/section file-offset mapping, Capstone ARM or Thumb according to ELF symbol bit zero, ARM PLT add/add/ldr GOT-slot resolution to ELF relocations; no target execution','limitations':'Linear symbol-size listings include literal pools and padding after code. Symbol signatures and driver in/out records are not ABI verified.','functions':rows},indent=2)+'\n')
