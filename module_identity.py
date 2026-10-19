"""Compare the loaded ELF build-id note with the verified module on disk."""
import gzip,lzma,struct,subprocess
from pathlib import Path
def build_note(path):
 p=Path(path);data=p.read_bytes()
 if p.suffix=='.xz':data=lzma.decompress(data)
 elif p.suffix=='.gz':data=gzip.decompress(data)
 elif p.suffix=='.zst':data=subprocess.check_output(['zstd','-q','-d','-c',str(p)],timeout=30)
 if len(data)>128*1024**2 or data[:6]!=b'\x7fELF\x02\x01':raise ValueError('Unsupported module ELF')
 off=struct.unpack_from('<Q',data,40)[0];size,count,names=struct.unpack_from('<HHH',data,58)
 if size!=64 or not 0<count<4096 or names>=count or off+size*count>len(data):raise ValueError('Invalid ELF section table')
 sections=[struct.unpack_from('<IIQQQQIIQQ',data,off+i*size) for i in range(count)]
 s=sections[names];strings=data[s[4]:s[4]+s[5]]
 for s in sections:
  name=strings[s[0]:].partition(b'\0')[0]
  if name==b'.note.gnu.build-id':
   if s[4]+s[5]>len(data):raise ValueError('Invalid ELF note')
   return data[s[4]:s[4]+s[5]]
 raise ValueError('Module has no build-id note; loaded identity cannot be verified')
def loaded_matches(path):
 note=Path('/sys/module/xt_ndpi/notes/.note.gnu.build-id')
 return note.is_file() and note.read_bytes()==build_note(path)
