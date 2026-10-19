#!/usr/bin/env python3
import hashlib,json,sys
from pathlib import Path
root=Path(sys.argv[1]).resolve();here=Path(__file__).resolve().parent
pins=json.loads((here/'source-hashes.json').read_text())
changes={
 'src/include/ndpi_typedefs.h':('struct hash_ip4p        tbl[0];','struct hash_ip4p        tbl[];'),
 'ndpi-netfilter/src/Makefile':('ccflags-y += -femit-struct-debug-detailed=any','ccflags-y += $(call cc-option,-femit-struct-debug-detailed=any)'),
 'ndpi-netfilter/src/main.c':('#else\n#include "livepatch/v6.0.c"','#elif LINUX_VERSION_CODE >= KERNEL_VERSION(7,2,0)\n#include "livepatch/v7.2.c"\n#else\n#include "livepatch/v6.0.c"')
}
for name, (old,new) in changes.items():
 p=root/name;s=p.read_text();sha=hashlib.sha256(p.read_bytes()).hexdigest()
 if sha==pins[name]['patched']:continue
 if sha!=pins[name]['original'] or s.count(old)!=1:raise SystemExit('Unexpected upstream source: '+name)
 updated=s.replace(old,new)
 if hashlib.sha256(updated.encode()).hexdigest()!=pins[name]['patched']:raise SystemExit('Patch digest mismatch: '+name)
 p.write_text(updated)
(root/'ndpi-netfilter/src/livepatch/v7.2.c').write_bytes((here/'v7.2.c').read_bytes())
