#!/usr/bin/env python3
import hashlib,json,sys
from pathlib import Path
root=Path(sys.argv[1]).resolve();here=Path(__file__).resolve().parent
pins=json.loads((here/'source-hashes.json').read_text())
changes=json.loads((here/'source-edits.json').read_text())
prepared={}
for name, replacements in changes.items():
 p=root/name;s=p.read_text();sha=hashlib.sha256(p.read_bytes()).hexdigest()
 if sha==pins[name]['patched']:continue
 if sha!=pins[name]['original']:raise SystemExit('Unexpected upstream source: '+name)
 updated=s
 for old,new in replacements:
  if not updated.count(old):raise SystemExit('Missing source pattern: '+name)
  updated=updated.replace(old,new)
 if hashlib.sha256(updated.encode()).hexdigest()!=pins[name]['patched']:raise SystemExit('Patch digest mismatch: '+name)
 prepared[p]=updated
for p,updated in prepared.items():p.write_text(updated)
(root/'ndpi-netfilter/src/livepatch/v7.2.c').write_bytes((here/'v7.2.c').read_bytes())
