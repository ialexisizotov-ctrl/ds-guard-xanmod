#!/usr/bin/env python3
import json,subprocess,sys
from pathlib import Path
from transaction import valid_txn
p=Path('/var/lib/ds-guard-safe/current.json')
if p.exists():
    txn=valid_txn(json.loads(p.read_text())['transaction'])
    if (txn/'transaction.py').is_file():
        sys.exit(subprocess.run(['/usr/bin/python3',str(txn/'transaction.py'),'rollback',str(txn)]).returncode)
