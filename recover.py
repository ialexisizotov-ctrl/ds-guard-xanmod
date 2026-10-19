#!/usr/bin/env python3
import json
from pathlib import Path
from transaction import rollback,valid_txn
p=Path('/var/lib/ds-guard-safe/current.json')
if p.exists():rollback(valid_txn(json.loads(p.read_text())['transaction']))
