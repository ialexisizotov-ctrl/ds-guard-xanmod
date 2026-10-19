#!/usr/bin/env python3
import argparse,json,os,re,sys
from pathlib import Path
from controller import execute
ap=argparse.ArgumentParser();ap.add_argument('--health-command');args=ap.parse_args()
run_id=os.environ['DS_INSTALL_RUN_ID']
if not re.fullmatch('[0-9a-f-]+',run_id):raise SystemExit('Invalid run identity')
try:rc=execute(args.health_command)
except Exception as e:
 print('FAILED: '+str(e),file=sys.stderr);rc=1
p=Path('/run/ds-guard-safe-result.'+run_id+'.json');p.write_text(json.dumps({'exit_code':rc,'run_id':run_id}));p.chmod(0o600)
sys.exit(rc)
