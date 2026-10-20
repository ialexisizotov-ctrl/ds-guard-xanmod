"""Read-only provenance proof for a pristine package file retained by rollback."""
import hashlib,json,re,stat
from pathlib import Path

STATE=Path('/var/lib/ds-guard-safe')
YAML=Path('/etc/suricata/suricata.yaml')
HOLD='/etc/systemd/system/suricata.service.d/97-safe-initial-install.conf'
UUID=re.compile(r'[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}')

def regular(p,mode=None):
    for parent in p.parents:
        s=parent.lstat()
        if not stat.S_ISDIR(s.st_mode) or s.st_uid!=0 or s.st_mode&0o022:
            raise ValueError('Небезопасный каталог журнала Suricata')
    s=p.lstat()
    if (not stat.S_ISREG(s.st_mode) or s.st_uid!=0 or s.st_gid!=0 or
        s.st_nlink!=1 or s.st_mode&0o022 or mode is not None and stat.S_IMODE(s.st_mode)!=mode):
        raise ValueError('Небезопасный файл журнала Suricata')
    if s.st_size>8*1024*1024:raise ValueError('Слишком большой журнал Suricata')
    return p.read_bytes(),stat.S_IMODE(s.st_mode)

def record(p):return json.loads(regular(p,0o600)[0])

def restored(txn):
    if (txn/'committed').exists() or (txn/'committed').is_symlink():return False
    r=record(txn/'rolled-back')
    return all(r.get(k) is True for k in ('files_restored_verified','foreign_firewall_preserved',
                                        'previously_active_services_restored'))

def proof(run):
    """No adoption from mere package presence, a disabled unit or a matching name."""
    try:
        current=record(STATE/'current.json')
        txn=Path(current['transaction'])
        base=STATE/'transactions'
        if txn.parent!=base or not UUID.fullmatch(txn.name) or not restored(txn):return None
        rc,status=run(['dpkg-query','-W','-f=${db:Status-Status}','suricata'])
        if rc or status!='installed':return None
        rc,raw=run(['systemctl','show','suricata.service','-p','ActiveState','-p','UnitFileState','-p','DropInPaths','-p','FragmentPath'])
        if rc:return None
        unit=dict(line.split('=',1) for line in raw.splitlines() if '=' in line)
        if (unit.get('ActiveState')!='inactive' or unit.get('UnitFileState')!='disabled' or
            unit.get('DropInPaths')!='' or unit.get('FragmentPath') not in
            ('/lib/systemd/system/suricata.service','/usr/lib/systemd/system/suricata.service')):return None
        actual,mode=regular(YAML)
        candidates=list(base.iterdir())
        if len(candidates)>128:return None
        for source in [txn]+sorted(p for p in candidates if p!=txn and UUID.fullmatch(p.name)):
            if not restored(source):continue
            b=record(source/'before.json')
            initial=b.get('suricata_initial_package_status')
            old_unit=b.get('units',{}).get('suricata.service',{})
            if initial not in ('','not-installed'):continue
            if old_unit.get('active') not in ('inactive','unknown','') or old_unit.get('enabled') not in ('not-found',''):continue
            if b.get('files',{}).get(str(YAML))!={'symlink':False,'new_package_default':True}:continue
            expected={'schema':1,'transaction':str(source),'dropin':HOLD,
                      'initial_package_status':initial,'initial_unit':old_unit}
            if record(source/'suricata-start-guard.json')!=expected:continue
            saved,saved_mode=regular(source/'files'/YAML.relative_to('/'))
            if actual==saved and mode==saved_mode:
                return {'transaction':str(source),'sha256':hashlib.sha256(actual).hexdigest(),
                        'reason':'unchanged_package_default_from_completed_rollback'}
    except (OSError,ValueError,KeyError,TypeError):
        return None
    return None
