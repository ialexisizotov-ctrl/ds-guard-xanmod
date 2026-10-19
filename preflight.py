#!/usr/bin/env python3
"""Read-only compatibility gate. Never import installation code here."""
import argparse, json, os, platform, re, shutil, subprocess, sys
from pathlib import Path

def run(args):
    try:p = subprocess.run(args, capture_output=True, text=True, timeout=25)
    except FileNotFoundError:return 127, ''
    except subprocess.TimeoutExpired:return 124, ''
    return p.returncode, p.stdout.strip()

def assess(kernel, config, os_id, arch, container, lockdown, free, available):
    errors = []
    if os_id != 'ubuntu': errors.append('This release has been validated on Ubuntu only')
    if arch != 'x86_64': errors.append('This release supports amd64 only')
    if container: errors.append('An independent host kernel is required; containers/WSL are unsupported')
    if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._+~-]{0,127}', kernel): errors.append('Invalid kernel release')
    # A successful compile does not prove that a replacement conntrack destructor is safe.
    if kernel not in ('6.8.0-87-generic', '6.8.0-147-generic', '7.0.12-x64v2-dsg1-xanmod1', '7.2.9-x64v3-dsg1-xanmod1'):
        errors.append('Kernel has not passed this release\'s runtime compatibility gate')
    for flag in ('CONFIG_MODULES', 'CONFIG_NETFILTER', 'CONFIG_NF_CONNTRACK', 'CONFIG_LIVEPATCH'):
        if not re.search(r'^' + flag + r'=[ym]$', config, re.M): errors.append(flag + ' is required')
    if 'CONFIG_MODULE_SIG_FORCE=y' in config or '[integrity]' in lockdown or '[confidentiality]' in lockdown:
        errors.append('Kernel signature/lockdown policy requires an explicitly trusted module; it will not be weakened')
    if free < 4 * 1024**3: errors.append('At least 4 GiB free disk is required')
    if available < 1536 * 1024**2: errors.append('At least 1536 MiB available RAM is required')
    return errors

def collect():
    kernel = platform.release()
    cfg = Path('/boot/config-' + kernel)
    os_data = dict(line.split('=', 1) for line in Path('/etc/os-release').read_text().splitlines() if '=' in line)
    mem = dict((p[0].rstrip(':'), int(p[1]) * 1024) for p in (l.split() for l in Path('/proc/meminfo').read_text().splitlines()))
    virt = run(['systemd-detect-virt', '--container'])[0] == 0
    lock = Path('/sys/kernel/security/lockdown')
    errors = assess(kernel, cfg.read_text() if cfg.exists() else '', os_data.get('ID', '').strip('"'),
                    platform.machine(), virt, lock.read_text() if lock.exists() else '',
                    shutil.disk_usage('/var').free, mem['MemAvailable'])
    version=os_data.get('VERSION_ID','').strip('"')
    expected_version='22.04' if kernel=='6.8.0-87-generic' else '24.04'
    if version!=expected_version: errors.append('This kernel/OS version pair has not passed runtime acceptance')
    if os.geteuid(): errors.append('Run as root')
    for tool in ('systemctl', 'systemd-run', 'python3', 'iptables', 'ip', 'curl', 'tar', 'flock', 'modinfo', 'modprobe', 'apt-get', 'dpkg'):
        if not shutil.which(tool): errors.append('Missing prerequisite: ' + tool)
    guard2 = [Path('/etc/systemd/system/ssh.service.d/zz-ds-guard.conf'), Path('/etc/systemd/system/suricata.service.d/zz-ds-guard-nfqueue.conf')]
    if any(p.exists() for p in guard2): errors.append('Existing ds-guard 2.x must not be overwritten')
    if Path('/etc/suricata/suricata.yaml').exists() and not Path('/etc/suricata/rules/ds-p2p.rules').exists():
        errors.append('A pre-existing Suricata configuration without ds-guard ownership must not be overwritten')
    related=run(['systemctl','show','ds-guard.service','-p','RequiredBy','-p','BoundBy'])[1]
    for line in related.splitlines():
        for unit in line.partition('=')[2].split():
            if unit not in ('ds-guard-apply.service',): errors.append('Foreign service depends on ds-guard: '+unit)
    if run(['dpkg', '--audit'])[1]: errors.append('Resolve existing dpkg errors first')
    if not Path('/run/systemd/system').exists(): errors.append('systemd is required')
    if run(['iptables', '-w', '5', '-S'])[0]: errors.append('Cannot read iptables rules')
    defaults = json.loads(run(['ip', '-j', '-4', 'route', 'show', 'default'])[1] or '[]')
    if len({(r.get('dev'),r.get('gateway')) for r in defaults}) != 1:
        errors.append('IPv4 default routes must resolve to one unambiguous WAN interface/gateway')
    return {'kernel': kernel, 'os': os_data.get('ID', '').strip('"'), 'available_bytes': mem['MemAvailable'],
            'errors': errors, 'compatible': not errors, 'loaded_module': Path('/sys/module/xt_ndpi').exists(),
            'headers_present': Path('/lib/modules/' + kernel + '/build/Makefile').exists(),
            'scope': 'IPv4 filtering; no kernel replacement or automatic reboot'}

if __name__ == '__main__':
    result = collect()
    print(json.dumps(result, ensure_ascii=False, indent=2))
    sys.exit(0 if result['compatible'] else 78)
