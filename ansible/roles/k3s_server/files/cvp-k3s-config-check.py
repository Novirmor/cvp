#!/usr/bin/python3
import json
from pathlib import Path
import re
import shlex
import subprocess
import sys


def properties(unit):
    names = ['LoadState', 'FragmentPath', 'DropInPaths', 'Environment', 'EnvironmentFiles',
             'PassEnvironment', 'ExecStart', 'ExecCondition', 'Type']
    result = subprocess.run(['systemctl', 'show', '--all', *['--property=' + name for name in names],
                             '--', unit], capture_output=True, text=True, check=True, timeout=15)
    rows = result.stdout.splitlines()
    values = dict(row.split('=', 1) for row in rows)
    if result.stderr.strip() or len(rows) != len(names) or set(values) != set(names):
        raise ValueError('Incomplete effective systemd configuration')
    return values


def command(value, expected):
    if value.count('{') != 1 or value.count('}') != 1:
        return False
    match = re.fullmatch(r'\{ path=(.*?) ; argv\[\]=(.*?) ; .*\}', value)
    return bool(match and match[1] == expected[0] and shlex.split(match[2]) == expected)


def check(request):
    for path in request['configs']:
        if not re.fullmatch(r'/[A-Za-z0-9_./-]+', path) or '..' in Path(path).parts:
            raise ValueError('K3s configuration paths must be canonical absolute paths without whitespace')
        base = Path(path)
        dropins = Path(path + '.d')
        if base.is_symlink() or dropins.is_symlink() or (dropins.exists() and any(dropins.iterdir())):
            raise ValueError('Unaccounted K3s config drop-ins or symlinks; reconcile effective configuration first')
    environment = Path(request['environment'])
    if environment.is_symlink():
        raise ValueError('Symlinked K3s environment files are not supported')
    if environment.exists() and any(line.strip() and not line.lstrip().startswith('#')
                                    for line in environment.read_text().splitlines()):
        raise ValueError('Unaccounted K3s environment file; reconcile effective configuration first')
    unit = request['unit']
    allowed = request['guard_dropin'] if unit == 'k3s.service' else ''
    expected_condition = request['guard_content'].split('ExecCondition=', 1)[1].strip().split()
    guard_conditions = [expected_condition]
    guard_contents = [request['guard_content']]
    if not request.get('require_guard', False):
        legacy_condition = expected_condition[:2] + expected_condition[-1:] + expected_condition[3:5]
        guard_conditions.append(legacy_condition)
        guard_contents.append(request['guard_content'].replace(
            'ExecCondition=' + ' '.join(expected_condition), 'ExecCondition=' + ' '.join(legacy_condition)))
    names = [unit + '.d', 'service.d']
    if '-' in unit:
        names.append(unit.split('-', 1)[0] + '-.service.d')
    for root in request['unit_roots']:
        for name in names:
            folder = Path(root) / name
            if folder.is_symlink():
                raise ValueError('Symlinked systemd drop-in directory is unsupported')
            if folder.exists():
                for entry in folder.glob('*.conf'):
                    if (str(entry) != allowed or entry.is_symlink()
                            or entry.read_text() not in guard_contents):
                        raise ValueError('Unaccounted systemd unit drop-in; reconcile it before K3s changes')
    manager = subprocess.run(['systemctl', 'show-environment'], capture_output=True, text=True,
                             check=True, timeout=15)
    if manager.stderr.strip() or any(line.startswith('K3S_') for line in manager.stdout.splitlines()):
        raise ValueError('Unaccounted K3S manager environment')
    values = properties(unit)
    if values['LoadState'] == 'not-found' and not request.get('require_unit', False):
        return
    if values['LoadState'] != 'loaded' or values['FragmentPath'] != request['unit_path']:
        raise ValueError('K3s must use the expected installed systemd unit')
    if values['Type'] != 'notify' or values['Environment'] or values['PassEnvironment']:
        raise ValueError('Unaccounted systemd execution settings')
    env_files = values['EnvironmentFiles']
    if env_files not in ('', str(environment) + ' (ignore_errors=yes)'):
        raise ValueError('Unaccounted systemd environment sources')
    if any(path != allowed for path in shlex.split(values['DropInPaths'])):
        raise ValueError('Unaccounted loaded systemd drop-ins')
    expected = [request['binary'], 'server' if unit == 'k3s.service' else 'agent',
                '--config', request['configs'][0]]
    if not command(values['ExecStart'], expected):
        raise ValueError('Effective K3s ExecStart does not match the recovery/convergence inputs')
    if values['ExecCondition'] and not any(command(values['ExecCondition'], condition) for condition in guard_conditions):
        raise ValueError('Unaccounted systemd startup condition')
    if request.get('require_guard', False) and (
            not values['ExecCondition'] or shlex.split(values['DropInPaths']) != [allowed]):
        raise ValueError('Recovery startup inhibit is not loaded by systemd')


if __name__ == '__main__':
    try:
        check(json.load(sys.stdin))
    except (OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
        sys.exit(str(error))
