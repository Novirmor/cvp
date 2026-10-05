#!/usr/bin/python3
import json
import os
from pathlib import Path
import stat
import sys


def inspect(request):
    ledger = Path(request['ledger'])
    desired = request['identity']
    if os.path.lexists(ledger):
        info = ledger.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
            raise ValueError('Unsafe backup identity ledger')
        if info.st_size > 4096 or json.loads(ledger.read_text()) != desired:
            raise ValueError('Applied backup identity differs: restore prior settings or explicitly migrate retired units and ledger')
    seen = set()
    for root in request['unit_roots']:
        folder = Path(root)
        if not folder.exists():
            continue
        for pattern in ('*.service', '*.timer'):
            for path in folder.glob(pattern):
                if not path.is_file():
                    continue
                text = path.read_text(errors='replace')
                owned = ('Description=Encrypted off-host K3s' in text
                         or 'Description=Run encrypted off-host K3s backup' in text
                         or '\nExecStart=' + desired['script'] + '\n' in '\n' + text)
                if not owned:
                    continue
                kind = 'timer' if path.suffix == '.timer' else 'service'
                if path.name != desired[kind]:
                    raise ValueError('Unaccounted prior backup unit: restore its configuration before convergence')
                if kind == 'service' and ('\nExecStart=' + desired['script'] + '\n') not in '\n' + text:
                    raise ValueError('Prior backup service uses another script; explicit migration is required')
                if kind == 'timer' and ('\nUnit=' + desired['service'] + '\n') not in '\n' + text:
                    raise ValueError('Prior backup timer targets another service; explicit migration is required')
                seen.add(kind)
    if not ledger.exists() and Path(desired['script']).exists() and seen != {'timer', 'service'}:
        raise ValueError('Existing backup script has no conclusive unit identity; reconcile before overwriting it')
    return ledger, desired


def execute(request):
    ledger, desired = inspect(request)
    if request['action'] == 'inspect':
        return
    if request['action'] != 'record':
        raise ValueError('Unknown backup identity operation')
    if not ledger.exists():
        ledger.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        descriptor = os.open(ledger, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(descriptor, 'w') as stream:
            json.dump(desired, stream, sort_keys=True)
            stream.write('\n')
            stream.flush()
            os.fsync(stream.fileno())
        descriptor = os.open(ledger.parent, os.O_DIRECTORY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        print('recorded')


if __name__ == '__main__':
    try:
        execute(json.load(sys.stdin))
    except (OSError, ValueError, KeyError) as error:
        sys.exit(str(error))
