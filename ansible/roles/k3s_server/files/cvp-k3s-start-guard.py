#!/usr/bin/python3
import json
import os
from pathlib import Path
import stat
import sys
import time


def private(path, directory=False):
    info = path.lstat()
    valid = stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode)
    if not valid or info.st_uid != os.geteuid() or info.st_mode & 0o077:
        raise ValueError('Unsafe recovery authorization ownership, permissions, or type')
    return info


def owner(path):
    private(path, directory=True)
    private(path / 'owner')
    return (path / 'owner').read_text().strip()


def exists(path):
    try:
        path.lstat()
    except FileNotFoundError:
        return False
    return True


def independent(guard, legacy_guard):
    if not guard.is_absolute() or '..' in guard.parts:
        raise ValueError('Recovery inhibit must be an absolute path')
    if legacy_guard is not None and os.path.commonpath([
            os.path.realpath(guard), os.path.realpath(legacy_guard.parent)]) == os.path.realpath(legacy_guard.parent):
        raise ValueError('Recovery inhibit must be outside the datastore')


def check(guard, authorization, lock, legacy_guard=None):
    independent(guard, legacy_guard)
    private(guard.parent, directory=True)
    if legacy_guard is not None and exists(legacy_guard):
        raise ValueError('Resolve the legacy recovery guard before startup')
    if not exists(guard):
        return
    info = private(guard, directory=True)
    private(authorization)
    value = json.loads(authorization.read_text())
    authorization.unlink()
    now = time.monotonic()
    if (value['token'] != owner(guard) or value['token'] != owner(lock)
            or value['boot'] != Path('/proc/sys/kernel/random/boot_id').read_text().strip()
            or value['guard'] != [info.st_dev, info.st_ino]
            or not now < value['expires'] <= now + 60):
        raise ValueError('Recovery startup authorization is stale or invalid')


def execute(request):
    guard = Path(request['guard'])
    independent(guard, Path(request['legacy_guard']) if 'legacy_guard' in request else None)
    authorization = Path(request['authorization'])
    lock = Path(request['lock'])
    token = request['token']
    if owner(lock) != token:
        raise ValueError('Lifecycle ownership is required for recovery authorization')
    if request['action'] == 'fence':
        if owner(guard) != token:
            raise ValueError('Recovery guard ownership is required for fencing')
        paths = {guard / 'owner', guard, guard.parent}
        for name in request['files']:
            path = Path(name)
            paths.update((path, path.parent, path.parent.parent))
        for path in paths:
            descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
            try:
                info = os.fstat(descriptor)
                if (not (stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode))
                        or info.st_uid != os.geteuid() or info.st_mode & 0o022):
                    raise ValueError('Unsafe recovery fencing path')
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
        return
    if request['action'] == 'revoke':
        if exists(authorization):
            private(authorization)
            if json.loads(authorization.read_text())['token'] != token:
                raise ValueError('Startup authorization belongs to another invocation')
            authorization.unlink()
        return
    if request['action'] != 'authorize' or owner(guard) != token:
        raise ValueError('Recovery guard ownership is required for startup')
    info = private(guard, directory=True)
    authorization.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    private(authorization.parent, directory=True)
    value = {'token': token, 'guard': [info.st_dev, info.st_ino],
             'boot': Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
             'expires': time.monotonic() + 60}
    descriptor = os.open(authorization, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, 'w') as stream:
        json.dump(value, stream)
        stream.flush()
        os.fsync(stream.fileno())


if __name__ == '__main__':
    try:
        if len(sys.argv) in (4, 5):
            check(*map(Path, sys.argv[1:]))
        elif len(sys.argv) == 1:
            execute(json.load(sys.stdin))
        else:
            raise ValueError('Invalid startup guard invocation')
    except (OSError, ValueError, KeyError, TypeError):
        sys.exit('K3s startup denied: unresolved recovery or invalid authorization')
