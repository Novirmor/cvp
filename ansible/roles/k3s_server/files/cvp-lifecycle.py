#!/usr/bin/python3
import json
import os
from pathlib import Path
import re
import stat
import sys


def directory(path):
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o022:
        raise ValueError('Lifecycle directory has unsafe ownership, permissions, or type')


def read_owner(path):
    directory(path)
    descriptor = os.open(path / 'owner', os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor) as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
            raise ValueError('Lifecycle owner file is unsafe')
        return stream.read(130).strip()


def exists(path):
    try:
        path.lstat()
    except FileNotFoundError:
        return False
    return True


def execute(request):
    path = Path(request['path'])
    if not path.is_absolute() or '..' in path.parts:
        raise ValueError('Lifecycle lock path must be absolute')
    action = request['action']
    guard = Path(request['guard'])
    legacy_guard = Path(request['legacy_guard']) if 'legacy_guard' in request else None
    if (not guard.is_absolute() or '..' in guard.parts or
            (legacy_guard is not None and os.path.commonpath([
                os.path.realpath(guard), os.path.realpath(legacy_guard.parent)]) == os.path.realpath(legacy_guard.parent))):
        raise ValueError('Persistent recovery inhibit must be absolute and outside the datastore')
    if legacy_guard is not None and exists(legacy_guard):
        raise ValueError('Resolve the legacy restore guard before convergence')
    if not request.get('allow_restore', False) and exists(guard):
        raise ValueError('Resolve the persistent restore guard before convergence')
    if action == 'check':
        if exists(path):
            raise ValueError('Lifecycle lock already exists; reconcile its owner explicitly')
        print('available')
        return
    token = request.get('token', '')
    if not re.fullmatch('[0-9a-f]{64}', token):
        raise ValueError('A lifecycle ownership token is required')
    if action == 'acquire':
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        directory(path.parent)
        try:
            path.mkdir(mode=0o700)
        except FileExistsError:
            if read_owner(path) != token:
                raise ValueError('Lifecycle lock is held by another invocation; never steal it') from None
            print('owned')
            return
        try:
            descriptor = os.open(path / 'owner', os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            with os.fdopen(descriptor, 'w') as stream:
                stream.write(token + '\n')
                stream.flush()
                os.fsync(stream.fileno())
            for folder in (path, path.parent, path.parent.parent):
                descriptor = os.open(folder, os.O_DIRECTORY)
                try:
                    os.fsync(descriptor)
                finally:
                    os.close(descriptor)
        except BaseException:
            (path / 'owner').unlink(missing_ok=True)
            path.rmdir()
            raise
        print('acquired')
        return
    if read_owner(path) != token:
        raise ValueError('Lifecycle ownership has changed; refusing mutation or release')
    if action == 'assert':
        print('owned')
    elif action == 'release':
        if sorted(entry.name for entry in path.iterdir()) != ['owner']:
            raise ValueError('Lifecycle lock contains unexpected recovery material')
        (path / 'owner').unlink()
        path.rmdir()
        print('released')
    else:
        raise ValueError('Unknown lifecycle operation')


if __name__ == '__main__':
    try:
        execute(json.load(sys.stdin))
    except (OSError, ValueError, KeyError) as error:
        sys.exit(str(error))
