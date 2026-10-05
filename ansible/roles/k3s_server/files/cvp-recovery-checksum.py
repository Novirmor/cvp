#!/usr/bin/python3
import hashlib
from pathlib import Path
import re
import sys


def verify(archive, sidecar):
    name = archive.name
    if not name or name in ('.', '..') or any(char in name for char in '\\/\r\n'):
        raise ValueError('Unsafe recovery archive basename')
    if sidecar.stat().st_size > 8192:
        raise ValueError('Recovery checksum must contain exactly one SHA256 record')
    match = re.fullmatch(rb'([0-9a-fA-F]{64}) [ *]' + re.escape(name.encode()) + rb'\n?', sidecar.read_bytes())
    if match is None:
        raise ValueError('Recovery checksum must name only the selected archive basename')
    digest = hashlib.sha256()
    with archive.open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(block)
    if digest.hexdigest() != match[1].decode().lower():
        raise ValueError('Recovery archive SHA256 mismatch')


if __name__ == '__main__':
    try:
        verify(*map(Path, sys.argv[1:]))
    except (OSError, ValueError, TypeError) as error:
        sys.exit(str(error))
