#!/usr/bin/env python3
"""Read a selected user 0 SQLite database from a verified Android model backup."""
import contextlib
import hashlib
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import tarfile
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import android_migration as migration
import android_data as ad
import archive_crypt as crypt
import filesystem as fs
import partition_archive as pa


def copy_database(fd, password, manifest, directory, package, database):
    portable = manifest['schema'] in (migration.personal.SCHEMA, migration.APK_SCHEMA)
    if portable:
        entries = manifest['files']
        names = [migration.personal.database_name(package, database)]
    else:
        entries = {entry['path']: entry for entry in manifest['entries']}
        names = [f'{root}/{package}/databases/{database}' for root in ('data', 'user/0')]
    names = [name for name in names if name in entries and entries[name]['type'] == 'file']
    ad.require(len(names) == 1, 'DATABASE_UNAVAILABLE', 'Expected one matching Android user 0 database')
    selected = {}
    for suffix in ('', '-wal', '-journal'):
        path = names[0] + suffix
        if path in entries:
            ad.require(entries[path]['type'] == 'file', 'DATABASE_UNAVAILABLE', 'Unsupported database link')
            selected[path if portable else 'payload/' + path] = (entries[path], directory / ('source.db' + suffix))
    copy_members(fd, password, selected, portable=portable)


def copy_members(fd, password, selected, *, portable=False):
    def extract(stream, mode):
        seen = set()
        with tarfile.open(fileobj=stream, mode=mode) as tar:
            for member in tar:
                if member.name not in selected:
                    continue
                entry, dest = selected[member.name]
                ad.require(member.isfile() and member.size == entry['size'], 'SOURCE_CHANGED', 'Archive member changed')
                digest = hashlib.sha256()
                with tar.extractfile(member) as source, dest.open('xb') as out:
                    while chunk := source.read(ad.CHUNK):
                        out.write(chunk)
                        digest.update(chunk)
                ad.require(digest.hexdigest() == entry['sha256'], 'SOURCE_CHANGED', 'Archive member contents changed')
                seen.add(member.name)
        while stream.read(ad.CHUNK):
            pass
        ad.require(seen == selected.keys(), 'ARCHIVE_DAMAGED', 'Incomplete archive member export')

    with crypt.source(fd, password) as plain:
        if portable:
            with os.fdopen(os.dup(plain), 'rb') as stream:
                extract(stream, 'r|gz')
        else:
            with subprocess.Popen([pa.zstd_path(), '-qdc'], stdin=plain, stdout=subprocess.PIPE) as proc:
                try:
                    extract(proc.stdout, 'r|')
                    ad.require(proc.wait() == 0, 'ARCHIVE_DAMAGED', 'Invalid compressed archive')
                finally:
                    proc.stdout.close()
                    if proc.poll() is None:
                        proc.kill()


def export_database(archive, password, output, digest, package, database, write):
    output = fs.absolute_no_symlinks(output, missing=True)
    fd = fs.open_regular(fs.absolute_no_symlinks(archive))
    try:
        before = ad.identity(os.fstat(fd))
        manifest = migration.verify_fd(fd, password, digest)['manifest']
        ad.require(manifest['schema'] in (ad.MODEL_SCHEMA, migration.personal.SCHEMA, migration.APK_SCHEMA),
                   'DATABASE_UNAVAILABLE', 'Choose a backup containing personal data')
        with tempfile.TemporaryDirectory(prefix='.a22x-db-', dir=output.parent) as tmp:
            root = Path(tmp)
            copy_database(fd, password, manifest, root, package, database)
            with contextlib.closing(sqlite3.connect(root / 'source.db')) as db, (root / 'export').open('xb') as out:
                os.fchmod(out.fileno(), 0o600)
                db.execute('PRAGMA trusted_schema=OFF')
                db.execute('PRAGMA query_only=ON')
                result = write(db, out)
                out.flush()
                os.fsync(out.fileno())
            ad.require(before == ad.identity(os.fstat(fd)), 'SOURCE_CHANGED', 'Archive changed during export')
            # Both names are on the output filesystem. link() refuses a pre-existing destination.
            os.link(root / 'export', output)
            parent = os.open(output.parent, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(parent)
            finally:
                os.close(parent)
        return result
    finally:
        os.close(fd)
