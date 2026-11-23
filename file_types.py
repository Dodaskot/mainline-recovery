#!/usr/bin/python3
# SPDX-License-Identifier: MIT
"""Kinds of files, by their name's extension (2026-11-20, the owner: a selective backup by the type of
files). Used by the Android migration's shared files and by Files' archives: only the chosen kinds
are written, folders are kept as they are."""

KINDS = {
    'photos': ('jpg', 'jpeg', 'png', 'heic', 'heif', 'webp', 'gif', 'bmp', 'dng', 'raw', 'tif', 'tiff', 'svg'),
    'videos': ('mp4', 'mkv', 'mov', '3gp', '3g2', 'webm', 'avi', 'm4v', 'ts', 'mpg', 'mpeg', 'wmv'),
    'audio': ('mp3', 'm4a', 'aac', 'flac', 'ogg', 'oga', 'opus', 'wav', 'amr', 'awb', 'mid', 'midi', 'wma', 'm4b'),
    'documents': ('pdf', 'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx', 'odt', 'ods', 'odp', 'txt', 'md', 'rtf',
                  'csv', 'epub', 'fb2', 'djvu', 'html', 'htm', 'json', 'xml', 'vcf', 'ics'),
    'archives': ('zip', 'rar', '7z', 'tar', 'gz', 'tgz', 'xz', 'zst', 'bz2', 'lz4', 'img'),
    'apks': ('apk', 'apks', 'xapk', 'apkm'),
}
OTHER = 'other'
NAMES = tuple(KINDS) + (OTHER,)
_BY_EXTENSION = {extension: kind for kind, extensions in KINDS.items() for extension in extensions}


def kind_of(name):
    """The kind of a file by its name: one of NAMES."""
    stem, dot, extension = name.rpartition('.')
    if not dot or not stem:
        return OTHER
    return _BY_EXTENSION.get(extension.lower(), OTHER)


def parse(text):
    """A comma-separated choice of kinds, as a sorted tuple; None for no choice (every file)."""
    if text is None or text == '':
        return None
    chosen = sorted({part.strip() for part in text.split(',') if part.strip()})
    if not chosen or any(kind not in NAMES for kind in chosen):
        raise ValueError('Unknown kind of files')
    return tuple(chosen)


def valid(kinds):
    return (isinstance(kinds, list) and kinds and kinds == sorted(set(kinds))
            and all(isinstance(kind, str) and kind in NAMES for kind in kinds))
