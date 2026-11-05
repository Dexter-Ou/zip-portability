#!/usr/bin/env python3
"""Conservative ZIP filename policy check. No extraction or payload validation."""
import argparse
import json
import re
import stat
import sys
import unicodedata
import zipfile
from pathlib import Path

MAX_BYTES = 16 * 1024 * 1024
MAX_ENTRIES = 10000
RESERVED = {'CON', 'PRN', 'AUX', 'NUL'} | {
    prefix + suffix for prefix in ('COM', 'LPT') for suffix in '123456789¹²³'
}


def inspect(path):
    findings = []
    def add(code, name, other=None):
        row = {'code': code, 'member': name}
        if other is not None:
            row['other_member'] = other
        findings.append(row)
    # This cap bounds input size, not total interpreter memory or execution time.
    with Path(path).open('rb') as source:
        if source.seek(0, 2) > MAX_BYTES:
            raise ValueError('archive exceeds 16 MiB prototype input limit')
        source.seek(0)
        with zipfile.ZipFile(source) as archive:
            entries = archive.infolist()
            if len(entries) > MAX_ENTRIES:
                raise ValueError('archive exceeds 10000 entry prototype limit')
            seen = {}
            files = {}
            paths = []
            for entry in entries:
                name = entry.orig_filename
                normalized = name.replace('\\', '/')
                if normalized.startswith('/') or re.match(r'^[A-Za-z]:', normalized):
                    add('absolute_or_drive_path', name)
                parts = normalized.rstrip('/').split('/')
                if any(part in ('', '.', '..') for part in parts):
                    add('ambiguous_or_parent_component', name)
                for part in parts:
                    if any(ord(c) < 32 or c in '<>:"|?*' for c in part):
                        add('windows_invalid_character', name)
                        break
                if any(part.endswith((' ', '.')) for part in parts):
                    add('windows_trailing_space_or_dot', name)
                if any(part.split('.')[0].rstrip(' ').upper() in RESERVED for part in parts):
                    add('windows_reserved_device', name)
                if '\\' in name:
                    add('backslash_separator', name)
                if stat.S_ISLNK(entry.external_attr >> 16):
                    add('symlink_member', name)
                # Deliberately conservative approximation, not an NTFS/APFS emulator.
                key = '/'.join(unicodedata.normalize('NFC', p).casefold() for p in parts)
                if key in seen:
                    add('case_or_unicode_or_duplicate_collision', name, seen[key])
                else:
                    seen[key] = name
                is_directory = normalized.endswith('/') or stat.S_ISDIR(entry.external_attr >> 16)
                paths.append((key, name))
                if not is_directory:
                    files.setdefault(key, name)
            for key, name in paths:
                components = key.split('/')
                for i in range(1, len(components)):
                    parent = '/'.join(components[:i])
                    if parent in files:
                        add('file_used_as_parent', name, files[parent])
                        break
    return {'format_version': 1, 'policy': 'conservative_filename_portability_v1',
            'entries_checked': len(entries), 'findings': findings,
            'status': 'findings' if findings else 'no_findings',
            'limits': ['Not an extraction safety or malware verdict',
                       'No payload, CRC, local-header, encryption or symlink-target validation',
                       'Casefold/NFC approximates collisions; real filesystems and extractors vary',
                       'No path-length or legacy-encoding compatibility certification']}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('archive')
    args = parser.parse_args(argv)
    try:
        result = inspect(args.archive)
    except (OSError, ValueError, zipfile.BadZipFile, NotImplementedError) as exc:
        print(json.dumps({'status': 'error', 'error_type': type(exc).__name__}))
        return 2
    # JSON escapes prevent member control characters from becoming terminal controls.
    print(json.dumps(result, ensure_ascii=True, indent=2))
    return 1 if result['findings'] else 0


if __name__ == '__main__':
    sys.exit(main())
