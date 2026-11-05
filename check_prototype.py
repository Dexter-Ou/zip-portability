import hashlib
import json
import subprocess
import sys
import tempfile
import warnings
import zipfile
from pathlib import Path

CASES = [
 ('ordinary', ['docs/readme.txt', 'data/table.csv'], None),
 ('case', ['A.txt', 'a.txt'], 'case_or_unicode_or_duplicate_collision'),
 ('unicode', ['caf\u00e9.txt', 'cafe\u0301.txt'], 'case_or_unicode_or_duplicate_collision'),
 ('device', ['NUL.txt'], 'windows_reserved_device'),
 ('superscript_device', ['COM¹.txt'], 'windows_reserved_device'),
 ('parent', ['../outside.txt'], 'ambiguous_or_parent_component'),
 ('absolute', ['/outside.txt'], 'absolute_or_drive_path'),
 ('drive', ['C:/outside.txt'], 'absolute_or_drive_path'),
 ('illegal', ['a:b.txt'], 'windows_invalid_character'),
 ('trailing', ['report.'], 'windows_trailing_space_or_dot'),
 ('parent_file', ['assets', 'assets/icon.txt'], 'file_used_as_parent'),
 ('backslash', ['a\\b.txt'], 'backslash_separator'),
 ('duplicate', ['same', 'same'], 'case_or_unicode_or_duplicate_collision'),
]
checker = Path(__file__).with_name('check_zip.py')
rows = []
with tempfile.TemporaryDirectory() as directory:
 root = Path(directory)
 for label, members, expected in CASES:
  path = root / (label + '.zip')
  with warnings.catch_warnings():
   warnings.simplefilter('ignore', UserWarning)
   with zipfile.ZipFile(path, 'w') as archive:
    for name in members:
     archive.writestr(name, b'synthetic data')
  before = hashlib.sha256(path.read_bytes()).hexdigest()
  run = subprocess.run([sys.executable, str(checker), str(path)], capture_output=True, text=True, timeout=5)
  result = json.loads(run.stdout)
  assert run.returncode == (1 if expected else 0), (label, run.stdout, run.stderr)
  assert (expected in [f['code'] for f in result['findings']]) if expected else not result['findings']
  assert hashlib.sha256(path.read_bytes()).hexdigest() == before
  rows.append({'case': label, 'passed': True, 'input_unchanged': True})
 for label, path in [('missing', root/'missing.zip'), ('malformed', root/'bad.zip')]:
  if label == 'malformed': path.write_bytes(b'not a zip')
  run = subprocess.run([sys.executable, str(checker), str(path)], capture_output=True, text=True, timeout=5)
  assert run.returncode == 2 and json.loads(run.stdout)['status'] == 'error'
  rows.append({'case': label, 'passed': True})
 assert len(list(root.iterdir())) == len(CASES) + 1
print(json.dumps({'type': 'SYNTHETIC_PROTOTYPE_CHECKS', 'passed': len(rows), 'cases': rows,
                  'real_os_extraction_tested': False, 'independent_users': 'UNKNOWN'}, indent=2))
