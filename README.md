# ZIP filename preflight prototype

Download the [source ZIP](https://codeload.github.com/Dexter-Ou/zip-portability/zip/7ee2fae5b765b01b65b8f98a3a99865530c2d561), extract it and open a terminal in the extracted folder.

Python 3.10+, standard library only. Run `python3 check_zip.py archive.zip`.
Exit 0 means no findings under this narrow policy; 1 means findings; 2 means input error.
JSON goes to stdout. The archive is opened read-only; nothing is extracted or repaired.

This conservative check flags case/NFC collisions, Windows device names and
invalid characters, trailing dots/spaces, parent/absolute paths, backslashes,
symlink metadata and files used as parent directories. It is intended for small
release ZIPs (16 MiB archive, 10000 entries maximum). Input-size caps do not
provide a hard memory/time sandbox. Run on trusted release artifacts only.

It does not validate CRCs, payloads, physical local headers, encryption, symlink
targets, path lengths or every extractor's filename decoding. Unicode casefold
and NFC are conservative heuristics, not exact Windows/macOS filesystem rules.
An archive with no findings is not certified portable or safe to extract.

Run the synthetic check with `python3 check_prototype.py`. Real Windows/macOS
extraction have not been performed.

## First run

From this folder, make a disposable archive and inspect it:

```sh
python3 -m zipfile -c sample.zip README.md
python3 check_zip.py sample.zip > report.json
```

The report should show `status: "no_findings"`, `entries_checked: 1` and an
empty `findings` list. A finding includes a policy code, member name and, for
collisions, the other member. Exit 1 can be used to stop a release check; review
the report before deciding whether a name is appropriate. JSON escapes member
control characters; filenames in reports may still contain private information.
Keep reports private when needed. Delete the disposable sample and report after
review. There is no repair command or recovery state.

## License and feedback

Free MIT-licensed preview from Gong LLC; see LICENSE. Best-effort support with
no service commitment. Report setup issues, confusing findings or missing
workflow details using repository Issues. Use synthetic member names only; do
not upload confidential releases, customer information or secrets.
