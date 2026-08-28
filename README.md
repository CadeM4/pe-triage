# pe_triage

`pe_triage.py` is a small, manual PE32/PE32+ triage utility. It reads the DOS,
COFF, optional, section, and import structures directly with `struct`; it does
not use a PE parsing package.

```text
python pe_triage.py <pe-file>
```

The report includes machine type, image base and size, entry-point RVA and
section, section permissions and Shannon entropy, overlay size, and imported
DLLs. The triage pass calls out writable/executable sections, high-entropy
sections, unusual virtual-only sections, unnamed sections, a non-executable
entry point, selected system/network/crypto imports, and unusually large
section tables.

The input file is opened read-only and is never modified. Python 3 and the
standard library are the only requirements.
