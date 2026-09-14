# Stage B2 — Attachment Forensics (Owner: Bhavit)

## Input
`attachments` array from Krish's Stage A `EmailObject`. Each entry expected
to look like:
```json
{"filename": "invoice.pdf", "content_type": "application/pdf", "content_bytes_b64": "..."}
```
Common key aliases (`declared_type`, `bytes_b64`, `data_b64`, etc.) are also
accepted — see `_get_filename` / `_get_declared_type` / `_get_b64_bytes` in
`attachment_forensics.py` if Stage A's real key names differ, update there.

## Output
```json
{
  "attachments": [
    {
      "filename": "invoice.docm",
      "declared_type": "application/vnd.ms-word.document.macroEnabled.12",
      "sha256": "...",
      "size_bytes": 41200,
      "actual_type": "application/x-ole-storage",
      "type_mismatch": false,
      "has_macro": true,
      "macro_behavior": {
        "has_macro": true,
        "suspicious": true,
        "autoexec_triggers": ["AutoOpen"],
        "suspicious_actions": ["Shell", "CreateObject"],
        "referenced_iocs": ["powershell.exe", "cmd.exe"],
        "flags": [
          "auto-runs on open (AutoOpen): Runs when the Word document is opened",
          "suspicious API usage (Shell): May run an executable file or a system command"
        ]
      },
      "suspicious": true,
      "flags": [
        "Office document contains a macro",
        "auto-runs on open (AutoOpen): Runs when the Word document is opened",
        "suspicious API usage (Shell): May run an executable file or a system command"
      ]
    }
  ]
}
```
`macro_behavior` is `null` when there's no macro, or when the file isn't an
Office document. `flags` is extra human-readable detail (beyond the
booleans) meant for the dashboard's evidence/reasons list.

## What it checks
- SHA-256 hash of every attachment
- Actual file type via magic bytes (libmagic if installed, hand-rolled
  signature table as fallback — so this still works on machines without
  libmagic set up, e.g. plain Windows Python installs)
- Declared vs actual type mismatch (lenient about generic/legacy-vs-OOXML
  Office type differences to avoid false positives)
- **Static behavioral macro analysis** (v2) — for Office documents
  containing a macro, statically decompiles and scores the VBA source via
  `oletools`' `VBA_Scanner`, without ever executing it. Surfaces:
  - **auto-exec triggers** — does it run the instant the file is opened
    (`AutoOpen`, `Document_Open`, etc.), with no click needed
  - **suspicious API usage** — process spawning (`Shell`), OLE object
    creation (`CreateObject`), PowerShell invocation, and similar
  - **referenced IOCs** — executable names, URLs, or other indicators the
    macro's own code mentions (e.g. `powershell.exe`, `cmd.exe`)

  This is "static sandboxing" — decompiling and scoring risky behavior
  from the source code, not dynamic detonation. Nothing is ever run.
  Macro *presence* alone is still flagged as suspicious regardless of
  whether `oletools` finds specific risky API calls (macros are rare and
  inherently notable in received attachments) — the behavioral detail is
  added evidence on top, not a narrower bar for flagging.
- Double file extensions (e.g. `invoice.pdf.exe`)
- Executable content disguised under a non-executable filename

## Files
- `file_signatures.py` — magic-byte detection + type-mismatch logic
- `macro_scan.py` — macro presence detection **and** static behavioral
  analysis via `oletools` (`analyze_macro_behavior()` is the main entry
  point; `has_macro()` is a lightweight boolean wrapper kept for
  backward compatibility)
- `attachment_forensics.py` — main module, `analyze_attachments()` is the
  Stage B2 entry point
- `../tests/test_attachment_forensics.py` — manual test with synthetic
  attachments covering the non-macro detection cases (type mismatch,
  double extension, disguised executable)
- `../tests/test_b2_against_krish_fixture.py` — integration test against
  Krish's real Stage A fixture
- `../tests/test_macro_behavior.py` — tests for the static behavioral
  macro analysis, including a real malicious-style VBA snippet run
  through the actual `oletools` engine (not mocked) to prove detection
  genuinely works, plus wiring/output-shape tests for `attachment_forensics.py`

## Setup
```
pip install python-magic oletools --break-system-packages
```
`python-magic` needs `libmagic` on the system (Linux/Mac: usually already
present or `apt install libmagic1`; Windows: `pip install python-magic-bin`
instead, or just rely on the built-in fallback signatures — the module
degrades gracefully either way).

## Known limitation
No public corpus we pulled (SpamAssassin, Nazario, Kaggle CSVs) actually
contains real attachments, and the static behavioral macro analysis has
only been validated against mocked `oletools` output and a real malicious
*VBA source snippet* run through the real engine — not a complete, real
`.docm` file with an actual embedded macro run through the full pipeline
end-to-end. Worth building one (Word → enable macros → a simple
`Sub AutoOpen(): Shell "cmd.exe": End Sub` → save as `.docm`) and running
it through `run_pipeline.py` before relying on this in a live demo.
