# Lightweight emulation and isolation for hosted attachment analysis (as of Oct 2026)

Scope note: this is a short pass with 4 searches. Many claims below are marked [unverified] where they rest on general knowledge rather than a source fetched this session.

## Emulators / instrumented interpreters (behaviour without a real OS)

### Takeaway
There is a usable per-file-type emulator stack that runs in Python on Linux and already writes structured JSON. Speakeasy covers PE and shellcode, box-js covers JScript/WSH, oletools/ViperMonkey cover VBA and XLMMacroDeobfuscator covers Excel 4 macros. Several of these are only lightly maintained.

### Cited Findings
- Speakeasy (mandiant/speakeasy) is an MIT-licensed Python emulator for Windows kernel- and user-mode binaries and shellcode. Its report lists API calls with arguments, file, registry and network activity, and decoded strings. — [Mandiant/Google blog](https://cloud.google.com/blog/topics/threat-intelligence/emulation-of-malicious-shellcode-with-speakeasy/)
- Speakeasy is on PyPI as `speakeasy-emulator`, and `se.get_report()` returns the report from code. — [PyPI](https://pypi.org/project/speakeasy-emulator); [programmatic use blog](https://cloud.google.com/blog/topics/threat-intelligence/using-speakeasy-emulation-framework-programmatically-to-unpack-malware)
- box-js (CapacitorSet) is a JScript emulator for JavaScript droppers in emails. It stubs ActiveX objects such as WScript.Shell and ADODB.Stream and writes `urls.json`, `resources.json`, `IOC.json` and `snippets.json`. By default it returns a fake 404 instead of downloading. It ships with a Dockerfile and is used in REMnux, Intel Owl and Assemblyline. Its last push was Nov 2024 (~642 stars). — [ecosyste.ms](https://awesome.ecosyste.ms/projects/github.com%2Fcapacitorset%2Fbox-js); [npm](https://npmjs.com/package/box-js); [Assemblyline JsJaws](https://github.com/cybercentrecanada/assemblyline-service-jsjaws)
- XLMMacroDeobfuscator's last PyPI release is 0.2.7 (Sept 2022, Beta). A third-party health score rates its maintenance at 0/25. — [pyup](https://pyup.io/packages/pypi/xlmmacrodeobfuscator/); [depscope](https://mcp.depscope.dev/pkg/pypi/XLMMacroDeobfuscator)
- ViperMonkey (decalage) is a VBA parser and emulation engine. Its author describes it as far from complete. — [decalage](https://decalage.info/en/vba_emulation)

### Inferences
- Coverage by file type:
  - PE/DLL/shellcode: Speakeasy, or Qiling/unicorn [unverified].
  - .js/.jse/.wsf: box-js.
  - .doc/.xls VBA: olevba static analysis plus ViperMonkey emulation.
  - XLM: XLMMacroDeobfuscator.
  - PDF: pdfid/peepdf/pdf.js are mostly static; JavaScript is extracted and then run in box-js or a JS sandbox [unverified].
  - PowerShell/HTA/LNK: deobfuscators such as PowerDecode and PSDecode, plus LnkParse3 [unverified, not searched].
  - HTML and links: Playwright in a container with HAR capture [unverified].
- None of these emulate Defender or real Office UI. "Enable macros" works only in the sense that the emulator runs the macro entry points (AutoOpen/Document_Open). Clicking PDF buttons is not simulated. Playwright can click links and buttons in HTML.

### Gaps
- I did not verify current commit dates for Qiling, ViperMonkey, PowerDecode or peepdf.

## Isolation on cheap hosting

### Takeaway
Firecracker-based services (E2B, Fly Machines, Vercel Sandbox) give per-job microVM isolation. Nested virtualization (a Windows VM inside them) is generally not available.

### Cited Findings
- Firecracker boots in about 125 ms with under 5 MiB of memory overhead. gVisor is a user-space kernel. E2B, Vercel Sandbox, CodeSandbox and Fly.io use Firecracker or derivatives. — [fly.io learn](https://fly.io/learn/)
- Fly.io staff said they do not support nested virtualisation, for security reasons. The thread may be dated. — [Fly community](https://community.fly.io/t/nested-virtualization-on-fly-io/11778)
- Firecracker does not expose the host's CPU virtualization extensions to guests, so nested KVM is blocked. Cloud Hypervisor can allow it. — [codenote comparison](https://codenote.net/en/posts/sandbox-services-japan-region-comparison/)
- E2B sessions can run up to 24 hours with pause and resume. — [codenote](https://codenote.net/en/posts/sandbox-services-japan-region-comparison/)

### Inferences
- Render free tier gives a plain container with no gVisor or KVM [unverified]. Run only pure-Python and Node emulators there, with no network, as subprocesses with strict timeouts and resource limits. For stronger isolation, send each job to an E2B or Fly Machine microVM.
- Wine-in-container would execute real payload code. Avoid it on shared infrastructure.

### Gaps
- No exact prices were found for E2B, Fly, Modal or Render. Check each provider's pricing page.

## The "venv package" idea and a safer reframing

### Takeaway
Shipping the attachment together with code that builds a venv cannot simulate Windows, Office or Defender. If the payload ever runs natively, it executes untrusted code. Reframe it as an immutable container image with the emulators preinstalled, run per job, with no network and a read-only filesystem except /tmp, and destroyed afterwards.

### Inferences
- Do not install dependencies at runtime from inside the job. Pin everything in the image.
- Never let box-js use `--download` or let Speakeasy/Playwright reach the network on shared infrastructure. If you need network behaviour, use a sinkhole or fake DNS.

## Normalising to ECS/OCSF for shared rules

### Takeaway
This is feasible. Speakeasy's file, registry and network events and box-js's resources and urls JSON map to ECS `process`, `file`, `registry` and `network` events. That lets a subset of the local Sysmon EQL rules run on hosted output.

### Inferences
- Emulated events do not have a real process tree or real PIDs. Rules that depend on parent-child process chains or timing will lose fidelity. Tag each event with `event.provider=emulator` so analysts can see where it came from.

### Gaps
- I found no existing published Speakeasy-to-ECS mapping.
