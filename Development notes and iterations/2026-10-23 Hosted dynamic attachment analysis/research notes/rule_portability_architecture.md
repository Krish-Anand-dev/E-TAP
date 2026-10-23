# Portable detection rules across telemetry sources (local VM, emulators, sandbox APIs)

Research date: 2026-10-23. About 10 web lookups. Claims marked "(background knowledge, not re-verified)" come from prior knowledge and should be checked before they are quoted as fact.

## Q1. Rule languages: Sigma vs EQL vs YARA vs YARA-L vs capa vs KQL

### Takeaway
For behaviour events from many sources, use Sigma: it is vendor-neutral, has the largest open corpus, has a Detection Rule License (DRL 1.1), and has Python and Rust engines that can evaluate rules directly over JSON events. Add YARA for file content and capa for capability mapping (capa already reads CAPE, DRAKVUF and VMRay reports). Keep Elastic EQL only as a source of ideas: the rules are under Elastic License v2 and are tied to Elastic telemetry.

### Cited Findings
- SigmaHQ offers "more than 3000 detection rules", licensed under DRL 1.1. They are split into `rules` (generic, technique-level), `rules-threat-hunting`, `rules-emerging-threats`, `rules-compliance` and `rules-placeholder`; other folders include `deprecated`, `unsupported` and `regression_data`. — [SigmaHQ/sigma](https://github.com/SigmaHQ/sigma)
- pySigma parses and converts Sigma rules and replaces legacy sigmac. Backends and processing pipelines live in separate plugin projects listed in the plugin directory. sigma-cli usage: `sigma convert -t <backend> -p <pipeline>`; `sigma plugin list --plugin-type backend`. — [pySigma PyPI](https://pypi.org/project/pySigma), [sigma-cli](https://github.com/SigmaHQ/sigma-cli), [plugin directory](https://github.com/SigmaHQ/pySigma-plugin-directory)
- Engines that evaluate Sigma over JSON events directly, with no SIEM:
  - rsigma (Rust): `rsigma eval` over NDJSON or stdin, with pipelines for field mapping; correlation state lasts only for a single run unless daemon mode is used. — [rsigma docs](https://docs.rs/crate/rsigma/0.10.0), [rsigma-eval](https://docs.rs/crate/rsigma-eval/0.22.0)
  - Zargunlite: pure Python on SQLite, follows Zircolite and consumes pySigma-backend-sqlite output. Pre-1.0. — [zargunlite](https://pypi.org/project/zargunlite)
  - vgi-sigma: DuckDB `sigma_match(event_json, rule_yaml)`. — [vgi-sigma](https://github.com/Query-farm/vgi-sigma)
- Elastic detection-rules: "everything in this repository — rules, code, etc." is Elastic License v2. Rules are TOML; the repo has `test`, `validate-all` and `validate-rule` commands and a KQL parser, and Red Team Automations live in the separate Cortado repo. — [elastic/detection-rules](https://github.com/elastic/detection-rules)
- capa (Apache-2.0) has rules that mix OpenIOC, YARA and YAML. Each rule has a `meta` section (name, namespace, scopes, MBC mappings, examples) and a `features` section. Besides static features, capa can run over CAPE `.json`/`.json.gz` reports, DRAKVUF `.log` files and VMRay `.zip` archives. — [mandiant/capa](https://github.com/mandiant/capa)
- (Background knowledge, not re-verified) Applicability of the other languages:
  - YARA (BSD-3, yara-python; YARA-X is the Rust successor) matches bytes and strings in files or memory, which suits maldocs, macros and droppers.
  - YARA-L is Google SecOps' event-correlation language over UDM and is not usable outside that product.
  - KQL is Microsoft Sentinel/Defender's query language, tied to Microsoft tables.
  - EQL needs Elastic's event-category and sequence semantics.

### Inferences
- E-TAP's 36-of-164 EQL evaluability problem is structural. The EQL rules assume Elastic Defend fields (`process.code_signature`, `process.Ext.*` and similar), so moving to Sigma `process_creation`-style rules over Sysmon-equivalent fields would multiply the number of rules E-TAP can run.
- The licence matters for a hosted product. DRL 1.1 permits use with attribution. Elastic License v2 restricts offering the software as a managed service, so a legal check is needed before shipping Elastic rules in a hosted SaaS.
- Suggested split:
  - Static layer: YARA, plus capa for PE files.
  - Behaviour layer: Sigma, evaluated in-process. Use pySigma or a Python matcher, or shell out to rsigma.
  - Sandbox-native layer: import the signatures each provider already computes (CAPE signatures, VirusTotal sandbox verdicts) as evidence, without re-deriving them.

### Gaps
- Latest pySigma/sigma-cli versions in 2026: search only confirmed pySigma 0.11.x and sigma-cli 1.0.5 pages.
- No primary source found for an official pySigma "in-memory Python evaluator" backend.

## Q2. Event schemas and mappers (ECS, OCSF, Sigma taxonomy)

### Takeaway
Normalise to the Sigma logsource taxonomy with Sysmon-style field names as the internal "rule schema", and optionally store OCSF/ECS for export. Sigma rules are already written against Sysmon/Windows field names, and pySigma processing pipelines exist to remap them for other targets. No off-the-shelf mapper was found that converts CAPE, ANY.RUN, Hybrid Analysis or VirusTotal behaviour JSON into OCSF or Sigma fields, so E-TAP would have to write thin adapters.

### Cited Findings
- OCSF tooling exists for log pipelines (Tenzir mapping guide, Datadog OCSF processor, Splunk OCSF-CIM add-on, an Edge Delta Windows Event Log to OCSF pack), but none of it is sandbox-specific. — [Tenzir](https://docs.tenzir.com/map-data-to-ocsf), [Datadog](https://docs.datadoghq.com/logs/log_configuration/processors/ocsf_processor/), [Edge Delta](https://docs.edgedelta.com/windowsevent-pack/)
- rsigma pipelines support field mapping and jq/JSONPath extraction over arbitrary JSON payloads. This is the same mechanism needed to adapt sandbox JSON. — [rsigma](https://docs.rs/crate/rsigma/0.10.0)
- (Background knowledge, not re-verified) Sigma logsource categories map to Sysmon event IDs:
  - `process_creation` = EID 1
  - `network_connection` = EID 3
  - `file_event` = EID 11
  - `registry_*` = EID 12–14
  - `dns_query` = EID 22
  - `image_load` = EID 7
  - Key fields: `Image`, `CommandLine`, `ParentImage`, `ParentCommandLine`, `TargetFilename`, `DestinationHostname`, `QueryName`.

### Inferences
- Minimum common denominator across providers is process tree + command lines, file writes, network/DNS, and registry writes. CAPE, VirusTotal behaviour, Hybrid Analysis and ANY.RUN reports all expose process lists with command lines plus network/file activity in some form. Office-spawns-script rules (the most valuable ones for email attachments) therefore stay portable.
- Rules that need image loads, process access or code-signature fields will not port to API providers. Tag each rule with its `requires:` fields, and report rules as "not evaluable on this provider" rather than "clean".

### Gaps
- No verified, published field schemas were fetched for the ANY.RUN, Hybrid Analysis or VirusTotal `behaviour_summary`/`behaviours` endpoints. Check each API doc before writing adapters.
- No existing open-source "sandbox report → OCSF" mapper was found.

## Q3. Rule corpora relevant to email attachments

### Takeaway
The best fit is SigmaHQ `rules/windows/process_creation` (Office or PDF readers spawning cmd/powershell/mshta/wscript/rundll32/regsvr32, plus LOLBin abuse), together with YARA maldoc rules and capa rules. All of these are open and run on process-plus-command-line telemetry or on files alone.

### Cited Findings
- SigmaHQ's generic `rules` folder targets technique-level behaviour, while `rules-emerging-threats` covers specific malware or campaigns. — [SigmaHQ/sigma](https://github.com/SigmaHQ/sigma)
- capa-rules is a separate repository; each capa rule carries ATT&CK/MBC metadata. — [mandiant/capa](https://github.com/mandiant/capa)

### Inferences
- Start with a curated subset of about 50–150 Sigma process_creation and file_event rules for Office, script and LOLBin chains, filtered by `level >= medium` and `status in (stable, test)`.

### Gaps
- No counts were verified for SigmaHQ process_creation rules or for maldoc YARA collections (e.g. Yara-Rules, signature-base licensing). Verify before quoting.

## Q4. Architecture pattern and replay testing

### Takeaway
Use telemetry provider plugins (local Sysmon VM / hosted emulator / external API / replay fixture) that feed adapters into one normalised event list, then a single rule engine, then evidence and scoring. Replay fixtures make the same rule tests run in CI with no VM.

### Cited Findings
- EVTX-ATTACK-SAMPLES has about 200 EVTX samples organised by ATT&CK tactic folders with technique-level metadata, plus a Winlogbeat replay script. License GPL-3.0. — [EVTX-ATTACK-SAMPLES](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES)
- OTRF Security-Datasets provides malicious and benign datasets from several platforms. Its licence is shown inconsistently on the page (MIT in the sidebar, GPL-3.0 in a section), so check the LICENSE file. — [OTRF/Security-Datasets](https://github.com/OTRF/Security-Datasets)
- SigmaHQ ships a `regression_data` folder, which points to rule-level regression fixtures. — [SigmaHQ/sigma](https://github.com/SigmaHQ/sigma)
- Elastic validates rules with schema and unit-test commands in CI. — [elastic/detection-rules](https://github.com/elastic/detection-rules)

### Inferences
- Interface sketch:
  - `Provider.submit(file) -> handle`
  - `Provider.collect(handle) -> RawReport`
  - `Adapter(RawReport) -> list[NormEvent]` (Sigma taxonomy fields plus `provider`, `capabilities`)
  - `Engine.evaluate(events, rules) -> matches`
  - `evidence.py` ids such as `dyn.sigma.<rule_id>`
- A `ReplayProvider` that loads stored JSON fixtures serves as both the test harness and the demo mode for the hosted build. This removes the need for a separate local build: the local VM becomes just one provider plugin.
- Avoid copying GPL fixtures into the repo if licence compatibility matters. Downloading them at test time keeps the licences separate.

### Gaps
- No public benchmark was found comparing Sigma coverage across sandbox providers.

## Q5. How mature projects structure this

### Takeaway
DRAKVUF Sandbox and CAPE produce their own report formats. capa and Assemblyline sit downstream and consume those reports, which is the "provider + downstream rule layer" pattern E-TAP should copy. DRAKVUF's virtualization requirements rule it out on major clouds.

### Cited Findings
- DRAKVUF Sandbox is agentless (built on the DRAKVUF engine) and has a web UI. It needs Intel VT-x with EPT. Nested virtualization works on Xen, KVM and VMware Workstation, but not on AWS, GCP, Azure or Hyper-V. Host OS is Debian 12 or Ubuntu 22.04; guests are Windows 10/7 x64. — [drakvuf-sandbox](https://github.com/CERT-Polska/drakvuf-sandbox)
- capa consumes CAPE, DRAKVUF and VMRay outputs, so one rule set runs over multiple sandboxes. This is the clearest existing example of rule portability. — [mandiant/capa](https://github.com/mandiant/capa)
- Assemblyline (Canadian Centre for Cyber Security) is an open-source file triage system that integrates CAPE among other tools. — [VB2024 paper](https://virusbulletin.com/uploads/pdf/conference/vb2024/papers/Supercharge-your-malware-analysis-workflow.pdf)
- CAPE signatures (e.g. `injection_runpe`) map to ATT&CK IDs. The only source for this is vendor documentation from a third party. — [knogin](https://knogin.com/developers/malware-analysis-cape-sandbox)

### Inferences
- A hosted E-TAP on Render cannot run a VM sandbox. Realistic options are an external API provider, a separate bare-metal or KVM worker running CAPE, or emulation (e.g. Speakeasy or Qiling for PE files; olevba/ViperMonkey-style macro emulation). All of these plug in behind the provider interface.

### Gaps
- The Assemblyline ontology documentation URL returned 404, so the internal result model is unverified.
- No primary source was fetched for Cuckoo3's structure.
- Whether CAPE natively evaluates Sigma was not confirmed from primary sources.
