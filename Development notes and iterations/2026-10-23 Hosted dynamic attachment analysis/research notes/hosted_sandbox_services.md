# Hosted malware sandbox / dynamic analysis APIs for E-TAP hosted edition (as of Oct 2026)

Note on method: ~14 tool calls. Several vendor pages (Joe Sandbox pricing, Hybrid Analysis FAQ/API docs) returned 403 or only headings, so some figures come from third-party integration docs and are flagged. Anything marked "(unverified / background knowledge)" was not confirmed by a source fetched in this session.

## Which services offer free or cheap API access?

### Takeaway
Realistic free API paths for a small academic project are Recorded Future Triage (tria.ge, public cloud, researcher accounts), Hybrid Analysis (free key, ~30 submissions/day, public), Filescan.io / MetaDefender Sandbox Community (free, public reports, API-limited), and the CAPE community instance. VirusTotal's free Public API forbids commercial/product use and only fetches existing behaviour reports; ANY.RUN and Joe Sandbox put real API access behind paid, sales-quoted plans.

### Cited Findings
- VirusTotal Public API: 500 requests/day and 4 requests/minute; "must not be used in commercial products or services"; business workflows that do not contribute files are prohibited; multiple accounts to evade limits not allowed — [VirusTotal docs: Public vs Premium API](https://docs.virustotal.com/reference/public-vs-premium-api)
- VirusTotal Premium API: no fixed rate limit (tier-licensed), provides sandbox behaviour data from executing Windows PEs, DMGs, Mach-Os, APKs, plus sample, PCAP and execution report downloads, with SLA — [VirusTotal docs](https://docs.virustotal.com/reference/public-vs-premium-api)
- VT v3 behaviour reports are per-sandbox (id = `sha256_sandboxname`), aggregated from multiple VT and partner sandboxes; a "file_behaviours" endpoint returns all of them — [VT/GTI docs: files behaviours](https://gtidocs.virustotal.com/reference/files-behaviours); old v2 behaviour endpoint was Private-API-only, WinXP, PE <10 MB, best effort, no guarantee a report is generated — [VT v2 docs](https://docs.virustotal.com/v2.0/reference/file-behaviour)
- Hybrid Analysis (CrowdStrike Falcon Sandbox) public API: 30 sandbox submissions/day; database requests (report fetch, search, download) 200/min and 2,000/hour — [Anomali integration docs](https://docs.anomali.com/Content/ThreatStream%20Administration/Integrations/Hybrid_Analysis.htm) (secondary source; official FAQ did not render)
- Hybrid Analysis quota can be read programmatically via `/key/current` and `/key/submission-quota` — [Glama MCP tool listing](https://glama.ai/mcp/servers/inadvisable-hibiscusfarragei279/Malware-Sandbox-mcp/tools/get_quota); API clients must send User-Agent "Falcon Sandbox" — [archive page](https://echo.archivarix.net/es/archive/hybrid-analysis) (secondary)
- ANY.RUN plans: Community free (16 MB, 60 s VM timeout, no private analyses, API not listed); Hunter (contact sales, private, 100 MB, 660 s); Enterprise Suite (contact sales, 1,500+ API tasks/month, 1,200 s) — [ANY.RUN plans](https://any.run/plans/)
- Joe Sandbox Cloud Basic: free, public results, single user, ~15 analyses/month, limited reporting formats and "limited RESTful API"; full REST API at Cloud Pro and above — [FitGap listing](https://us.fitgap.com/products/joe-sandbox) (third-party, unverified); terms prohibit bypassing subscription limits — [Joe Sandbox T&C](https://www.joesandbox.com/tandc)
- Filescan.io (OPSWAT community tier of MetaDefender Sandbox, newer docs call it "MetaDefender Aether"): free, public reports, 100 MB cap, API limits apply, no private reports or priority; paid standalone: up to 2,000 MB, private reports, no API limits — [OPSWAT FAQ](https://www.opswat.com/docs/filescan/faq/what-is-the-difference-between-filescan-io-and-opswat-filescan-c)
- MetaDefender Cloud free keys go to lower-priority queues; daily per-key limits per endpoint category (including sandbox), reset 24 h after first call, values shown on account page — [MetaDefender Cloud API v4](https://www.opswat.com/docs/mdcloud/metadefender-cloud-api-v4)
- CAPE: free demonstration instance at capesandbox.com; account activation via the project's Twitter — [CAPEv2 GitHub fork README](https://github.com/azurda/CAPEv2); CAPE exposes `/apiv2/` (token auth, submit file/URL, tasks, reports, IOCs, artifact/sample download) — [capecli on PyPI](https://pypi.org/project/capecli/), [CAPE MCP docs](https://capev2.readthedocs.io/en/latest/usage/mcp.html)
- Intezer Analyze community got a free API in 2019 — [Intezer blog](https://www.intezer.com/blog/malware-analysis/api-intezer-analyze-community/); downloaded extracted files count against quota — [Assemblyline Intezer service](https://hub.docker.com/r/cccs/assemblyline-service-intezer)
- Triage API: public cloud `https://tria.ge/api/v0/`, private cloud `private.tria.ge`, plus Recorded Future Sandbox endpoints (default/US/APJ); v0 declared stable; official Go and Python clients — [tria.ge API docs](https://tria.ge/docs/)

### Inferences
- For a hosted, open (no-auth) product, VT Public API ToS is a poor fit for submission-driven use; use VT only for hash lookups / existing behaviour reports if at all.
- Best free fit: Triage (rich JSON + event stream, see below) as primary, Hybrid Analysis as fallback (30/day). Render free tier is fine since all are async: submit, store task id, poll (matches existing `analysis_jobs.py` job model).
- Triage free accounts and quotas: background knowledge says researcher accounts are granted on request and are rate limited; not confirmed this session (unverified).

### Gaps
- Exact Triage free quota, Intezer free quota, Filescan.io daily numbers, Joe Basic API scope: not found on primary pages.
- Microsoft (Defender detonation is only inside M365/MDO, no standalone public API — background knowledge, unverified) and Google (VT/GTI is Google's offering) — no separate options found.
- "Cuckoo-as-a-service": no current maintained commercial offer found; Cuckoo2 is legacy, CAPE is the maintained fork.

## Report formats, telemetry granularity, MITRE, Sigma/YARA, PCAP, user interaction

### Takeaway
Triage returns the most structured JSON (process tree with cmdlines, network flows with JA3/SNI, signatures with TTPs and YARA, dumps, extracted configs) and an events JSONL stream; Hybrid Analysis offers JSON/XML/PCAP/MISP/STIX/memory; VT gives normalized per-sandbox behaviour summaries (including Sigma hits in practice). ANY.RUN is the only one built around interactive user simulation.

### Cited Findings
- Triage dynamic (behavioural) report `TriageReport`: processes (pid/ppid, cmdline, image, start/stop), network flows (protocol, bytes, JA3/JA3S, SNI, domain, country, ASN) and DNS/HTTP requests, signatures (score, tags, indicators, optional YARA rule), TTPs per signature and per analysis, memory/file dumps with hashes, extracted configs/droppers/credentials — [Triage dynamic report docs](https://tria.ge/docs/cloud-api/dynamic-report/)
- Triage events endpoints `/api/v0/samples/events` and `/api/v0/samples/<id>/events` exist; NDJSON deprecated for JSONL in 2024-04 — [Triage API changelog](https://tria.ge/docs/)
- Triage supports custom YARA rules via API ("Yara" section) and profiles — [tria.ge docs index](https://tria.ge/docs/)
- Hybrid Analysis API report outputs include JSON, XML, PCAP, MISP, STIX and memory — [HA API v2 docs page](https://www.hybrid-analysis.com/docs/api/v2) (only topic list rendered)
- VT Premium: download PCAPs and execution reports — [VirusTotal docs](https://docs.virustotal.com/reference/public-vs-premium-api)
- ANY.RUN VM timeout 60 s (free) to 1,200 s (Enterprise) — [ANY.RUN plans](https://any.run/plans/); Joe Basic "live interaction 2 minutes" — [FitGap](https://us.fitgap.com/products/joe-sandbox)

### Inferences
- VT behaviour reports (background knowledge, unverified here) include processes_tree, files_dropped, registry, ip_traffic, dns, mitre_attack_techniques, sigma_analysis_results and crowdsourced YARA, and VT also offers an EVTX/Sysmon-style download for some sandboxes on premium (unverified).
- Macro-enabled Office/LNK/ISO: commercial sandboxes (Joe, HA, ANY.RUN, Triage) auto-click/enable content per background knowledge; not confirmed per vendor here.

### Gaps
- Per-vendor confirmation of auto macro-enable and link-clicking in documents.
- Supported file-type lists (PDF/Office/JS/LNK/ISO/ZIP with password) not retrieved from primary docs.

## Privacy: public by default?

### Takeaway
Every free tier found is public: submitted attachments (which may contain recipients' names, invoices, internal data) become downloadable/searchable by others. Private analysis is paid and mostly sales-quoted.

### Cited Findings
- Hybrid Analysis free submissions shared with the community — [FitGap](https://us.fitgap.com/products/hybrid-analysis) (secondary)
- ANY.RUN Community: no private analyses — [ANY.RUN plans](https://any.run/plans/)
- Joe Basic: samples and results publicly shared — [FitGap](https://us.fitgap.com/products/joe-sandbox); [glossary](https://ayinedjimi-consultants.fr/glossaire/joe-sandbox)
- Filescan.io community: public reports only — [OPSWAT FAQ](https://www.opswat.com/docs/filescan/faq/what-is-the-difference-between-filescan-io-and-opswat-filescan-c)
- Triage has a separate private cloud endpoint (`private.tria.ge`) — [tria.ge docs](https://tria.ge/docs/)
- VT submissions are shared with VT premium customers (background knowledge); Public API usage rules — [VT docs](https://docs.virustotal.com/reference/public-vs-premium-api)

### Inferences
- E-TAP should require explicit user consent before uploading an attachment to a public sandbox, prefer hash lookup first (no upload if already known), and never upload the full .eml (only the attachment).

### Gaps
- Private-tier prices for Triage, HA (Falcon Sandbox), Joe, ANY.RUN: none published.

## Practical limits: quotas, turnaround, file types

### Takeaway
Free quotas are small (HA 30/day; VT 500 req/day, 4/min; Joe ~15/month; ANY.RUN free has no API). Turnaround is minutes, so the hosted app must poll asynchronously.

### Cited Findings
- HA 30 submissions/day; 200 req/min, 2,000/h — [Anomali](https://docs.anomali.com/Content/ThreatStream%20Administration/Integrations/Hybrid_Analysis.htm)
- VT 500/day, 4/min — [VT docs](https://docs.virustotal.com/reference/public-vs-premium-api)
- File size: ANY.RUN 16 MB free / 100 MB paid — [ANY.RUN](https://any.run/plans/); Filescan 100 MB free — [OPSWAT](https://www.opswat.com/docs/filescan/faq/what-is-the-difference-between-filescan-io-and-opswat-filescan-c)
- MetaDefender free keys in lower-priority queue — [MetaDefender Cloud API](https://www.opswat.com/docs/mdcloud/metadefender-cloud-api-v4)

### Inferences
- Render free tier sleeps after inactivity and jobs are in-memory: a pending sandbox task can be lost on restart; persist task ids in Mongo and resume polling.

### Gaps
- Typical latency figures not found in primary sources (background expectation: 2–10 min).

## Which allow exporting raw telemetry for custom EQL/Sigma rules?

### Takeaway
None of the free options give Sysmon-equivalent ECS events. Triage's events JSONL plus process/network JSON, HA's JSON/PCAP, and self-hosted CAPE (full behavioural API calls) are the closest; E-TAP would need a normalizer mapping these into its ECS-like schema so its existing EQL rules run unchanged.

### Cited Findings
- Triage events JSONL endpoint and structured process/network objects — [tria.ge docs](https://tria.ge/docs/), [dynamic report](https://tria.ge/docs/cloud-api/dynamic-report/)
- HA JSON/XML/PCAP/memory exports — [HA API docs](https://www.hybrid-analysis.com/docs/api/v2)
- VT premium: PCAP + execution reports download — [VT docs](https://docs.virustotal.com/reference/public-vs-premium-api)
- CAPE API: reports, IOCs, artifact download — [capecli](https://pypi.org/project/capecli/)

### Inferences
- Design: a `SandboxProvider` adapter (submit, poll, fetch) + `normalize_to_ecs()` producing process.start / network.connection / file.create / dns events; rules then run identically for local VirtualBox Sysmon and hosted providers. Process-creation and network rules map well; registry/file-level rules will lose coverage depending on provider.
- PCAP (HA, VT premium) can be fed to Zeek/Suricata-style parsing if network rules are needed.

### Gaps
- Whether Triage's events stream contents are documented field-by-field (only endpoint existence confirmed).
- Whether HA free tier includes PCAP/memory downloads or only paid/vetted users.
