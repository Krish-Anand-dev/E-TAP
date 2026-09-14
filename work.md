# 🔄 Current Analysis Pipeline

``` text
Raw .eml / .msg
      ↓
A. Ingestion ✅
      ↓
B. Header Forensics ✅ ──┐
B2. Attachment Forensics ✅
      ↓                  │
D. IOC Extraction ✅ ◄──┘
      ↓
E. Threat Intelligence 🔄
      ↓
F. Correlation + Persistence 🔄
      ↓
G. Gemini Interpretation + ATT&CK Mapping 🔄
      ↓
H. Backend Assembly 🔄
      ↓
I. Frontend Dashboard 🔄
```

## Architecture Update: AI Runs at the End

The original standalone Stage C AI classifier has been removed. We first
collect the technical evidence through:

``` text
A → B/B2 → D → E → F
```

Only after those stages are complete do we call Gemini. Gemini receives
the original email content plus the structured results from the earlier
stages.

It performs the higher-level **email content classification,
explanation/reasoning, and MITRE ATT&CK mapping**.

This means Gemini is an interpretation layer over the collected
evidence, rather than an early-stage detector working only from the
email body.

------------------------------------------------------------------------

# Stage Responsibilities at a Glance

  -----------------------------------------------------------------------
  Stage                   Component               Status
  ----------------------- ----------------------- -----------------------
  A                       Email Ingestion         ✅ Complete

  B                       Header Forensics        ✅ Complete

  B2                      Attachment Forensics    ✅ Complete

  C                       Standalone AI           ❌ Removed / merged
                          Classification          into G

  D                       IOC Extraction          ✅ Complete

  E                       Threat Intelligence     🔄 In Progress

  F                       Correlation +           🔄 In Progress
                          Persistence             

  G                       Gemini Interpretation + 🔄 In Progress
                          Content                 
                          Classification + MITRE  
                          ATT&CK Mapping          

  H                       Backend Assembly        🔄 In Progress

  I                       Frontend Dashboard      🔄 In Progress
  -----------------------------------------------------------------------

------------------------------------------------------------------------

# Stage A --- Ingestion\*\*

**\*\*Status:\*\*** \~\~✅ Complete\~\~

**\### Input**

Raw \`.eml\` or \`.msg\` file.

**\### Purpose**

Detect the uploaded email format and normalize it into a single
consistent internal representation that can be consumed by all
downstream analysis stages.

\`.eml\` and \`.msg\` use fundamentally different formats:

\- \`.eml\` → MIME/text-based email format

\- \`.msg\` → Microsoft OLE Compound File binary format

The parser uses format-specific libraries:

\- Python \`email\` module → \`.eml\`

\- \`extract-msg\` → \`.msg\`

**\### Output**

The parser produces a normalized \`EmailObject\`.

\`\`\`json

{

  "subject": "Life Insurance - Why Pay More?",

  "from_raw": "12a1mailbot1@web.de",

  "from_display_name": null,

  "from_email": "12a1mailbot1@web.de",

  "to": "dcek1a1@netsgo.com",

  "reply_to": null,

  "date": "Wed, 21 Aug 2002 20:31:57 -1600",

  "message_id": "\<0103c1042001882DD_IT7@dd_it7\>",

  "all_headers": {

    "Return-Path": \[

      "\<12a1mailbot1@web.de\>"

    \],

    "Delivered-To": \[

      "zzzz@localhost.example.com"

    \],

    "Received": \[

      "..."

    \],

    "From": \[

      "12a1mailbot1@web.de"

    \],

    "To": \[

      "dcek1a1@netsgo.com"

    \],

    "Subject": \[

      "Life Insurance - Why Pay More?"

    \]

  },

  "body_text": null,

  "body_html": "...",

  "attachments": \[\],

  "source_format": "eml",

  "parse_warnings": \[\]

}

\`\`\`

**\### Field Description**

\| Field \| Description \|

\|---\|---\|

\| \`subject\` \| Normalized subject of the email \|

\| \`from_raw\` \| Original \`From\` header value \|

\| \`from_display_name\` \| Extracted sender display name, if present \|

\| \`from_email\` \| Extracted sender email address \|

\| \`to\` \| Primary recipient \|

\| \`reply_to\` \| \`Reply-To\` address, if present \|

\| \`date\` \| Parsed email date \|

\| \`message_id\` \| Email \`Message-ID\` \|

\| \`all_headers\` \| Complete parsed header collection, including
multi-valued headers such as \`Received\` \|

\| \`body_text\` \| Plain-text body, if available \|

\| \`body_html\` \| HTML body, if available \|

\| \`attachments\` \| Parsed attachment information \|

\| \`source_format\` \| Original email format (\`eml\` / \`msg\`) \|

\| \`parse_warnings\` \| Non-fatal issues encountered during parsing \|

**\### Important Parsing Behavior**

The parser preserves both **\*\*normalized fields\*\*** and the
**\*\*complete header set\*\***.

This is important because downstream header forensics may need access to
headers beyond the commonly used \`From\`, \`To\`, and \`Subject\`
fields, particularly the full \`Received\` chain.

Body fields may legitimately be empty or \`null\` depending on the
source email. For example:

\`\`\`json

{

  "body_text": "",

  "body_html": null

}

\`\`\`

is a valid parser result for an email with no body content.

**\### Deliverable**

\`\`\`python

parse_email(file) -\> EmailObject

\`\`\`

The ingestion stage is the foundation of the pipeline. All downstream
modules should consume the normalized \`EmailObject\` rather than
directly parsing \`.eml\` / \`.msg\` files.

**\### Downstream Mapping**

The normalized object provides the following inputs to later stages:

\- **\*\*Stage B --- Header Forensics\*\***

  - \`from_raw\`

  - \`from_display_name\`

  - \`from_email\`

  - \`reply_to\`

  - \`all_headers\`

  - \`date\`

  - \`message_id\`

\- **\*\*Stage B2 --- Attachment Forensics\*\***

  - \`attachments\`

\- **\*\*Stage C --- AI Content Classification\*\***

  - \`subject\`

  - \`body_text\`

  - \`body_html\`

\- **\*\*Stage D --- IOC Extraction\*\***

  - \`all_headers\`

  - \`body_text\`

  - \`body_html\`

  - attachment information where applicable

---

**\# Stage B --- Header Forensics**

**\*\*Status:\*\*** \~\~✅ Complete\~\~

**\### Input**

Relevant fields from the normalized \`EmailObject\`:

\- \`from_raw\`

\- \`from_display_name\`

\- \`from_email\`

\- \`reply_to\`

\- \`all_headers\`

\- \`date\`

\- \`message_id\`

**\### Purpose**

Analyze the email's transport and sender information to identify
spoofing and other header-level indicators.

The module should:

\- Extract the actual sender email

\- Extract the display name

\- Extract \`Reply-To\`

\- Walk the \`Received\` chain

\- Identify the originating IP

\- Evaluate SPF

\- Evaluate DKIM

\- Evaluate DMARC

\- Detect spoofed/lookalike domains

\- Identify suspicious sender/reply-to mismatches

**\### Output**

\`\`\`json

{

  "sender_email": "attacker@fake-bank.com",

  "display_name": "Bank Support",

  "reply_to": "different@domain.com",

  "spf": "fail",

  "dkim": "fail",

  "dmarc": "fail",

  "originating_ip": "185.x.x.x",

  "received_chain": \[

    "hop1",

    "hop2"

  \],

  "red_flags": \[

    "reply-to mismatch",

    "SPF fail",

    "lookalike domain"

  \]

}

\`\`\`

---

**\# Stage B2 --- Attachment Forensics**

**\*\*Status:\*\*** \~\~✅ Complete\~\~

**\### Input**

\`attachments\` from the normalized \`EmailObject\` produced by Stage A.

**\### Purpose**

Analyze email attachments for file-type spoofing and potentially
malicious content.

The module should:

\- Decode Base64 attachment data

\- Calculate SHA-256 hashes

\- Determine actual file type using magic bytes

\- Compare actual type against declared MIME type

\- Detect MIME/type mismatches

\- Scan supported Office documents for macros

\- Flag suspicious attachments

**\### Output**

\`\`\`json

{

  "attachments": \[

    {

      "filename": "invoice.pdf",

      "sha256": "abc123...",

      "declared_type": "application/pdf",

      "actual_type": "application/x-msdownload",

      "type_mismatch": true,

      "has_macro": false,

      "suspicious": true

    }

  \]

}

\`\`\`

---

**\# Stage D --- IOC Extraction**

**\### Input**

Relevant data from the normalized email and forensic stages:

\- \`all_headers\`

\- \`body_text\`

\- \`body_html\`

\- attachment information where applicable

\- Stage B output where normalized/extracted indicators are useful

**\### Purpose**

Extract Indicators of Compromise (IOCs) appearing anywhere in the email.

The module should identify:

\- IP addresses

\- Domains

\- URLs

\- File hashes

**\### Output**

\`\`\`json

{

  "ips": \[

    "185.x.x.x"

  \],

  "domains": \[

    "fake-bank.com"

  \],

  "urls": \[

    "http://fake-bank.com/login"

  \],

  "hashes": \[

    "abc123..."

  \]

}

\`\`\`

This is intentionally a small, fast module and can be implemented
independently using regexes and/or existing parsing libraries.

---

**\# Stage E --- Threat Intelligence Lookup**

**\### Input**

IOC list from Stage D.

**\### Purpose**

Enrich extracted IOCs using external threat-intelligence services.

Potential sources include:

\| IOC \| Intelligence Source \|

\|---\|---\|

\| IP \| VirusTotal \|

\| IP \| AbuseIPDB \|

\| IP \| ipinfo.io \|

\| Domain \| VirusTotal \|

\| Domain \| WHOIS \|

\| URL \| VirusTotal \|

\| Hash \| VirusTotal \|

The module should retrieve relevant information such as:

\- Malicious/reputation status

\- Number of reports

\- Domain age

\- Registrar

\- Geographic information

\- URL reputation

**\### Output**

\`\`\`json

{

  "ip_reputation": {

    "185.x.x.x": {

      "malicious": true,

      "reports": 45,

      "country": "RU"

    }

  },

  "domain_info": {

    "fake-bank.com": {

      "age_days": 3,

      "registrar": "..."

    }

  },

  "url_reputation": {

    "http://fake-bank.com/login": {

      "malicious": true

    }

  },

  "geo": \[

    {

      "ip": "185.x.x.x",

      "lat": 55.7,

      "lon": 37.6,

      "country": "RU"

    }

  \]

}

\`\`\`

\> **\*\*Development note:\*\*** This module can be tested independently
using known malicious/suspicious IOCs.

---

\*\*# Stage F --- Correlation Engine

**Status:** 🔄 In Progress

### Role

Stage F performs **historical correlation and persistence**. It checks
whether the current email is related to previously analyzed emails,
identifies shared infrastructure/campaign relationships, and stores the
current email so it can be used as historical data for future
correlation.

F is not responsible for the final phishing verdict, external
threat-intelligence lookups, or MITRE ATT&CK mapping.

### Input

-   Current email IOCs from Stage D
-   Relevant current email metadata and forensic results
-   Historical analyzed-email data from the shared MongoDB database
-   Threat-intelligence enrichment from Stage E where useful

### Correlation Flow

``` text
Current Email
     ↓
Stage D IOCs
     ↓
Search historical records
     ├── Exact IP/domain/URL/hash matches
     └── Domain similarity where applicable
     ↓
Related Emails / Shared Infrastructure
     ↓
Create / Retrieve / Merge Campaign
     ↓
Store Current Email + Relevant Analysis
     ↓
MongoDB
```

### If There Is No Match

A new email is still stored.

``` text
No historical match
       ↓
Store current email + IOCs + relevant analysis
       ↓
Create/assign campaign where appropriate
       ↓
Email becomes historical data
       ↓
Future emails can correlate against it
```

### Campaign Correlation

Related emails can be grouped through shared indicators or
infrastructure. If a later email connects previously separate campaign
groups, those groups can be merged when the evidence establishes the
relationship.

Example:

``` text
Email A
IP: 1.2.3.4
Campaign: campaign_001

        ↓ later email shares the IP

Email B
IP: 1.2.3.4

        ↓

Email B is related to campaign_001
```

### Stage E vs Stage F

``` text
Stage E:
"What is known about this IOC externally?"

Stage F:
"Have we seen this IOC/infrastructure in our own
previously analyzed emails?"
```

Stage E provides external reputation/enrichment. Stage F provides
internal historical relationships.

### Persistence

F uses the project's shared MongoDB rather than creating a separate
database.

Local configuration can use:

``` text
MONGODB_URI=mongodb://localhost:27017/phishing-investigator
```

The database/repository layer keeps correlation logic separate from
MongoDB implementation details. Historical analyzed emails and campaign
information are retained so later emails can be compared against them.

The implementation should also avoid duplicate records when the same
email is processed again, using stable identifiers such as `message_id`
where available.

### Output

``` json
{
  "related_emails": [
    "email_id_12",
    "email_id_45"
  ],
  "campaign_id": "campaign_007",
  "shared_infrastructure": [
    "185.x.x.x",
    "fake-bank.com"
  ]
}
```

When there are no matches, relationship fields can be empty while the
current email is still persisted.

# Stage G --- Gemini Interpretation & MITRE ATT&CK Mapping

**Status:** 🔄 In Progress

### Purpose

Stage G is the final AI interpretation layer. Gemini is called **once**,
after technical analysis, IOC extraction, threat-intelligence enrichment
and correlation are available.

### Input

``` json
{
  "email": {
    "subject": "...",
    "body_text": "...",
    "body_html": "..."
  },
  "header_forensics": {},
  "attachment_forensics": {},
  "iocs": {},
  "threat_intelligence": {},
  "correlation": {}
}
```

### Responsibilities

Gemini should:

-   Read and understand the email subject/body.
-   Classify the email as benign, suspicious, phishing, or another
    relevant threat category.
-   Identify social-engineering indicators such as urgency,
    impersonation, credential requests, financial scams and suspicious
    calls-to-action.
-   Interpret the technical evidence collected by the previous stages.
-   Explain the reasoning behind the classification.
-   Map supported observed behavior to existing MITRE ATT&CK tactics,
    techniques and sub-techniques.
-   Provide confidence/evidence for mappings where appropriate.
-   Avoid inventing ATT&CK mappings that are not supported by the
    evidence.

### Example Output

``` json
{
  "verdict": "Phishing",
  "risk_score": 91,
  "reasons": [
    "Credential harvesting language",
    "Malicious URL detected",
    "Sender authentication failure",
    "Domain previously associated with suspicious emails"
  ],
  "mitre_attack": [
    {
      "technique": "T1566.002",
      "name": "Phishing: Spearphishing Link",
      "tactic": "Initial Access",
      "confidence": 0.94,
      "evidence": [
        "Email contains a credential harvesting URL"
      ]
    }
  ]
}
```

### Important Design Principle

Gemini is an **interpretation layer**, not the source of raw forensic
evidence.

``` text
Forensics → IOC Extraction → Threat Intel → Correlation
                         ↓
              Complete Evidence Context
                         ↓
                       Gemini
              ┌──────────┼──────────┐
              ↓          ↓          ↓
          Content    Explanation   ATT&CK
        Classification             Mapping
```

# Stage H --- Backend Assembly

**Status:** 🔄 In Progress

### Purpose

Provide the single API entry point that connects the entire analysis
pipeline.

### Endpoint

``` http
POST /analyze
```

### Responsibilities

The endpoint should:

1.  Accept an uploaded `.eml` / `.msg` file.
2.  Pass it through Stage A.
3.  Run header analysis.
4.  Run attachment analysis.
5.  Extract IOCs.
6.  Query threat-intelligence sources.
7.  Run correlation and persist the current email.
8.  Build the complete analysis context.
9.  Send the email content + structured analysis to Gemini.
10. Receive the AI classification, explanation and ATT&CK mapping.
11. Combine all results.
12. Save the final analysis where appropriate.
13. Return the final analysis object.

### Current End-to-End Flow

``` text
Upload
  ↓
Ingestion
  ├──► Header Forensics
  └──► Attachment Forensics
              ↓
        IOC Extraction
              ↓
      Threat Intelligence
              ↓
          Correlation
          ├──► Historical Database
          └──► Store Current Email
              ↓
    Complete Analysis Context
              ↓
       Gemini Interpretation
       + Content Classification
       + MITRE ATT&CK Mapping
              ↓
       Final Analysis Object
              ↓
       Backend API Response
```

### Final API Response

``` json
{
  "email_id": "uuid",
  "risk_score": 91,
  "verdict": "Phishing",
  "headers": {},
  "attachments": [],
  "iocs": {},
  "threat_intel": {},
  "correlation": {},
  "ai_analysis": {},
  "mitre_attack": []
}
```

# Stage I --- Frontend Dashboard\*\*

**\### Input**

Combined JSON response from Stage G.

**\### Dashboard Components**

**\#### Risk Assessment**

\- Risk score card

\- Verdict banner

\- Overall assessment

**\#### Header Analysis**

\- Sender information

\- Reply-To

\- SPF / DKIM / DMARC results

\- Originating IP

\- Received chain

\- Red flags

**\#### Attachment Analysis**

\- Filename

\- File type

\- SHA-256

\- Type mismatch

\- Macro status

\- Suspicion status

**\#### Content Analysis**

\- AI risk score

\- Verdict

\- Evidence / reasons

**\#### Threat Graph**

Visualize relationships between:

\`\`\`text

Email

  │

  ├── Domain

  │      │

  │      └── IP

  │

  └── Related Emails

\`\`\`

Potential libraries:

\- \`react-force-graph\`

\- \`vis-network\`

**\#### Geo Map**

Plot IP geolocation data from Stage E.

Potential library:

\- \`Leaflet.js\`

**\#### Report Export**

Provide a **\*\*PDF export\*\*** containing the analysis and relevant
evidence.

Potential backend libraries:

\- \`reportlab\`

\- \`weasyprint\`

---

\*\*# 🧩 Development Strategy

The stages are designed to be **loosely coupled**. Each stage should:

1.  Accept a clearly defined input object.
2.  Perform one specific type of analysis.
3.  Return a predictable JSON-compatible output.
4.  Avoid depending on internal implementation details of other stages.

### Current Integration Strategy

The project is now close to end-to-end integration, so the priority is
to finish the remaining stages and then diagnose the complete pipeline
using real `.eml` / `.msg` samples.

Target flow:

``` text
A → B/B2 → D → E → F → G → H → I
```

Mocks can still be used temporarily where a dependency is unfinished,
but the final system should exercise the real pipeline.

Once connected, diagnose the complete system for:

-   stage-to-stage schema mismatches
-   API wiring
-   MongoDB persistence
-   IOC correlation
-   threat-intelligence integration
-   Gemini context and output
-   final risk/verdict logic
-   dashboard rendering
-   malformed or edge-case emails

------------------------------------------------------------------------

# 📌 Current Stage Status

  -----------------------------------------------------------------------
  Stage                   Component               Status
  ----------------------- ----------------------- -----------------------
  A                       Email Ingestion         ✅ Complete

  B                       Header Forensics        ✅ Complete

  B2                      Attachment Forensics    ✅ Complete

  C                       Standalone AI Content   ❌ Removed / merged
                          Classification          into G

  D                       IOC Extraction          ✅ Complete

  E                       Threat Intelligence     🔄 In Progress

  F                       Correlation +           🔄 In Progress
                          Persistence             

  G                       Gemini Interpretation + 🔄 In Progress
                          Content                 
                          Classification + MITRE  
                          ATT&CK Mapping          

  H                       Backend Assembly        🔄 In Progress

  I                       Frontend Dashboard      🔄 In Progress
  -----------------------------------------------------------------------

------------------------------------------------------------------------

## 🎯 Definition of Done

The platform is considered functionally complete when a user can:

``` text
Upload .eml / .msg
        ↓
Parse & Normalize
        ↓
Analyze Headers
        ↓
Analyze Attachments
        ↓
Extract IOCs
        ↓
Enrich with Threat Intelligence
        ↓
Correlate with Previous Emails
        ↓
Persist Current Email
        ↓
Build Complete Analysis Context
        ↓
Gemini Reads Email + All Evidence
        ↓
Classify Threat + Explain Findings
        ↓
Map Supported Evidence to MITRE ATT&CK
        ↓
Return Final Risk / Verdict
        ↓
View Interactive Dashboard
        ↓
Export Analysis Report
```

The final result should provide **one unified view of the email's
technical indicators, content-based assessment, threat intelligence,
historical relationships, MITRE ATT&CK mapping and supporting
evidence.**
