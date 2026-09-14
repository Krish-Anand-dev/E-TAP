# Stage F — Correlation Engine + persistence

Stage F is the historical relationship layer of the email-analysis pipeline.
It does two jobs together:

1. **Correlate** the current email's Stage D IOCs against previously stored emails.
2. **Persist** the current email's analysis so future emails can be correlated against it.

## Flow

```text
Stage A  -> normalized EmailObject
Stage B  -> header forensics
Stage B2 -> attachment forensics
Stage D  -> IPs / domains / URLs / hashes
                 |
                 v
              Stage F
        correlation + persistence
                 |
                 v
               MongoDB
```

Stage E (threat intelligence) is a separate stage. Its enrichment may be
passed into F for persistence, but F does not depend on threat-intel
reputation to perform its basic correlation.

## What F does

For the current email, F checks historical records for:

- exact IP matches
- exact URL matches
- exact file-hash matches
- exact domain matches
- fuzzy domain relationships using the existing Stage B domain helpers

It then:

- returns related historical emails
- identifies shared infrastructure
- joins an existing campaign when appropriate
- creates a new campaign when there is no historical match
- merges campaigns when one email bridges multiple existing campaigns
- stores the current email/analysis regardless of whether a match was found

The stored analysis keeps the correlation-relevant email metadata (`message_id`,
subject, sender, recipient, date, source format), plus Stage B/B2/D results and
optional Stage E enrichment. Raw email bodies are not stored by Stage F.

A repeated `message_id` is updated in place and is not treated as its own
historical match.

## Database

The implementation uses the shared database handle from `db.connection`.
Set `USE_FAKE_DB=1` for an in-memory local test store. For the team's shared
MongoDB setup, configure:

```text
MONGODB_URI=mongodb://localhost:27017/phishing-investigator
```

No F-specific database is required.

## Read-only query surface

`correlation.queries` is separate from the write path and is intended for
future API/dashboard endpoints:

```python
queries.recent_analyses(limit=10)
queries.analyses_in_last_days(7)
queries.analyses_by_ioc("ips", "45.33.32.156")
queries.list_campaigns()
queries.campaign_detail("campaign_003")
```

## Testing

Run the regression/demo test with:

```bash
USE_FAKE_DB=1 PYTHONPATH=. python3 tests/test_correlation_demo.py
```

Run the real A -> B/B2 -> D -> F integration runner with:

```bash
USE_FAKE_DB=1 THREAT_INTEL_LIVE=0 PYTHONPATH=. python3 run_pipeline.py path/to/email.eml
```

The integration runner now executes the complete A -> B/B2 -> D -> E -> F
-> G -> H flow using the actual Stage A parser in this codebase.
