# Paste-a-message demo

A suspicious text plus a harmless attachment that triggers one of the sandbox's seven E-TAP rules.

1. Open **Analyze email**, find the box **Or paste a message you were sent**.
2. Paste the whole of `suspicious-message.txt`.
3. **Add attachments**, choose `invoice.js` from this folder.
4. **Use this message**, pick **Deeper attachment analysis** (the sandbox must be paired and the agent running), then **Run deeper analysis**.

What to expect
- The "Checking sender & headers" step says it does not apply to a pasted message and is skipped; the headers add nothing to the score.
- The link `kyc-update-hdfc-secure.top` and the attachment are checked as they are for an email.
- In the VM, `invoice.js` is run by the Windows script host from the user folder, which matches **etap-004** (Suspicious Script Host Execution of Script File, MITRE T1059.005 and T1059.007). The script also tries a certutil download from `example.invalid` (rule etap-001 territory); Windows Defender usually blocks it, and the report records that.
- The score rises when the rule matches (at least 65; 85 for a prevention-grade match).

`invoice.js` is harmless: it only tries to fetch a file from a domain that cannot resolve.
