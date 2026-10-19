"""Versioned deterministic guidance. No inference about device compromise."""
VERSION = '2026-10-18.1'
GUIDANCE = {
    'opened_email': ('I only opened the email', ['Avoid replying, opening attachments or following links.', 'Verify the request through a known contact channel; report suspicious messages to your administrator.']),
    'clicked_link': ('I clicked a link or scanned a QR code', ['Close the page and do not enter information or approve prompts.', 'Review whether you downloaded anything, entered credentials or granted permissions; select the matching checklist.', 'Report the interaction to your administrator with the approximate time.']),
    'downloaded_file': ('I downloaded a file', ['Do not open the downloaded file.', 'Use your organization\'s approved reporting and endpoint scanning process; ask IT how to preserve or remove the file.']),
    'opened_attachment': ('I opened an attachment', ['Stop interacting with the attachment; do not enable macros or approve new permissions.', 'Contact your IT or security team promptly and follow their device isolation and endpoint scanning instructions.', 'Record the filename and interaction time without forwarding the artifact broadly.']),
    'entered_password': ('I entered my password', ['From a trusted device, open the official service directly and change the affected password.', 'Change reused passwords on other services; review and revoke unfamiliar sessions.', 'Review recovery details and MFA settings, and notify the account administrator promptly.']),
    'approved_mfa': ('I approved an MFA request', ['Contact the account administrator promptly through a known channel.', 'Use the official account security settings to revoke unfamiliar sessions and review sign-ins.', 'Change affected credentials and review MFA enrollment with your administrator.']),
    'sent_money': ('I sent money or shared sensitive information', ['Contact your bank or payment provider promptly using a known official channel to ask about stopping or recalling the payment.', 'Notify the relevant organization about the information disclosed; preserve receipts and timestamps.', 'Be cautious of recovery offers demanding additional payments.']),
}

def guidance(kind):
    title, steps = GUIDANCE[kind]
    return {'version': VERSION, 'interaction': kind, 'title': title, 'steps': steps,
            'uncertainty': 'This interaction alone cannot establish compromise or safety. Follow your organization\'s incident response process.'}
