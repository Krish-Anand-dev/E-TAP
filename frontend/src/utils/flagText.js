/** Header red-flag codes (backend/forensics/header_forensics.py) in plain words. */
const FIXED = {
  no_received_headers: 'No record of the mail servers this email passed through',
  reply_to_domain_mismatch: 'Replies would go to a different domain than the sender',
  punycode_domain: 'Sender domain uses encoded international characters',
  homograph_attack_suspected: 'Sender domain mixes look-alike letters from different alphabets',
  no_sender_domain: 'Sender address has no usable domain',
  spf_fail: 'SPF check failed: this server may not send for the domain',
  spf_softfail: 'SPF check partly failed: this server is not clearly allowed to send',
  dkim_fail: 'DKIM check failed: the signature does not verify',
  dkim_key_not_found: 'DKIM signing key was not found',
  dkim_misaligned: 'DKIM signature belongs to a different domain',
  dmarc_fail: 'DMARC check failed: the sender domain does not vouch for this email',
};

export function flagText(code = '') {
  const value = String(code);
  if (FIXED[value]) return FIXED[value];
  let found = value.match(/^lookalike_of_(.+)$/);
  if (found) return `Sender domain looks like an imitation of ${found[1]}`;
  found = value.match(/^display_name_claims_(.+?)_but_domain_is_(.+)$/);
  if (found) return `The sender's name suggests ${found[1]}, but the address is at ${found[2]}`;
  return value.replace(/_/g, ' ').replace(/^./, (c) => c.toUpperCase());
}
