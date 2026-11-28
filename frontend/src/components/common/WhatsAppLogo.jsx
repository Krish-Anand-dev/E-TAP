import React, { useState } from 'react';
import Icon from './Icon';

/**
 * The official WhatsApp logo, unchanged, from public/whatsapp-logo.svg (taken from Meta's
 * brand resource centre). Until that file is there, a plain message icon stands in.
 */
export default function WhatsAppLogo({ size = 24 }) {
  const [missing, setMissing] = useState(false);
  if (missing) return <Icon name="message" size={size} />;
  return <img className="whatsapp-logo" src="/whatsapp-logo.svg" alt="" width={size} height={size} onError={() => setMissing(true)} />;
}
