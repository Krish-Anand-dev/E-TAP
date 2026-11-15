import apiClient from './client';

const detail = (error, fallback) => error.response?.data?.detail || fallback;

/** { linked, linked_at, bot_number } for the signed-in account. Throws when not signed in. */
export async function getWhatsAppLink() {
  try {
    const response = await apiClient.get('/whatsapp/link', { timeout: 15000 });
    return response.data;
  } catch (error) {
    throw new Error(detail(error, 'Could not read the WhatsApp link.'));
  }
}

/** A one-time code to send to the bot from the WhatsApp you want to link: { code, expires_in_minutes, bot_number }. */
export async function newWhatsAppLinkCode() {
  try {
    const response = await apiClient.post('/whatsapp/link/code', null, { timeout: 15000 });
    return response.data;
  } catch (error) {
    throw new Error(detail(error, 'Could not create a link code. Try again in a moment.'));
  }
}

export async function unlinkWhatsApp() {
  try {
    await apiClient.delete('/whatsapp/link', { timeout: 15000 });
  } catch (error) {
    throw new Error(detail(error, 'Could not unlink. Try again in a moment.'));
  }
}
