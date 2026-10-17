document.getElementById('save').onclick = async () => {
  await chrome.storage.session.setAccessLevel({ accessLevel: 'TRUSTED_CONTEXTS' });
  await chrome.storage.session.set({ apiKey: document.getElementById('key').value.trim() });
  document.getElementById('key').value = '';
  document.getElementById('status').textContent = 'Key saved for this session.';
};
document.getElementById('clear').onclick = async () => {
  await chrome.storage.session.clear();
  document.getElementById('status').textContent = 'Signed out.';
};
