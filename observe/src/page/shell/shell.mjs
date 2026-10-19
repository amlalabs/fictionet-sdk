const fragment = new URLSearchParams(location.hash.slice(1));
history.replaceState(null, '', location.pathname);
const key = `page-token:${location.origin}`;
const supplied = fragment.get('token');
const token = supplied || sessionStorage.getItem(key);
const content = document.querySelector('#content');
async function api(path, method = 'GET') {
  const response = await fetch(path, {
    method,
    headers: { Authorization: `Bearer ${token}` },
  });
  const value = await response.json();
  if (!response.ok) throw new Error(value.error || `HTTP ${response.status}`);
  return value;
}
try {
  if (!token) throw new Error('Open the URL printed by the demo.');
  if (supplied) {
    await api('/api/bootstrap', 'POST');
    sessionStorage.setItem(key, token);
  }
  const page = await api('/api/page');
  document.title = page.title;
  document.querySelector('h1').textContent = page.title;
  content.textContent = JSON.stringify(page, null, 2);
  const world = await api('/api/world');
  content.textContent += `\n\n${JSON.stringify(world, null, 2)}`;
} catch (error) {
  const loading = content.textContent === 'Loading…';
  content.textContent = loading ? error.message : `${content.textContent}\n\n${error.message}`;
}
