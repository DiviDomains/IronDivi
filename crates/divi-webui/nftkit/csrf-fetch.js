// Every write the kit sends to the node's /api/nft proxy carries the page's CSRF token.
const realFetch = (...a) => globalThis.fetch(...a);
export function fetch(input, init = {}) {
  const method = (init.method || 'GET').toUpperCase();
  const url = new URL(typeof input === 'string' ? input : input.url, document.baseURI);
  if (method !== 'GET' && method !== 'HEAD' && url.origin === location.origin && url.pathname.startsWith('/api/nft/')) {
    const headers = new Headers(init.headers);
    const token = typeof window.__irondiviCsrf === 'function' ? window.__irondiviCsrf() : '';
    if (token) headers.set('X-CSRF-Token', token);
    init = { ...init, headers };
  }
  return realFetch(input, init);
}
