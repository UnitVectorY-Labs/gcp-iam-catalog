/* UVY Design v0.1.0 — MIT. Load synchronously in <head> before styles. */
(() => {
  if (window.__uvyThemeInitialized) return;
  window.__uvyThemeInitialized = true;
  const root = document.documentElement;
  const selector = '[data-uvy-theme-toggle], #theme-toggle';
  const system = matchMedia('(prefers-color-scheme: dark)');
  let preference = null;
  try {
    const cookie = document.cookie.split('; ').find(value => value.startsWith('uvy-theme='));
    const saved = cookie?.slice('uvy-theme='.length);
    if (saved === 'light' || saved === 'dark') preference = saved;
  } catch {}
  const sync = () => {
    const dark = preference ? preference === 'dark' : system.matches;
    root.dataset.theme = dark ? 'dark' : 'light';
    root.style.colorScheme = dark ? 'dark' : 'light';
    document.querySelectorAll(selector).forEach(button => {
      button.hidden = false;
      button.setAttribute('aria-label', dark ? 'Switch to light mode' : 'Switch to dark mode');
      button.title = dark ? 'Switch to light mode' : 'Switch to dark mode';
    });
  };
  sync();
  system.addEventListener('change', () => { if (!preference) sync(); });
  document.addEventListener('click', event => {
    if (!(event.target instanceof Element) || !event.target.closest(selector)) return;
    preference = root.dataset.theme === 'dark' ? 'light' : 'dark';
    try {
      document.cookie = `uvy-theme=${preference}; Path=/; Max-Age=31536000; SameSite=Lax${location.protocol === 'https:' ? '; Secure' : ''}`;
    } catch {}
    sync();
  });
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', sync, { once: true });
  else sync();
  // Both spellings are version-specific; supporting shell reinitialization is harmless.
  document.addEventListener('htmx:after:swap', sync);
  document.addEventListener('htmx:afterSwap', sync);
})();
