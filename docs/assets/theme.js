// Apply a saved theme before first paint (an inline script would violate the CSP).
try {
  var saved = localStorage.getItem('theme');
  if (saved === 'light' || saved === 'dark') document.documentElement.dataset.theme = saved;
} catch (e) { /* storage blocked: follow the OS */ }
