/* Encode untrusted values at the HTML and inline-JavaScript attribute boundaries. */
(function (root) {
  function escapeHtml(value) {
    return String(value ?? '').replace(/[&<>"']/g, character => ({'&':'&amp;', '<':'&lt;', '>':'&gt;', '"':'&quot;', "'":'&#39;'}[character]));
  }
  function handlerArg(value) {
    // JSON quotes the JS string; HTML encoding then protects the enclosing attribute.
    // JSON.stringify does not escape apostrophes, so escape them as JS unicode first.
    return escapeHtml(JSON.stringify(String(value ?? '')).replace(/'/g, '\\u0027'));
  }
  root.xssHtml = escapeHtml;
  root.xssArg = handlerArg;
  if (typeof module !== 'undefined' && module.exports) module.exports = {escapeHtml, handlerArg};
})(typeof window !== 'undefined' ? window : globalThis);
