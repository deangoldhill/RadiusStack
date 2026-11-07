// Stored appearance IDs are stable across upgrades. Keep in sync with the
// client-side preset catalogue; both API paths validate against this set.
const THEME_IDS = new Set(['blue', 'red', 'green', 'purple', 'gray', 'terminal', 'paper', 'ocean']);
const isTheme = value => typeof value === 'string' && THEME_IDS.has(value);
module.exports = { THEME_IDS, isTheme };
