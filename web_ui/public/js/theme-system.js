/* Shared catalogue for platform defaults and personal appearance preferences.
   IDs blue/red/green/purple/gray are retained for existing saved values. */
(function (root) {
  'use strict';
  const presets = Object.freeze([
    { id: 'blue', name: 'Classic', description: 'The familiar crisp RadiusStack workspace.', swatches: ['#f3f6fb','#ffffff','#2563eb'] },
    { id: 'gray', name: 'Midnight', description: 'Deep slate surfaces and quiet blue highlights.', swatches: ['#0d1117','#19232f','#3487d4'] },
    { id: 'terminal', name: 'Terminal', description: 'Retro phosphor green, grid lines and monospaced type.', swatches: ['#07140b','#102418','#207842'] },
    { id: 'purple', name: 'Aurora', description: 'Velvet-black panels with luminous violet details.', swatches: ['#141023','#251c38','#7755ba'] },
    { id: 'paper', name: 'Archive', description: 'Warm paper, ink, and editorial typography.', swatches: ['#f5f0e5','#fffdf7','#754a28'] },
    { id: 'ocean', name: 'Tidal', description: 'Airy cyan canvas and deep nautical navigation.', swatches: ['#eaf6f8','#ffffff','#036b7a'] },
    { id: 'green', name: 'Grove', description: 'Soft sage panels with a grounded forest accent.', swatches: ['#eef5eb','#ffffff','#276c4d'] },
    { id: 'red', name: 'Ember', description: 'Warm ivory surfaces and terracotta controls.', swatches: ['#fff6f1','#ffffff','#ad4034'] }
  ]);
  const byId = new Map(presets.map(p => [p.id, p]));
  function valid(value) { return typeof value === 'string' && byId.has(value); }
  function resolve(personal, platform) { return valid(personal) ? personal : valid(platform) ? platform : 'blue'; }
  function apply(id) {
    const chosen = valid(id) ? id : 'blue';
    document.documentElement.dataset.rsTheme = chosen;
    if (root.Chart && root.getComputedStyle) {
      const style = root.getComputedStyle(document.documentElement);
      root.Chart.defaults.color = style.getPropertyValue('--rs-ink').trim();
      root.Chart.defaults.borderColor = style.getPropertyValue('--rs-border').trim();
      Object.values(root.Chart.instances || {}).forEach(chart => chart.update('none'));
    }
    return chosen;
  }
  function fillSelector(select, includeDefault = false) {
    if (!select) return;
    select.replaceChildren();
    if (includeDefault) select.add(new Option('Use platform default', ''));
    for (const item of presets) select.add(new Option(item.name, item.id));
  }
  function preview(select, target, fallback = 'blue', applyPage = false) {
    if (!select || !target) return;
    const item = byId.get(resolve(select.value, fallback));
    target.dataset.previewTheme = item.id;
    target.replaceChildren();
    const palette = document.createElement('div');
    palette.className = 'theme-preview-palette';
    for (const color of item.swatches) {
      const swatch = document.createElement('span');
      swatch.style.backgroundColor = color;
      palette.appendChild(swatch);
    }
    const copy = document.createElement('div');
    const name = document.createElement('strong');
    name.textContent = item.name;
    const description = document.createElement('small');
    description.textContent = item.description;
    copy.append(name, description);
    target.append(palette, copy);
    if (applyPage) apply(item.id);
  }
  root.RSTheme = Object.freeze({ presets, valid, resolve, apply, fillSelector, preview });
})(window);
