// Downstream route controls are scoped by the same apiFetch tenant header as the owning form.
const DownstreamRouteControls = (() => {
  let destinations = [];
  const pending = {};
  const byId = id => document.getElementById(id);
  const escape = value => String(value).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
  async function load(prefix) {
    const select = byId(prefix + 'Destination');
    if (!select) return;
    select.disabled = true;
    try {
      const response = await apiFetch('/api/downstream-destinations');
      if (!response.ok) throw new Error((await response.json()).error || 'Destinations unavailable');
      destinations = await response.json();
      select.innerHTML = '<option value="">Local only (no downstream route)</option>' + destinations.map(d => `<option value="${Number(d.id)}">${escape(d.name)} (${escape(d.ipv4)})</option>`).join('');
      byId(prefix + 'RouteHelp').textContent = destinations.length ? 'Choose a destination owned by this tenant. Changes take effect after the owning record is saved.' : 'No destinations in this scope. Create one on the Downstream RADIUS page first.';
      select.disabled = false;
      if (pending[prefix]) populate(prefix, pending[prefix]);
    } catch (error) { byId(prefix + 'RouteHelp').textContent = error.message; }
    update(prefix);
  }
  function update(prefix) {
    const id = byId(prefix + 'Destination').value;
    const mode = byId(prefix + 'Mode');
    if (!id) mode.value = '';
    mode.disabled = !id;
    const validate = byId(prefix + 'Validate');
    if (!id || mode.value !== 'duplicate') validate.checked = false;
    validate.disabled = mode.value !== 'duplicate';
  }
  function populate(prefix, record) {
    pending[prefix] = record;
    const select = byId(prefix + 'Destination');
    select.value = destinations.some(d => String(d.id) === String(record?.downstream_destination_id)) ? String(record.downstream_destination_id) : '';
    byId(prefix + 'Mode').value = select.value ? (record.downstream_mode || '') : '';
    byId(prefix + 'Validate').checked = !!record?.downstream_validate_response;
    update(prefix);
  }
  function payload(prefix) {
    const id = byId(prefix + 'Destination').value;
    const mode = byId(prefix + 'Mode').value;
    if (id && !mode) throw new Error('Choose duplicate or proxy-only route mode.');
    if (id && !destinations.some(d => String(d.id) === id)) throw new Error('Destination is not in the selected tenant.');
    return { downstream_destination_id: id ? Number(id) : null, downstream_mode: id ? mode : null, downstream_validate_response: id && mode === 'duplicate' && byId(prefix + 'Validate').checked === true };
  }
  return { load, update, populate, payload };
})();
