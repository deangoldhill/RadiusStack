(function (root, factory) {
  const api = factory();
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
  root.PlanTableCore = api;
})(typeof window !== 'undefined' ? window : globalThis, function () {
  function sortValue(plan, field) {
    if (field === 'data_limit_mb' || field === 'time_limit_seconds') return Number(plan[field] || 0);
    return String(plan[field] || '');
  }

  function applyPlanTableState(plans, { search = '', sort = 'name', order = 'asc', page = 1, pageSize = 25 } = {}) {
    const term = String(search).trim().toLocaleLowerCase();
    const filtered = plans.filter(plan => !term || [plan.name, plan.reset_period, plan.data_limit_mb, plan.time_limit_seconds].join(' ').toLocaleLowerCase().includes(term));
    const sorted = [...filtered].sort((left, right) => {
      const a = sortValue(left, sort), b = sortValue(right, sort);
      const comparison = typeof a === 'number' && typeof b === 'number' ? a - b : a.localeCompare(b, undefined, { numeric: true, sensitivity: 'base' });
      return order === 'desc' ? -comparison : comparison;
    });
    const safePageSize = [25, 50, 100].includes(Number(pageSize)) ? Number(pageSize) : 25;
    const totalRows = sorted.length;
    const totalPages = Math.max(1, Math.ceil(totalRows / safePageSize));
    const safePage = Math.min(Math.max(Number(page) || 1, 1), totalPages);
    const start = (safePage - 1) * safePageSize;
    return { rows: sorted.slice(start, start + safePageSize), totalRows, totalPages, page: safePage, pageSize: safePageSize };
  }

  return { applyPlanTableState };
});
