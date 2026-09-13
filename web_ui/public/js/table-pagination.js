(function (root, factory) {
  const api = factory();
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
  root.TablePagination = api;
})(typeof window !== 'undefined' ? window : globalThis, function () {
  function paginateRows(rows, { page = 1, pageSize = 25 } = {}) {
    const safePageSize = [25, 50, 100].includes(Number(pageSize)) ? Number(pageSize) : 25;
    const totalRows = rows.length;
    const totalPages = Math.max(1, Math.ceil(totalRows / safePageSize));
    const safePage = Math.min(Math.max(Number(page) || 1, 1), totalPages);
    const start = (safePage - 1) * safePageSize;
    return { rows: rows.slice(start, start + safePageSize), totalRows, totalPages, page: safePage, pageSize: safePageSize };
  }
  return { paginateRows };
});
