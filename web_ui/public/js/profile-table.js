(function (root, factory) {
  const api = factory();
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
  root.ProfileTableCore = api;
})(typeof window !== 'undefined' ? window : globalThis, function () {
  const skipReplyAttributes = new Set(['Tunnel-Type', 'Tunnel-Medium-Type', 'Tunnel-Private-Group-ID']);

  function buildProfileRows({ checks = [], replies = [], users = [], userCounts = [] }) {
    const names = new Set();
    [...checks, ...replies].forEach(item => { if (item.groupname) names.add(item.groupname); });
    users.forEach(user => { if (user.profile) names.add(user.profile); });
    userCounts.forEach(item => { if (item.groupname) names.add(item.groupname); });
    const userCountByProfile = new Map(userCounts.map(item => [item.groupname, Number(item.users) || 0]));

    return Array.from(names).map(profileName => {
      const profileChecks = checks.filter(check => check.groupname === profileName);
      const profileReplies = replies.filter(reply => reply.groupname === profileName);
      const nas = profileChecks.filter(check => check.attribute === 'NAS-IP-Address').map(check => check.value);
      const vlanReply = profileReplies.find(reply => reply.attribute === 'Tunnel-Private-Group-ID');
      const visibleReplies = profileReplies.filter(reply => !skipReplyAttributes.has(reply.attribute));
      const replyText = visibleReplies.map(reply => `${reply.attribute} ${reply.value}`).join(' ');
      return {
        profileName,
        vlan: vlanReply ? vlanReply.value : '',
        nas,
        replies: visibleReplies.length,
        replyText,
        users: userCountByProfile.has(profileName) ? userCountByProfile.get(profileName) : users.filter(user => user.profile === profileName).length
      };
    });
  }

  function sortValue(row, field) {
    if (field === 'users' || field === 'replies') return Number(row[field] || 0);
    if (field === 'vlan') return row.vlan === '' ? -1 : Number(row.vlan);
    if (field === 'nas') return row.nas.join(', ');
    return row.profileName || '';
  }

  function applyProfileTableState(rows, { search = '', sort = 'profileName', order = 'asc', page = 1, pageSize = 25 } = {}) {
    const term = String(search).trim().toLocaleLowerCase();
    const filtered = rows.filter(row => {
      const searchable = [row.profileName, row.vlan, row.nas.join(' '), row.replyText].join(' ').toLocaleLowerCase();
      return !term || searchable.includes(term);
    });
    const sorted = [...filtered].sort((left, right) => {
      const a = sortValue(left, sort);
      const b = sortValue(right, sort);
      const comparison = typeof a === 'number' && typeof b === 'number'
        ? a - b
        : String(a).localeCompare(String(b), undefined, { numeric: true, sensitivity: 'base' });
      return order === 'desc' ? -comparison : comparison;
    });
    const safePageSize = [25, 50, 100].includes(Number(pageSize)) ? Number(pageSize) : 25;
    const totalRows = sorted.length;
    const totalPages = Math.max(1, Math.ceil(totalRows / safePageSize));
    const safePage = Math.min(Math.max(Number(page) || 1, 1), totalPages);
    const start = (safePage - 1) * safePageSize;
    return { rows: sorted.slice(start, start + safePageSize), totalRows, totalPages, page: safePage, pageSize: safePageSize };
  }

  return { buildProfileRows, applyProfileTableState };
});
