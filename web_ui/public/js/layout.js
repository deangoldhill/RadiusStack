function getApiKey() {
  const key = localStorage.getItem('apiKey');
  if (!key && !window.location.pathname.endsWith('login.html')) window.location.href = 'login.html';
  return key;
}
function logout() { localStorage.removeItem('apiKey'); window.location.href = 'login.html'; }

const apiFetch = async (url, options = {}) => {
  const key = getApiKey();
  const headers = { 'X-API-Key': key, 'Content-Type': 'application/json', ...(options.headers || {}) };
  const res = await fetch(url, { ...options, headers });
  if (res.status === 401) { logout(); }
  return res;
};

document.head.insertAdjacentHTML('beforeend', `<style>
  [data-tooltip]:hover::after {
    content: attr(data-tooltip);
    position: absolute; background: #333; color: #fff;
    padding: 4px 8px; border-radius: 4px;
    font-size: 12px; white-space: nowrap; z-index: 100;
    transform: translateY(-100%); margin-top: -5px;
  }
  .custom-scrollbar::-webkit-scrollbar { width: 4px; }
  .custom-scrollbar::-webkit-scrollbar-track { background: transparent; }
  .custom-scrollbar::-webkit-scrollbar-thumb { background: #374151; border-radius: 4px; }
  .custom-scrollbar::-webkit-scrollbar-thumb:hover { background: #4b5563; }
  .nav-hidden { display: none !important; }
  #accessDeniedBanner {
    position: fixed; inset: 0; z-index: 9999;
    background: rgba(0,0,0,0.75);
    display: flex; align-items: center; justify-content: center;
  }
  #accessDeniedBanner .banner-box {
    background: #1f2937; border: 1px solid #ef4444;
    border-radius: 1rem; padding: 2.5rem 3rem;
    text-align: center; color: white; max-width: 400px;
  }
  #accessDeniedBanner .banner-box h2 { font-size: 1.5rem; font-weight: 800; color: #ef4444; margin-bottom: 0.5rem; }
  #accessDeniedBanner .banner-box p  { color: #9ca3af; margin-bottom: 1.5rem; }
  #accessDeniedBanner .banner-box button {
    background: #374151; color: white; border: none;
    padding: 0.6rem 1.5rem; border-radius: 0.5rem; cursor: pointer; font-weight: 600;
  }
  #accessDeniedBanner .banner-box button:hover { background: #4b5563; }
</style>`);

const PAGE_PERMISSIONS = {
  'index.html': null, 'users.html': 'users', 'mac-auth.html': 'users',
  'profiles.html': 'users', 'plans.html': 'plans', 'nas.html': 'nas',
  'authlogs.html': 'reports', 'accounting.html': 'reports', 'reports.html': 'reports',
  'audit.html': 'admins', 'admins.html': 'admins', 'settings.html': 'settings', 'api-docs.html': null,
};

const NAV_MODULES = {
  'users.html': 'users', 'mac-auth.html': 'users', 'profiles.html': 'users',
  'plans.html': 'plans', 'nas.html': 'nas',
  'authlogs.html': 'reports', 'accounting.html': 'reports', 'reports.html': 'reports',
  'audit.html': 'admins', 'admins.html': 'admins', 'settings.html': 'settings',
};

function hasPermission(perms, module) {
  if (!module) return true;
  if (!perms || Object.keys(perms).length === 0) return true; // fail open if perms unavailable
  return !!perms[module];
}

function showAccessDenied() {
  const el = document.createElement('div');
  el.id = 'accessDeniedBanner';
  el.innerHTML = '<div class="banner-box"><h2>&#x1F6AB; Access Denied</h2><p>You don\'t have permission to view this page.</p><button onclick="window.location.href=\'index.html\'">Go to Dashboard</button></div>';
  document.body.appendChild(el);
}

document.addEventListener("DOMContentLoaded", async () => {
  if (window.location.pathname.endsWith('login.html')) return;
  getApiKey();

  let themeColor = 'blue';
  let perms = {};

  try {
    const [settingsRes, meRes] = await Promise.all([
      apiFetch('/api/settings'),
      apiFetch('/api/auth/me'),
    ]);
    if (settingsRes && settingsRes.ok) {
      const d = await settingsRes.json();
      if (d.ui_theme) themeColor = d.ui_theme;
    }
    if (meRes && meRes.ok) {
      const me = await meRes.json();
      try { perms = typeof me.permissions === 'string' ? JSON.parse(me.permissions) : (me.permissions || {}); }
      catch(e) { perms = {}; }
      window.currentAdmin = me.username || '';
    }
  } catch(e) { console.warn('RadiusStack layout: permission fetch failed', e); }

  const colors = {
    blue:   { bg: 'bg-blue-600',   text: 'text-blue-400',   shadow: 'shadow-blue-500/40' },
    red:    { bg: 'bg-red-600',    text: 'text-red-400',    shadow: 'shadow-red-500/40' },
    green:  { bg: 'bg-green-600',  text: 'text-green-400',  shadow: 'shadow-green-500/40' },
    purple: { bg: 'bg-purple-600', text: 'text-purple-400', shadow: 'shadow-purple-500/40' },
    gray:   { bg: 'bg-gray-800',   text: 'text-gray-400',   shadow: 'shadow-gray-500/40' },
  };
  const theme = colors[themeColor] || colors.blue;

  document.body.insertAdjacentHTML('afterbegin', `
    <div class="w-64 bg-gray-900 text-white h-screen p-5 flex flex-col shadow-2xl rounded-r-3xl border-r border-gray-800 relative z-20">
      <div class="flex items-center mb-10 gap-3 px-3 py-3 rounded-2xl" style="background:linear-gradient(135deg,#1e2736 0%,#1a2234 100%);border:1px solid rgba(59,130,246,0.2);">
        <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100" class="w-10 h-10 flex-shrink-0 drop-shadow-lg" aria-label="RadiusStack">
          <defs>
            <linearGradient id="shieldGrad" x1="0%" y1="0%" x2="100%" y2="100%">
              <stop offset="0%" stop-color="#3b82f6"/>
              <stop offset="100%" stop-color="#1d4ed8"/>
            </linearGradient>
            <clipPath id="shieldClip">
              <path d="M50 8 L88 22 L88 52 C88 72 70 88 50 94 C30 88 12 72 12 52 L12 22 Z"/>
            </clipPath>
          </defs>
          <path d="M50 8 L88 22 L88 52 C88 72 70 88 50 94 C30 88 12 72 12 52 L12 22 Z" fill="url(#shieldGrad)"/>
          <path d="M50 14 L83 26 L83 52 C83 69 67 84 50 89 C33 84 17 69 17 52 L17 26 Z" fill="none" stroke="rgba(255,255,255,0.15)" stroke-width="1.5"/>
          <g clip-path="url(#shieldClip)" fill="none" stroke="white" stroke-linecap="round">
            <path d="M28 56 A26 26 0 0 1 72 56" stroke-width="5.5" stroke-opacity="0.5"/>
            <path d="M34 62 A18 18 0 0 1 66 62" stroke-width="5.5" stroke-opacity="0.75"/>
            <path d="M40 68 A10 10 0 0 1 60 68" stroke-width="5.5"/>
            <circle cx="50" cy="72" r="4.5" fill="white" stroke="none"/>
          </g>
        </svg>
        <div class="min-w-0">
          <div style="font-size:1.1rem;font-weight:800;letter-spacing:-0.02em;line-height:1.2;">
            <span style="color:#f1f5f9;">Radius</span><span style="color:#3b82f6;">Stack</span>
          </div>
          <div style="font-size:0.65rem;letter-spacing:0.12em;text-transform:uppercase;color:#475569;font-weight:600;margin-top:1px;">Network Auth</div>
          ${window.currentAdmin ? `<p class="text-xs truncate max-w-xs" style="color:#64748b;margin-top:2px;">${window.currentAdmin}</p>` : ''}
        </div>
      </div>
      <nav class="flex-1 space-y-2 font-medium overflow-y-auto pr-2 custom-scrollbar" id="sideNav">
        <a href="index.html"      class="nav-link flex items-center py-3 px-4 rounded-xl transition-all duration-200 hover:bg-gray-800 text-gray-400 hover:text-white group"><span class="mr-3 text-lg opacity-70 group-hover:opacity-100 group-hover:scale-110 transition-transform">&#x1F4CA;</span> Dashboard</a>
        <a href="active-sessions.html" class="nav-link flex items-center py-3 px-4 rounded-xl transition-all duration-200 hover:bg-gray-800 text-gray-400 hover:text-white group"><span class="mr-3 text-lg opacity-70 group-hover:opacity-100 group-hover:scale-110 transition-transform">&#x1F7E2;</span> Active Sessions</a>
        <a href="users.html"      class="nav-link flex items-center py-3 px-4 rounded-xl transition-all duration-200 hover:bg-gray-800 text-gray-400 hover:text-white group"><span class="mr-3 text-lg opacity-70 group-hover:opacity-100 group-hover:scale-110 transition-transform">&#x1F465;</span> Users</a>
        <a href="mac-auth.html"   class="nav-link flex items-center py-3 px-4 rounded-xl transition-all duration-200 hover:bg-gray-800 text-gray-400 hover:text-white group"><span class="mr-3 text-lg opacity-70 group-hover:opacity-100 group-hover:scale-110 transition-transform">&#x1F5A5;</span> MAC Auth</a>
        <a href="plans.html"      class="nav-link flex items-center py-3 px-4 rounded-xl transition-all duration-200 hover:bg-gray-800 text-gray-400 hover:text-white group"><span class="mr-3 text-lg opacity-70 group-hover:opacity-100 group-hover:scale-110 transition-transform">&#x1F4CB;</span> Plans</a>
        <a href="profiles.html"   class="nav-link flex items-center py-3 px-4 rounded-xl transition-all duration-200 hover:bg-gray-800 text-gray-400 hover:text-white group"><span class="mr-3 text-lg opacity-70 group-hover:opacity-100 group-hover:scale-110 transition-transform">&#x1F6E1;&#xFE0F;</span> Profiles</a>
        <a href="nas.html"        class="nav-link flex items-center py-3 px-4 rounded-xl transition-all duration-200 hover:bg-gray-800 text-gray-400 hover:text-white group"><span class="mr-3 text-lg opacity-70 group-hover:opacity-100 group-hover:scale-110 transition-transform">&#x1F4E1;</span> NAS Clients</a>
        <a href="authlogs.html"   class="nav-link flex items-center py-3 px-4 rounded-xl transition-all duration-200 hover:bg-gray-800 text-gray-400 hover:text-white group"><span class="mr-3 text-lg opacity-70 group-hover:opacity-100 group-hover:scale-110 transition-transform">&#x1F511;</span> Auth Logs</a>
        <a href="accounting.html" class="nav-link flex items-center py-3 px-4 rounded-xl transition-all duration-200 hover:bg-gray-800 text-gray-400 hover:text-white group"><span class="mr-3 text-lg opacity-70 group-hover:opacity-100 group-hover:scale-110 transition-transform">&#x23F1;&#xFE0F;</span> Accounting</a>
        <a href="reports.html"    class="nav-link flex items-center py-3 px-4 rounded-xl transition-all duration-200 hover:bg-gray-800 text-gray-400 hover:text-white group"><span class="mr-3 text-lg opacity-70 group-hover:opacity-100 group-hover:scale-110 transition-transform">&#x1F4C8;</span> Reports</a>
        <a href="audit.html"      class="nav-link flex items-center py-3 px-4 rounded-xl transition-all duration-200 hover:bg-gray-800 text-gray-400 hover:text-white group"><span class="mr-3 text-lg opacity-70 group-hover:opacity-100 group-hover:scale-110 transition-transform">&#x1F4DD;</span> Audit Log</a>
        <a href="admins.html"     class="nav-link flex items-center py-3 px-4 rounded-xl transition-all duration-200 hover:bg-gray-800 text-gray-400 hover:text-white group"><span class="mr-3 text-lg opacity-70 group-hover:opacity-100 group-hover:scale-110 transition-transform">&#x2699;&#xFE0F;</span> Administrators</a>
        <a href="api-docs.html"   class="nav-link flex items-center py-3 px-4 rounded-xl transition-all duration-200 hover:bg-gray-800 text-gray-400 hover:text-white group"><span class="mr-3 text-lg opacity-70 group-hover:opacity-100 group-hover:scale-110 transition-transform">&#x1F4DA;</span> API Docs</a>
        <a href="settings.html"   class="nav-link flex items-center py-3 px-4 rounded-xl transition-all duration-200 hover:bg-gray-800 text-gray-400 hover:text-white group"><span class="mr-3 text-lg opacity-70 group-hover:opacity-100 group-hover:scale-110 transition-transform">&#x1F527;</span> Settings</a>
      </nav>
      <div class="mt-auto pt-6 border-t border-gray-800 space-y-3">
        <button onclick="openadminPasswordModal()" class="w-full flex items-center justify-center bg-gray-800 hover:bg-gray-700 transition-all duration-300 text-gray-300 hover:text-white py-3 rounded-xl font-bold shadow-sm group">
          <span class="mr-2 group-hover:-translate-y-1 transition-transform">👤</span> Profile
        </button>
        <button onclick="logout()" class="w-full flex items-center justify-center bg-gray-800 hover:bg-red-600 transition-all duration-300 text-gray-300 hover:text-white py-3 rounded-xl font-bold shadow-sm group">
          <span class="mr-2 group-hover:-translate-x-1 transition-transform"></span> Logout
        </button>
      </div>
    </div>
  `);

  document.body.className = "flex bg-gray-100 font-sans h-screen text-gray-800 antialiased";

  // Hide nav items the admin has no permission for
  document.querySelectorAll('.nav-link').forEach(link => {
    const mod = NAV_MODULES[link.getAttribute('href')];
    if (mod && !hasPermission(perms, mod)) link.classList.add('nav-hidden');
  });

  // Block direct URL access to forbidden pages
  const currentPage = window.location.pathname.split('/').pop() || 'index.html';
  const pageModule = PAGE_PERMISSIONS[currentPage];
  if (pageModule && !hasPermission(perms, pageModule)) showAccessDenied();

  // Highlight active nav link
  document.querySelectorAll('.nav-link').forEach(link => {
    if (link.getAttribute('href') === currentPage) {
      link.classList.remove('text-gray-400', 'hover:bg-gray-800', 'hover:text-white');
      link.classList.add(theme.bg, 'text-white', 'shadow-lg', 'font-bold', theme.shadow);
    }
  });

  const main = document.querySelector('main');
  if (main) main.className = "flex-1 p-8 overflow-y-auto";

    window.appTheme = theme;
  // Inject Profile Password Modal
  document.body.insertAdjacentHTML('beforeend', `
    <div id="adminPasswordModal" class="fixed inset-0 bg-black bg-opacity-60 hidden flex items-center justify-center p-4 z-50 backdrop-blur-sm">
      <div class="bg-white p-6 rounded-xl shadow-2xl max-w-md w-full border border-gray-100">
        <h2 class="text-xl font-bold mb-4 text-gray-800">Change My Password</h2>
        <form id="adminPasswordForm" class="space-y-4">
          <div>
            <label class="block text-sm font-bold text-gray-700 mb-1">Current Password</label>
            <input type="password" id="profOldPass" class="w-full border p-2 rounded-lg bg-gray-50 focus:ring focus:ring-blue-200 outline-none" required>
          </div>
          <div>
            <label class="block text-sm font-bold text-gray-700 mb-1">New Password</label>
            <input type="password" id="profNewPass" class="w-full border p-2 rounded-lg bg-gray-50 focus:ring focus:ring-blue-200 outline-none" required>
          </div>
          <div class="flex justify-end gap-3 mt-6">
            <button type="button" onclick="closeadminPasswordModal()" class="px-4 py-2 bg-gray-200 text-gray-800 rounded-lg hover:bg-gray-300 font-bold transition-colors shadow-sm">Cancel</button>
            <button type="submit" class="px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 font-bold transition-colors shadow-sm">Save Password</button>
          </div>
        </form>
      </div>
    </div>
  `);

  window.openadminPasswordModal = () => {
      document.getElementById('adminPasswordModal').classList.remove('hidden');
      document.getElementById('adminPasswordForm').reset();
  };

  window.closeadminPasswordModal = () => {
      document.getElementById('adminPasswordModal').classList.add('hidden');
  };

  document.getElementById('adminPasswordForm').onsubmit = async (e) => {
      e.preventDefault();
      const oldPassword = document.getElementById('profOldPass').value;
      const newPassword = document.getElementById('profNewPass').value;
      
      const res = await apiFetch('/api/auth/me/password', {
          method: 'PUT',
          body: JSON.stringify({ oldPassword, newPassword })
      });
      
      if (res.ok) {
          alert('Password updated successfully!');
          closeadminPasswordModal();
      } else {
          const data = await res.json();
          alert('Error: ' + data.error);
      }
  };
});
