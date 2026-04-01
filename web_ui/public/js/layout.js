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
      <div class="flex items-center mb-10 space-x-3 bg-gray-800 p-3 rounded-2xl border border-gray-700">
        <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100" class="w-10 h-10 drop-shadow-md">
          <defs>
            <linearGradient id="boltGrad" x1="0%" y1="0%" x2="100%" y2="100%">
              <stop offset="0%" style="stop-color:#fbbf24;stop-opacity:1"/>
              <stop offset="100%" style="stop-color:#d97706;stop-opacity:1"/>
            </linearGradient>
            <filter id="glow" x="-20%" y="-20%" width="140%" height="140%">
              <feGaussianBlur stdDeviation="3" result="blur"/>
              <feComposite in="SourceGraphic" in2="blur" operator="over"/>
            </filter>
          </defs>
          <path d="M 15 50 Q 25 20 45 40 T 75 40 Q 85 20 95 35" fill="none" stroke="#6b7280" stroke-width="8" stroke-linecap="round"/>
          <path d="M 55 5 L 25 50 L 45 55 L 35 95 L 75 45 L 55 40 Z" fill="url(#boltGrad)" filter="url(#glow)"/>
          <path d="M 5 60 Q 25 80 50 60 T 80 65 Q 95 85 95 65" fill="none" stroke="#9ca3af" stroke-width="8" stroke-linecap="round"/>
          <circle cx="25" cy="50" r="4" fill="#374151"/>
          <circle cx="75" cy="50" r="4" fill="#374151"/>
        </svg>
        <div>
          <h1 class="text-2xl font-black tracking-tight bg-clip-text text-transparent bg-gradient-to-r from-gray-100 to-gray-400">Radius<span class="${theme.text}">Stack</span></h1>
          ${window.currentAdmin ? `<p class="text-xs text-gray-500 truncate max-w-xs">${window.currentAdmin}</p>` : ''}
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
      <div class="mt-auto pt-6 border-t border-gray-800">
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
});
