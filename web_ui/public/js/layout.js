
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
  if (res.status === 401 || res.status === 403) {
    alert('Access Denied or Session Expired');
    if(res.status === 401) logout();
  }
  return res;
};

// Tooltip style injection
document.head.insertAdjacentHTML('beforeend', `<style>
  [data-tooltip]:hover::after {
    content: attr(data-tooltip);
    position: absolute;
    background: #333; color: #fff;
    padding: 4px 8px; border-radius: 4px;
    font-size: 12px; white-space: nowrap;
    z-index: 100;
    transform: translateY(-100%); margin-top: -5px;
  }
  .custom-scrollbar::-webkit-scrollbar { width: 4px; }
  .custom-scrollbar::-webkit-scrollbar-track { background: transparent; }
  .custom-scrollbar::-webkit-scrollbar-thumb { background: #374151; border-radius: 4px; }
  .custom-scrollbar::-webkit-scrollbar-thumb:hover { background: #4b5563; }

</style>`);

document.addEventListener("DOMContentLoaded", async () => {
  if (window.location.pathname.endsWith('login.html')) return;
  getApiKey();

  let themeColor = 'blue';
  try {
    const res = await apiFetch('/api/settings');
    if (res.ok) {
      const data = await res.json();
      if(data.ui_theme) themeColor = data.ui_theme;
    }
  } catch(e){}

  const colors = {
    blue: { bg: 'bg-blue-600', text: 'text-blue-400', hover: 'hover:bg-blue-700' },
    red: { bg: 'bg-red-600', text: 'text-red-400', hover: 'hover:bg-red-700' },
    green: { bg: 'bg-green-600', text: 'text-green-400', hover: 'hover:bg-green-700' },
    purple: { bg: 'bg-purple-600', text: 'text-purple-400', hover: 'hover:bg-purple-700' },
    gray: { bg: 'bg-gray-800', text: 'text-gray-400', hover: 'hover:bg-gray-700' }
  };
  const theme = colors[themeColor] || colors.blue;

  const sidebar = `
    <div class="w-64 bg-gray-900 text-white h-screen p-5 flex flex-col shadow-2xl rounded-r-3xl border-r border-gray-800 relative z-20">
      <div class="flex items-center mb-10 space-x-3 bg-gray-800 p-3 rounded-2xl border border-gray-700">
        <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100" class="w-10 h-10 drop-shadow-md">
          <defs>
            <linearGradient id="boltGrad" x1="0%" y1="0%" x2="100%" y2="100%">
              <stop offset="0%" style="stop-color:#fbbf24;stop-opacity:1" />
              <stop offset="100%" style="stop-color:#d97706;stop-opacity:1" />
            </linearGradient>
            <filter id="glow" x="-20%" y="-20%" width="140%" height="140%">
              <feGaussianBlur stdDeviation="3" result="blur" />
              <feComposite in="SourceGraphic" in2="blur" operator="over" />
            </filter>
          </defs>
          <path d="M 15 50 Q 25 20 45 40 T 75 40 Q 85 20 95 35" fill="none" stroke="#6b7280" stroke-width="8" stroke-linecap="round" />
          <path d="M 55 5 L 25 50 L 45 55 L 35 95 L 75 45 L 55 40 Z" fill="url(#boltGrad)" filter="url(#glow)" />
          <path d="M 5 60 Q 25 80 50 60 T 80 65 Q 95 85 95 65" fill="none" stroke="#9ca3af" stroke-width="8" stroke-linecap="round" />
          <circle cx="25" cy="50" r="4" fill="#374151" />
          <circle cx="75" cy="50" r="4" fill="#374151" />
        </svg>
        <h1 class="text-2xl font-black tracking-tight bg-clip-text text-transparent bg-gradient-to-r from-gray-100 to-gray-400">Radius<span class="${theme.text}">Stack</span></h1>
      </div>
      <nav class="flex-1 space-y-2 font-medium overflow-y-auto pr-2 custom-scrollbar" id="sideNav">
        <a href="index.html" class="nav-link flex items-center py-3 px-4 rounded-xl transition-all duration-200 hover:bg-gray-800 text-gray-400 hover:text-white group">
            <span class="mr-3 text-lg opacity-70 group-hover:opacity-100 group-hover:scale-110 transition-transform">&#x1F4CA;</span> Dashboard
        </a>
        <a href="users.html" class="nav-link flex items-center py-3 px-4 rounded-xl transition-all duration-200 hover:bg-gray-800 text-gray-400 hover:text-white group">
            <span class="mr-3 text-lg opacity-70 group-hover:opacity-100 group-hover:scale-110 transition-transform">&#x1F465;</span> Users
        </a>
        <a href="mac-auth.html" class="nav-link flex items-center py-3 px-4 rounded-xl transition-all duration-200 hover:bg-gray-800 text-gray-400 hover:text-white group">
            <span class="mr-3 text-lg opacity-70 group-hover:opacity-100 group-hover:scale-110 transition-transform">&#x1F5A5;</span> MAC Auth
        </a>
        <a href="plans.html" class="nav-link flex items-center py-3 px-4 rounded-xl transition-all duration-200 hover:bg-gray-800 text-gray-400 hover:text-white group"><span class="mr-3 text-lg opacity-70 group-hover:opacity-100 group-hover:scale-110 transition-transform">&#x1F4CB;</span> Plans</a>
        <a href="profiles.html" class="nav-link flex items-center py-3 px-4 rounded-xl transition-all duration-200 hover:bg-gray-800 text-gray-400 hover:text-white group">
            <span class="mr-3 text-lg opacity-70 group-hover:opacity-100 group-hover:scale-110 transition-transform">&#x1F6E1;&#xFE0F;</span> Profiles
        </a>
        <a href="nas.html" class="nav-link flex items-center py-3 px-4 rounded-xl transition-all duration-200 hover:bg-gray-800 text-gray-400 hover:text-white group">
            <span class="mr-3 text-lg opacity-70 group-hover:opacity-100 group-hover:scale-110 transition-transform">&#x1F4E1;</span> NAS Clients
        </a>
        <a href="authlogs.html" class="nav-link flex items-center py-3 px-4 rounded-xl transition-all duration-200 hover:bg-gray-800 text-gray-400 hover:text-white group">
            <span class="mr-3 text-lg opacity-70 group-hover:opacity-100 group-hover:scale-110 transition-transform">&#x1F511;</span> Auth Logs
        </a>
        <a href="accounting.html" class="nav-link flex items-center py-3 px-4 rounded-xl transition-all duration-200 hover:bg-gray-800 text-gray-400 hover:text-white group">
            <span class="mr-3 text-lg opacity-70 group-hover:opacity-100 group-hover:scale-110 transition-transform">&#x23F1;&#xFE0F;</span> Accounting
        </a>
        <a href="reports.html" class="nav-link flex items-center py-3 px-4 rounded-xl transition-all duration-200 hover:bg-gray-800 text-gray-400 hover:text-white group">
            <span class="mr-3 text-lg opacity-70 group-hover:opacity-100 group-hover:scale-110 transition-transform">&#x1F4C8;</span> Reports
        </a>
        <a href="audit.html" class="nav-link flex items-center py-3 px-4 rounded-xl transition-all duration-200 hover:bg-gray-800 text-gray-400 hover:text-white group">
            <span class="mr-3 text-lg opacity-70 group-hover:opacity-100 group-hover:scale-110 transition-transform">&#x1F4DD;</span> Audit Log
        </a>
        <a href="admins.html" class="nav-link flex items-center py-3 px-4 rounded-xl transition-all duration-200 hover:bg-gray-800 text-gray-400 hover:text-white group">
            <span class="mr-3 text-lg opacity-70 group-hover:opacity-100 group-hover:scale-110 transition-transform">&#x2699;&#xFE0F;</span> Administrators
        </a>
        <a href="api-docs.html" class="nav-link flex items-center py-3 px-4 rounded-xl transition-all duration-200 hover:bg-gray-800 text-gray-400 hover:text-white group">
          <span class="mr-3 text-lg opacity-70 group-hover:opacity-100 group-hover:scale-110 transition-transform">&#x1F4DA;</span> API Docs
        </a>
        <a href="settings.html" class="nav-link flex items-center py-3 px-4 rounded-xl transition-all duration-200 hover:bg-gray-800 text-gray-400 hover:text-white group">
            <span class="mr-3 text-lg opacity-70 group-hover:opacity-100 group-hover:scale-110 transition-transform">&#x1F527;</span> Settings
        </a>
      </nav>
      <div class="mt-auto pt-6 border-t border-gray-800">
        <button onclick="logout()" class="w-full flex items-center justify-center bg-gray-800 hover:bg-red-600 transition-all duration-300 text-gray-300 hover:text-white py-3 rounded-xl font-bold shadow-sm group">
            <span class="mr-2 group-hover:-translate-x-1 transition-transform"></span> Logout
        </button>
      </div>
    </div>
`;

  document.body.insertAdjacentHTML('afterbegin', sidebar);
  document.body.className = "flex bg-gray-100 font-sans h-screen text-gray-800 antialiased";

  // Highlight active link
  const path = window.location.pathname.split('/').pop() || 'index.html';
  document.querySelectorAll('.nav-link').forEach(link => {
    if(link.getAttribute('href') === path) {
      link.classList.remove('text-gray-400', 'hover:bg-gray-800');
      link.classList.add(theme.bg, 'text-white', 'shadow-lg', 'font-bold');
      // Hacky dynamic shadow color based on theme
      if(theme.bg.includes('blue')) link.classList.add('shadow-blue-500/40');
      if(theme.bg.includes('red')) link.classList.add('shadow-red-500/40');
      if(theme.bg.includes('green')) link.classList.add('shadow-green-500/40');
      if(theme.bg.includes('purple')) link.classList.add('shadow-purple-500/40');
    }
  });

  const main = document.querySelector('main');
  if(main) main.className = "flex-1 p-8 overflow-y-auto";

  // Expose theme globally for buttons
  window.appTheme = theme;
});
