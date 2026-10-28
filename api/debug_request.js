// Log only the route family. Request bodies, query strings, and dynamic IDs/tokens
// can contain credentials and must never enter the persistent container log.
function summarizeRequest(req) {
    const match = String(req.path || '').match(/^\/(api|auth)\/([a-z][a-z0-9-]*)(?:\/|$)/i);
    const route = match ? `/${match[1]}/${match[2]}` : '[other]';
    return `${req.method} ${route} - IP: ${req.ip}`;
}
module.exports = { summarizeRequest };
