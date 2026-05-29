const fs = require('fs');
const path = require('path');

module.exports = function(app, pool, requireApiAuth, auditLog, dependencies) {
    require('./auth_self')(app, pool, requireApiAuth, auditLog, dependencies);
    require('./audit_logs')(app, pool, requireApiAuth, auditLog, dependencies);
    require('./settings')(app, pool, requireApiAuth, auditLog, dependencies);
    require('./system')(app, pool, requireApiAuth, auditLog, dependencies);
    require('./certs')(app, pool, requireApiAuth, auditLog, dependencies);
    require('./admins')(app, pool, requireApiAuth, auditLog, dependencies);
    require('./plans')(app, pool, requireApiAuth, auditLog, dependencies);
    require('./nas')(app, pool, requireApiAuth, auditLog, dependencies);
    require('./profiles')(app, pool, requireApiAuth, auditLog, dependencies);
    require('./users')(app, pool, requireApiAuth, auditLog, dependencies);
    require('./reports')(app, pool, requireApiAuth, auditLog, dependencies);
    require('./backup')(app, pool, requireApiAuth, auditLog, dependencies);
    require('./mac_auth')(app, pool, requireApiAuth, auditLog, dependencies);
};
