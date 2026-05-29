const mysql = require('mysql2/promise');

const pool = mysql.createPool({
    host: process.env.DB_HOST || 'mariadb',
    user: process.env.DB_USER || 'radius',
    password: process.env.DB_PASS || '',
    database: process.env.DB_NAME || 'radius',
    dateStrings: true
});

module.exports = { pool };
