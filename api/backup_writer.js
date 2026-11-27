const LOG_TABLES = [
    ['radacct', 'radacctid', 'acct'],
    ['radpostauth', 'id', 'auth'],
    ['admin_audit_log', 'id', 'audit']
];

// Configuration is bounded by table; log tables are emitted one row at a time.
async function* backupChunks(pool, job, buildBackup) {
    const connection = await pool.getConnection();
    try {
        await connection.query('SET TRANSACTION ISOLATION LEVEL REPEATABLE READ');
        await connection.query('START TRANSACTION WITH CONSISTENT SNAPSHOT');
        const backup = await buildBackup(connection, { ...job, strict: false, strictQueries: true, omitLogs: true });
        yield '{"metadata":';
        yield JSON.stringify(backup.metadata);
        yield ',"data":{';
        let separator = '';
        for (const [table, rows] of Object.entries(backup.data)) {
            yield separator + JSON.stringify(table) + ':';
            yield JSON.stringify(rows);
            separator = ',';
        }
        // Identifiers come only from this static whitelist, never from the job.
        for (const [table, key, flag] of LOG_TABLES) {
            if (job.type !== 'full' && job[flag] !== true && job[flag] !== 1) continue;
            yield separator + JSON.stringify(table) + ':[';
            let cursor = null;
            let rowSeparator = '';
            while (true) {
                const where = cursor === null ? '' : ` WHERE \`${key}\` > ?`;
                let rows;
                try {
                    [rows] = await connection.query({
                        sql: `SELECT * FROM \`${table}\`${where} ORDER BY \`${key}\` ASC LIMIT 500`,
                        supportBigNumbers: true,
                        bigNumberStrings: true
                    }, cursor === null ? [] : [cursor]);
                } catch (error) {
                    error.backupTable = table;
                    error.backupStage = 'read';
                    throw error;
                }
                for (const row of rows) {
                    const value = row[key];
                    if ((typeof value !== 'string' && typeof value !== 'number') ||
                        (typeof value === 'number' && !Number.isSafeInteger(value)) ||
                        !/^-?\d+$/.test(String(value)) ||
                        (cursor !== null && BigInt(value) <= BigInt(cursor))) {
                        throw new Error('Invalid backup pagination');
                    }
                    cursor = String(value);
                    yield rowSeparator + JSON.stringify(row);
                    rowSeparator = ',';
                }
                if (rows.length < 500) break;
            }
            yield ']';
            separator = ',';
        }
        yield '}}';
    } finally {
        try { await connection.rollback(); }
        finally { connection.release(); }
    }
}

module.exports = { backupChunks };
