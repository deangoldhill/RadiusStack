'use strict';

// Standalone pool writes only. The captured getConnection must return raw mysql2
// connections; never use a connection whose query/execute is HA-wrapped.
function createHaWriteCapture({ pool, getConnection, query, execute, isPrimary }) {
    async function write(method, args) {
        const [sql, values] = args;
        const sqlUpper = sql ? sql.toString().trim().toUpperCase() : '';
        const isWrite = /^(INSERT|UPDATE|DELETE|REPLACE)\b/.test(sqlUpper);
        const exempt = args[2]?.isSync === true || sqlUpper.includes('HA_QUEUE') ||
            sqlUpper.includes('HA_SYNC_STATE') ||
            (sqlUpper.includes('INTO RADIUS_STATS') || sqlUpper.includes('UPDATE RADIUS_STATS') || sqlUpper.includes('FROM RADIUS_STATS'));
        if (!isPrimary() || !isWrite || exempt) {
            return (method === 'query' ? query : execute).apply(pool, args);
        }

        const connection = await getConnection.call(pool);
        let transactionStarted = false;
        try {
            await connection.beginTransaction();
            transactionStarted = true;
            const [control] = await connection.query('SELECT id FROM ha_control_state WHERE id=1 FOR UPDATE');
            if (control.length !== 1) throw new Error('HA control row missing; apply database migrations');
            const result = await connection[method](sql, values);
            const insertId = result?.[0]?.insertId || null;
            await connection.query('INSERT INTO ha_queue (query, values_json, insert_id) VALUES (?, ?, ?)',
                [sql, JSON.stringify(values || []), insertId]);
            await connection.commit();
            return result;
        } catch (error) {
            if (transactionStarted) {
                try { await connection.rollback(); } catch (rollbackError) { error.rollbackError = rollbackError; }
            }
            throw error;
        } finally {
            connection.release();
        }
    }
    return {
        query(...args) { return write('query', args); },
        execute(...args) { return write('execute', args); }
    };
}

module.exports = { createHaWriteCapture };
