const express = require('express');
const { Pool } = require('pg');
const app = express();

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: {
        rejectUnauthorized: false
    }
});

// Ensure table exists (safe on every cold start)
async function ensureSchema() {
    try {
        await pool.query(`
            CREATE TABLE IF NOT EXISTS universal_breaches (
                id SERIAL PRIMARY KEY,
                identifier_type VARCHAR(50) NOT NULL,
                first_name TEXT,
                last_name TEXT,
                username TEXT,
                email TEXT,
                password TEXT,
                leaked_data_snippet TEXT,
                source_leak VARCHAR(255),
                breach_date DATE,
                created_at TIMESTAMPTZ DEFAULT NOW()
            );
        `);
    } catch (err) {
        console.error('Schema ensure error:', err.message);
    }
}
ensureSchema();

app.get('/api/health', async (req, res) => {
    try {
        await pool.query('SELECT 1');
        return res.json({ ok: true, database: 'connected' });
    } catch (err) {
        console.error('Health check error:', err.message);
        return res.status(500).json({ ok: false, database: 'error', detail: err.message });
    }
});

app.get('/api', (req, res) => {
    return res.json({
        name: 'BreachIntel API',
        status: 'online',
        endpoints: {
            health: 'GET /api/health',
            secureCheck: 'POST /api/secure-check',
            adminStats: 'GET /api/admin/stats'
        }
    });
});

app.post('/api/secure-check', async (req, res) => {
    try {
        const body = req.body || {};
        const type = body.type;
        const query = body.query;

        if (!query || !String(query).trim()) {
            return res.status(400).json({ error: 'Search query is required' });
        }

        const fieldMap = {
            email: 'email',
            username: 'username',
            password: 'password',
            first_name: 'first_name',
            last_name: 'last_name'
        };

        const column = fieldMap[type];
        if (!column) {
            return res.status(400).json({ error: 'Invalid search type' });
        }

        const allowed = ['email', 'username', 'password', 'first_name', 'last_name'];
        if (!allowed.includes(column)) {
            return res.status(400).json({ error: 'Invalid search type' });
        }

        const sql = `
            SELECT
                identifier_type,
                first_name,
                last_name,
                username,
                email,
                password,
                source_leak,
                breach_date,
                leaked_data_snippet
            FROM universal_breaches
            WHERE ${column} = $1
            LIMIT 1
        `;

        const result = await pool.query(sql, [String(query).trim()]);

        if (result.rows.length === 0) {
            return res.json({ pwned: false });
        }

        const record = result.rows[0];

        return res.json({
            pwned: true,
            match: {
                type: record.identifier_type,
                firstName: record.first_name,
                lastName: record.last_name,
                username: record.username,
                email: record.email,
                // Intentionally omit password from API response for safety
                source: record.source_leak,
                date: record.breach_date,
                snippet: record.leaked_data_snippet
            }
        });
    } catch (err) {
        console.error('Database query error:', err.message);
        return res.status(500).json({
            error: 'Internal server error',
            detail: err.message
        });
    }
});

app.get('/api/admin/stats', async (req, res) => {
    const adminToken = req.headers['x-admin-token'];
    if (
        !adminToken ||
        !process.env.ADMIN_SECRET ||
        adminToken !== process.env.ADMIN_SECRET
    ) {
        return res.status(401).json({ error: 'Unauthorized access' });
    }

    try {
        const totalCountRes = await pool.query(`
            SELECT COUNT(*) AS count FROM universal_breaches
        `);
        const typeBreakdownRes = await pool.query(`
            SELECT identifier_type, COUNT(*) AS count
            FROM universal_breaches
            GROUP BY identifier_type
            ORDER BY count DESC
        `);
        const recentRecordsRes = await pool.query(`
            SELECT
                id, identifier_type, first_name, last_name,
                username, email, source_leak, breach_date
            FROM universal_breaches
            ORDER BY id DESC
            LIMIT 10
        `);

        return res.json({
            totalRecords: totalCountRes.rows[0].count,
            breakdown: typeBreakdownRes.rows,
            recent: recentRecordsRes.rows
        });
    } catch (err) {
        console.error('Admin stats error:', err.message);
        return res.status(500).json({ error: 'Internal server error', detail: err.message });
    }
});

app.use('/api', (req, res) => {
    return res.status(404).json({
        error: 'API endpoint not found',
        path: req.originalUrl
    });
});

module.exports = app;
