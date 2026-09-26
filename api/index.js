const express = require('express');
const { Pool } = require('pg');
const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
// ==================================================
// Neon PostgreSQL connection
// ==================================================
const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: {
        rejectUnauthorized: false
    }
});
// ==================================================
// Health check
// ==================================================
app.get('/api/health', async (req, res) => {
    try {
        await pool.query('SELECT 1');
        return res.json({
            ok: true,
            database: 'connected'
        });
    } catch (err) {
        console.error('Health check error:', err.message);
        return res.status(500).json({
            ok: false,
            database: 'error'
        });
    }
});
// ==================================================
// API information
// ==================================================
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
// ==================================================
// Secure database search
// ==================================================
app.post('/api/secure-check', async (req, res) => {
    const { type, query } = req.body;
    if (!query || !String(query).trim()) {
        return res.status(400).json({
            error: 'Search query is required'
        });
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
        return res.status(400).json({
            error: 'Invalid search type'
        });
    }
    try {
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
        const result = await pool.query(sql, [
            String(query).trim()
        ]);
        if (result.rows.length === 0) {
            return res.json({
                pwned: false
            });
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
                password: record.password,
                source: record.source_leak,
                date: record.breach_date,
                snippet: record.leaked_data_snippet
            }
        });
    } catch (err) {
        console.error(
            'Database query error:',
            err.message
        );
        return res.status(500).json({
            error: 'Internal server error'
        });
    }
});
// ==================================================
// Admin statistics
// ==================================================
app.get('/api/admin/stats', async (req, res) => {
    const adminToken = req.headers['x-admin-token'];
    if (
        !adminToken ||
        !process.env.ADMIN_SECRET ||
        adminToken !== process.env.ADMIN_SECRET
    ) {
        return res.status(401).json({
            error: 'Unauthorized access'
        });
    }
    try {
        const totalCountRes = await pool.query(`
            SELECT COUNT(*) AS count
            FROM universal_breaches
        `);
        const typeBreakdownRes = await pool.query(`
            SELECT
                identifier_type,
                COUNT(*) AS count
            FROM universal_breaches
            GROUP BY identifier_type
            ORDER BY count DESC
        `);
        const recentRecordsRes = await pool.query(`
            SELECT
                id,
                identifier_type,
                first_name,
                last_name,
                username,
                email,
                password,
                source_leak,
                breach_date
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
        console.error(
            'Admin stats error:',
            err.message
        );
        return res.status(500).json({
            error: 'Internal server error'
        });
    }
});
// ==================================================
// API 404
// ==================================================
app.use('/api', (req, res) => {
    return res.status(404).json({
        error: 'API endpoint not found',
        path: req.originalUrl
    });
});
// ==================================================
// Vercel export
// ==================================================
module.exports = app;