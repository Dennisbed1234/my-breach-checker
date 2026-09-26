const { Pool } = require('pg');

const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: {
        rejectUnauthorized: false
    }
});

async function initDb() {
    const client = await pool.connect();

    try {
        await client.query(`
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

        await client.query(`
            CREATE INDEX IF NOT EXISTS idx_universal_breaches_email
            ON universal_breaches(email);
        `);

        await client.query(`
            CREATE INDEX IF NOT EXISTS idx_universal_breaches_username
            ON universal_breaches(username);
        `);

        await client.query(`
            CREATE INDEX IF NOT EXISTS idx_universal_breaches_first_name
            ON universal_breaches(first_name);
        `);

        await client.query(`
            CREATE INDEX IF NOT EXISTS idx_universal_breaches_last_name
            ON universal_breaches(last_name);
        `);

        await client.query(`
            CREATE INDEX IF NOT EXISTS idx_universal_breaches_password
            ON universal_breaches(password);
        `);

        await client.query(`
            CREATE INDEX IF NOT EXISTS idx_universal_breaches_identifier_type
            ON universal_breaches(identifier_type);
        `);

        console.log('[✔] Cloud PostgreSQL database initialized.');
    } finally {
        client.release();
    }
}

initDb().catch(err => {
    console.error('[!] Database initialization error:', err.message);
});

exports.query = (text, params) => {
    return pool.query(text, params);
};

exports.pool = pool;
