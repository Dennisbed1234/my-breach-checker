const fs = require('fs');
const readline = require('readline');
const { Pool } = require('pg');

const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: { rejectUnauthorized: false }
});

async function importSqlDump(filePath) {
    console.log(`[*] Starting stream import for SQL dump: ${filePath}`);

    const fileStream = fs.createReadStream(filePath);
    const rl = readline.createInterface({
        input: fileStream,
        crlfDelay: Infinity
    });

    const emailRegex = /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g;

    let batch = [];
    let totalFound = 0;
    const BATCH_SIZE = 1000;

    for await (const line of rl) {
        const emails = line.match(emailRegex);

        if (emails) {
            emails.forEach(email => {
                batch.push({ type: 'email', value: email.toLowerCase() });
            });
        }

        if (batch.length >= BATCH_SIZE) {
            await flushSqlBatch(batch);
            totalFound += batch.length;
            process.stdout.write(`\r[+] Processed & queued identifiers: ${totalFound}`);
            batch = [];
        }
    }

    if (batch.length > 0) {
        await flushSqlBatch(batch);
        totalFound += batch.length;
    }

    console.log(`\n[✔] SQL dump import complete. Total records indexed: ${totalFound}`);
    await pool.end();
}

async function flushSqlBatch(records) {
    const client = await pool.connect();
    try {
        await client.query('BEGIN');
        const queryText = `
            INSERT INTO universal_breaches (
                identifier_type,
                email,
                leaked_data_snippet,
                source_leak,
                breach_date
            )
            VALUES ($1, $2, $3, $4, CURRENT_DATE)
        `;

        for (const rec of records) {
            await client.query(queryText, [
                'email',
                rec.value,
                'Extracted via SQL dump stream parser',
                'Archive: SQL Dump'
            ]);
        }
        await client.query('COMMIT');
    } catch (err) {
        await client.query('ROLLBACK');
        console.error('[!] SQL batch error:', err.message);
    } finally {
        client.release();
    }
}

if (process.argv[2]) {
    importSqlDump(process.argv[2]);
}

module.exports = { importSqlDump };
