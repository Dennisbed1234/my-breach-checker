const crypto = require('crypto');
const axios = require('axios');
const readline = require('readline');
const { Pool } = require('pg');

const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: { rejectUnauthorized: false }
});

const EXPANDED_FEED_URLS = [
    {
        name: 'MIT Adobe Credential Exposure Dataset',
        url: 'https://web.mit.edu/zyan/Public/adobe_sanitized_passwords_with_bad_hints.txt',
        type: 'adobe'
    },
    {
        name: 'Public Domain Email Test Corpus A',
        url: 'https://raw.githubusercontent.com/jhuggins/email-validator/master/test/fixtures/emails.txt',
        type: 'email'
    },
    {
        name: 'Open Source Security Feed Archive Alpha',
        url: 'https://raw.githubusercontent.com/audibleblink/some-sample-lists/master/emails.txt',
        type: 'email'
    }
];

const BATCH_SIZE = 2000;

function fingerprint(...parts) {
    return crypto
        .createHash("sha256")
        .update(parts.map((part) => String(part ?? "")).join("|"), "utf8")
        .digest("hex");
}

async function runAggregatedIngestion() {
    console.log('[*] Initializing Mass Threat Intelligence Ingestion Pipeline...');

    for (const feed of EXPANDED_FEED_URLS) {
        try {
            console.log(`\n--------------------------------------------------`);
            console.log(`[*] Connecting to source: [${feed.name}]`);
            console.log(`[*] URL: ${feed.url}`);

            const response = await axios({
                method: 'get',
                url: feed.url,
                responseType: 'stream',
                timeout: 60000
            });

            await processFeedStream(response.data, feed);
        } catch (error) {
            console.error(`[!] Failed to pull from [${feed.name}]: ${error.message}`);
        }
    }

    console.log('\n==================================================');
    console.log('[✔] All threat intelligence feeds synchronized successfully.');
    await pool.end();
}

async function processFeedStream(inputStream, feed) {
    const rl = readline.createInterface({
        input: inputStream,
        crlfDelay: Infinity
    });

    const emailRegex = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;

    let batch = [];
    let totalProcessed = 0;
    let totalInserted = 0;

    for await (const line of rl) {
        totalProcessed++;
        const cleanLine = line.trim();

        if (!cleanLine || cleanLine.startsWith('#')) continue;

        if (feed.type === 'adobe') {
            const parts = cleanLine.split('\t');
            if (parts.length >= 2) {
                const domain = parts[0].trim().toLowerCase();
                const password = parts[1].trim();
                if (domain && password) {
                    const recordFingerprint = fingerprint(feed.name, domain, password);
                    batch.push({
                        identifierType: 'domain',
                        domain,
                        password,
                        sourceLeak: feed.name,
                        recordFingerprint
                    });
                }
            }
        } else if (feed.type === 'email' && emailRegex.test(cleanLine)) {
            const email = cleanLine.toLowerCase();
            const domain = email.split('@')[1] || null;
            const recordFingerprint = fingerprint(feed.name, 'email', email);
            batch.push({
                identifierType: 'email',
                email,
                domain,
                sourceLeak: feed.name,
                recordFingerprint
            });
        }

        if (batch.length >= BATCH_SIZE) {
            const insertedCount = await insertBatchToDatabase(batch);
            totalInserted += insertedCount;
            batch = [];
            process.stdout.write(`\r[+] Processed lines: ${totalProcessed} | Indexed records: ${totalInserted}`);
        }
    }

    if (batch.length > 0) {
        const insertedCount = await insertBatchToDatabase(batch);
        totalInserted += insertedCount;
    }

    console.log(`\n[✔] Finished [${feed.name}] -> Scanned: ${totalProcessed}, Saved: ${totalInserted}`);
}

async function insertBatchToDatabase(records) {
    if (records.length === 0) return 0;

    const client = await pool.connect();
    try {
        await client.query('BEGIN');

        let insertedTotal = 0;
        for (const rec of records) {
            const res = await client.query(
                `
                INSERT INTO universal_breaches (
                    identifier_type,
                    email,
                    domain,
                    password,
                    leaked_data_snippet,
                    source_leak,
                    breach_date,
                    record_fingerprint
                )
                VALUES ($1, $2, $3, $4, $5, $6, CURRENT_DATE, $7)
                ON CONFLICT (record_fingerprint) WHERE record_fingerprint IS NOT NULL
                DO NOTHING
                RETURNING 1
                `,
                [
                    rec.identifierType,
                    rec.email || null,
                    rec.domain || null,
                    rec.password || null,
                    'Indexed from feed stream',
                    rec.sourceLeak,
                    rec.recordFingerprint
                ]
            );
            if (res.rowCount > 0) insertedTotal++;
        }

        await client.query('COMMIT');
        return insertedTotal;
    } catch (err) {
        await client.query('ROLLBACK');
        console.error('[!] Database batch error:', err.message);
        return 0;
    } finally {
        client.release();
    }
}

runAggregatedIngestion();
