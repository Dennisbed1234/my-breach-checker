const axios = require('axios');
const readline = require('readline');
const { Pool } = require('pg');

const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: { rejectUnauthorized: false }
});

const EXPANDED_FEED_URLS = [
    {
        name: 'SecLists Usernames & Aliases',
        url: 'https://raw.githubusercontent.com/danielmiessler/SecLists/master/Usernames/Names/names.txt',
        type: 'username'
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

            await processFeedStream(response.data, feed.name, feed.type);
        } catch (error) {
            console.error(`[!] Failed to pull from [${feed.name}]: ${error.message}`);
        }
    }

    console.log('\n==================================================');
    console.log('[✔] All threat intelligence feeds synchronized successfully.');
    await pool.end();
}

async function processFeedStream(inputStream, sourceLabel, defaultType) {
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

        let identifierType = null;
        let identifierValue = null;

        if (emailRegex.test(cleanLine)) {
            identifierType = 'email';
            identifierValue = cleanLine.toLowerCase();
        } else if (defaultType === 'username' && cleanLine.length > 2) {
            identifierType = 'username';
            identifierValue = cleanLine.toLowerCase();
        }

        if (identifierType && identifierValue) {
            batch.push({
                type: identifierType,
                value: identifierValue,
                snippet: 'Indexed from active threat feed'
            });
        }

        if (batch.length >= BATCH_SIZE) {
            await insertBatchToDatabase(batch, sourceLabel);
            totalInserted += batch.length;
            batch = [];
            process.stdout.write(`\r[+] Processed lines: ${totalProcessed} | Indexed records: ${totalInserted}`);
        }
    }

    if (batch.length > 0) {
        await insertBatchToDatabase(batch, sourceLabel);
        totalInserted += batch.length;
    }

    console.log(`\n[✔] Finished [${sourceLabel}] -> Scanned: ${totalProcessed}, Saved: ${totalInserted}`);
}

async function insertBatchToDatabase(records, sourceLabel) {
    const client = await pool.connect();
    try {
        await client.query('BEGIN');

        const queryText = `
            INSERT INTO universal_breaches (
                identifier_type,
                email,
                username,
                leaked_data_snippet,
                source_leak,
                breach_date
            )
            VALUES ($1, $2, $3, $4, $5, CURRENT_DATE)
        `;

        for (const rec of records) {
            const email = rec.type === 'email' ? rec.value : null;
            const username = rec.type === 'username' ? rec.value : null;

            await client.query(queryText, [
                rec.type,
                email,
                username,
                rec.snippet || 'Indexed from feed',
                `Feed: ${sourceLabel}`
            ]);
        }

        await client.query('COMMIT');
    } catch (err) {
        await client.query('ROLLBACK');
        console.error('[!] Database batch error:', err.message);
    } finally {
        client.release();
    }
}

runAggregatedIngestion();
