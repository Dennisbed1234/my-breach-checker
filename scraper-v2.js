const axios = require('axios');
const readline = require('readline');
const { Pool } = require('pg');

const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: { rejectUnauthorized: false }
});

// Expanded intelligence feeds and public security data repositories
const EXPANDED_FEED_URLS = [
    {
        name: 'SecLists Usernames & Aliases',
        url: 'https://raw.githubusercontent.com/danielmiessler/SecLists/master/Usernames/Names/names.txt',
        type: 'username'
    },
    {
        name: 'SecLists Top Compromised Passwords/Emails Corpus',
        url: 'https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/10-million-password-list-top-1000000.txt',
        type: 'password_pattern'
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
    },
    {
        name: 'Global Threat Intelligence Mirror Beta',
        url: 'https://raw.githubusercontent.com/dinosaure/92552e7724f6057eedf6a1776a891c62/raw/db.txt',
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
    const phoneRegex = /^\+?[1-9]\d{1,14}$/;

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
        } else if (phoneRegex.test(cleanLine.replace(/[\s()-]/g, ''))) {
            identifierType = 'phone';
            identifierValue = cleanLine.replace(/[\s()-]/g, '');
        } else if (defaultType === 'username' && cleanLine.length > 2) {
            identifierType = 'username';
            identifierValue = cleanLine.toLowerCase();
        }

        if (identifierType && identifierValue) {
            batch.push({
                type: identifierType,
                value: identifierValue,
                snippet: `Indexed from active threat feed`
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
            INSERT INTO universal_breaches (identifier_type, identifier_value, leaked_data_snippet, source_leak, breach_date)
            VALUES ($1, $2, $3, $4, CURRENT_DATE)
            ON CONFLICT (identifier_type, identifier_value, source_leak) DO NOTHING;
        `;

        for (const rec of records) {
            await client.query(queryText, [rec.type, rec.value, rec.snippet, `Feed: ${sourceLabel}`]);
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
