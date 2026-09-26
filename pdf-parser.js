const fs = require('fs');
const pdfParse = require('pdf-parse');
const { Pool } = require('pg');

const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: { rejectUnauthorized: false }
});

async function extractPdfArchive(filePath) {
    console.log(`[*] Reading and extracting text from PDF: ${filePath}`);
    
    try {
        const dataBuffer = fs.readFileSync(filePath);
        const pdfData = await pdfParse(dataBuffer);
        
        const textContent = pdfData.text;
        console.log(`[✔] PDF successfully parsed. Total pages: ${pdfData.numpages}. Extracting identifiers...`);

        const emailRegex = /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g;
        const emails = textContent.match(emailRegex) || [];
        
        // Deduplicate extracted records
        const uniqueEmails = [...new Set(emails)].map(e => e.toLowerCase());
        console.log(`[+] Found ${uniqueEmails.length} unique identifiers in PDF document.`);

        const client = await pool.connect();
        try {
            await client.query('BEGIN');
            const queryText = `
                INSERT INTO universal_breaches (identifier_type, identifier_value, leaked_data_snippet, source_leak, breach_date)
                VALUES ($1, $2, $3, $4, CURRENT_DATE)
                ON CONFLICT (identifier_type, identifier_value, source_leak) DO NOTHING;
            `;

            for (const email of uniqueEmails) {
                await client.query(queryText, ['email', email, 'Extracted from document archive', 'Archive: PDF Report']);
            }
            await client.query('COMMIT');
            console.log('[✔] PDF records successfully committed to Neon database.');
        } catch (err) {
            await client.query('ROLLBACK');
            console.error('[!] Database transaction error:', err.message);
        } finally {
            client.release();
        }

    } catch (err) {
        console.error('[!] Failed to parse PDF:', err.message);
    } finally {
        await pool.end();
    }
}

// Execute if run directly
if (process.argv[2]) {
    extractPdfArchive(process.argv[2]);
}

module.exports = { extractPdfArchive };
