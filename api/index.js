const crypto = require("crypto");
const axios = require("axios");
const express = require("express");
const { Pool } = require("pg");

const app = express();

app.use(express.json({ limit: "1mb" }));
app.use(express.urlencoded({ extended: true }));

// ============================================================
// DATABASE
// ============================================================

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: {
    rejectUnauthorized: false,
  },
});

// ============================================================
// ADMIN AUTH
// ============================================================

const ADMIN_SECRET = process.env.ADMIN_SECRET;

// ============================================================
// FEEDS
// ============================================================

const FEEDS = [
  {
    name: "MIT Adobe Credential Exposure Dataset",
    url: "https://web.mit.edu/zyan/Public/adobe_sanitized_passwords_with_bad_hints.txt",
    type: "adobe",
    enabled: true,
  },
];

// ============================================================
// DATABASE INITIALIZATION & SCHEMA FIXES
// ============================================================

async function ensureSchema() {
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

  await pool.query(`
    ALTER TABLE universal_breaches
      ADD COLUMN IF NOT EXISTS domain TEXT,
      ADD COLUMN IF NOT EXISTS exposure_type TEXT,
      ADD COLUMN IF NOT EXISTS record_fingerprint TEXT;
  `);

  await pool.query(`
    DROP INDEX IF EXISTS universal_breaches_record_fingerprint_uidx;
  `);

  await pool.query(`
    CREATE UNIQUE INDEX universal_breaches_record_fingerprint_uidx
    ON universal_breaches (record_fingerprint)
    WHERE record_fingerprint IS NOT NULL;
  `);

  await pool.query(`
    CREATE INDEX IF NOT EXISTS universal_breaches_email_idx
    ON universal_breaches (LOWER(email));
  `);

  await pool.query(`
    CREATE INDEX IF NOT EXISTS universal_breaches_username_idx
    ON universal_breaches (LOWER(username));
  `);

  await pool.query(`
    CREATE INDEX IF NOT EXISTS universal_breaches_domain_idx
    ON universal_breaches (LOWER(domain));
  `);
}

const schemaReady = ensureSchema().catch((error) => {
  console.error("Database schema initialization failed:", error);
  throw error;
});

app.use(async (req, res, next) => {
  try {
    await schemaReady;
    next();
  } catch (error) {
    next(error);
  }
});

// ============================================================
// HELPERS (Case-preserving fingerprint & strict normalization)
// ============================================================

function normalizeIdentifier(value) {
  return String(value ?? "").trim().toLowerCase();
}

function fingerprint(...parts) {
  return crypto
    .createHash("sha256")
    .update(
      parts.map((part) => String(part ?? "")).join("|"),
      "utf8"
    )
    .digest("hex");
}

function requireAdmin(req, res, next) {
  const token = req.headers["x-admin-token"];

  if (!ADMIN_SECRET) {
    return res.status(500).json({
      error: "ADMIN_SECRET is not configured.",
    });
  }

  if (!token || token !== ADMIN_SECRET) {
    return res.status(401).json({
      error: "Unauthorized",
    });
  }

  next();
}

// ============================================================
// FEED FETCHER
// ============================================================

async function fetchFeed(feed) {
  const response = await axios.get(feed.url, {
    timeout: 30_000,
    responseType: "text",
    maxContentLength: 25 * 1024 * 1024,
    maxBodyLength: 25 * 1024 * 1024,
    headers: {
      "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
      Accept: "text/plain,text/*,*/*",
    },
    validateStatus: (status) => status >= 200 && status < 300,
  });

  return String(response.data ?? "");
}

// ============================================================
// PARSERS
// ============================================================

function parseAdobeFeed(text, feed) {
  const lines = text.split(/\r?\n/);
  const records = [];
  let totalLines = 0;
  let skippedLines = 0;

  for (const rawLine of lines) {
    totalLines++;
    const line = rawLine.trim();
    if (!line) continue;

    const parts = line.split("\t");
    if (parts.length < 2) {
      skippedLines++;
      continue;
    }

    const domain = normalizeIdentifier(parts[0]);
    const credentialMaterial = String(parts[1] ?? "").trim();

    if (!domain || !credentialMaterial) {
      skippedLines++;
      continue;
    }

    const recordFingerprint = fingerprint(
      feed.name,
      domain,
      credentialMaterial
    );

    records.push({
      identifierType: "domain",
      domain,
      password: credentialMaterial,
      exposureType: "credential-related",
      sourceLeak: feed.name,
      breachDate: null,
      recordFingerprint,
    });
  }

  return { records, totalLines, skippedLines };
}

function parseGenericFeed(text, feed) {
  const lines = text.split(/\r?\n/);
  const records = [];
  let totalLines = 0;
  let skippedLines = 0;

  for (const rawLine of lines) {
    totalLines++;
    const value = normalizeIdentifier(rawLine);
    if (!value) continue;

    if (value.includes("@")) {
      const recordFingerprint = fingerprint(feed.name, "email", value);

      records.push({
        identifierType: "email",
        email: value,
        domain: value.split("@")[1] || null,
        exposureType: "identifier-exposure",
        sourceLeak: feed.name,
        breachDate: null,
        recordFingerprint,
      });
      continue;
    }
    skippedLines++;
  }

  return { records, totalLines, skippedLines };
}

function parseFeed(text, feed) {
  switch (feed.type) {
    case "adobe":
      return parseAdobeFeed(text, feed);
    case "generic":
      return parseGenericFeed(text, feed);
    default:
      throw new Error(`Unsupported feed type: ${feed.type}`);
  }
}

// ============================================================
// HIGH-PERFORMANCE BATCH INSERTION (Fixed ON CONFLICT matching partial index)
// ============================================================

async function insertRecords(records) {
  if (records.length === 0) return { inserted: 0, duplicates: 0 };

  const client = await pool.connect();
  try {
    await client.query("BEGIN");

    const identifierTypes = records.map(r => r.identifierType || null);
    const firstNames = records.map(r => r.firstName || null);
    const lastNames = records.map(r => r.lastName || null);
    const usernames = records.map(r => r.username || null);
    const emails = records.map(r => r.email || null);
    const passwords = records.map(r => r.password || null);
    const snippets = records.map(() => "Credential-related exposure detected.");
    const sources = records.map(r => r.sourceLeak || null);
    const breachDates = records.map(r => r.breachDate || null);
    const domains = records.map(r => r.domain || null);
    const exposureTypes = records.map(r => r.exposureType || null);
    const fingerprints = records.map(r => r.recordFingerprint || null);

    const query = `
      WITH input_data AS (
        SELECT * FROM UNNEST(
          $1::text[], $2::text[], $3::text[], $4::text[], $5::text[], 
          $6::text[], $7::text[], $8::text[], $9::date[], $10::text[], 
          $11::text[], $12::text[]
        ) AS t(
          identifier_type, first_name, last_name, username, email, 
          password, leaked_data_snippet, source_leak, breach_date, 
          domain, exposure_type, record_fingerprint
        )
      ),
      inserted AS (
        INSERT INTO universal_breaches (
          identifier_type, first_name, last_name, username, email,
          password, leaked_data_snippet, source_leak, breach_date,
          domain, exposure_type, record_fingerprint
        )
        SELECT * FROM input_data
        ON CONFLICT (record_fingerprint) WHERE record_fingerprint IS NOT NULL
        DO NOTHING
        RETURNING 1
      )
      SELECT 
        (SELECT COUNT(*) FROM input_data) AS total_input,
        (SELECT COUNT(*) FROM inserted) AS inserted_count;
    `;

    const res = await client.query(query, [
      identifierTypes,
      firstNames,
      lastNames,
      usernames,
      emails,
      passwords,
      snippets,
      sources,
      breachDates,
      domains,
      exposureTypes,
      fingerprints,
    ]);

    await client.query("COMMIT");

    const totalInput = Number(res.rows[0]?.total_input || 0);
    const insertedCount = Number(res.rows[0]?.inserted_count || 0);
    const duplicateCount = totalInput - insertedCount;

    return {
      inserted: insertedCount,
      duplicates: duplicateCount,
    };
  } catch (error) {
    await client.query("ROLLBACK");
    throw error;
  } finally {
    client.release();
  }
}

// ============================================================
// AUTOMATED OSINT SEARCH DISCOVERY WORKER (Google Custom Search Integration)
// ============================================================

async function discoverAndIngestFromSearch() {
  const apiKey = process.env.GOOGLE_SEARCH_API_KEY;
  const searchEngineId = process.env.GOOGLE_CSE_ID;

  if (!apiKey || !searchEngineId) {
    throw new Error("Google Custom Search API credentials (GOOGLE_SEARCH_API_KEY and GOOGLE_CSE_ID) are not configured.");
  }

  const searchQueries = [
    'filetype:txt "password" "email"',
    'ext:txt intext:"@gmail.com" intext:"password"',
    'intitle:"index of" "credentials.txt"',
  ];

  let totalDiscovered = 0;
  let queriesRun = 0;

  for (const query of searchQueries) {
    queriesRun++;
    try {
      const searchUrl = `https://www.googleapis.com/customsearch/v1?key=${apiKey}&cx=${searchEngineId}&q=${encodeURIComponent(query)}`;
      const response = await axios.get(searchUrl, { timeout: 15_000 });
      const items = response.data.items || [];

      for (const item of items) {
        const fileUrl = item.link;
        try {
          const fileContent = await axios.get(fileUrl, {
            timeout: 10_000,
            responseType: "text",
            maxContentLength: 10 * 1024 * 1024,
          });

          const textData = String(fileContent.data || "");
          const feedMeta = { name: `OSINT Discovery: ${item.title || fileUrl}`, type: textData.includes("\t") ? "adobe" : "generic" };
          
          const parsed = parseFeed(textData, feedMeta);
          const insertResult = await insertRecords(parsed.records);
          totalDiscovered += insertResult.inserted;
        } catch (fetchErr) {
          console.error(`Failed to fetch/parse target URL [${fileUrl}]:`, fetchErr.message);
        }
      }
    } catch (err) {
      console.error(`Discovery execution error for query [${query}]:`, err.message);
    }
  }

  return {
    success: true,
    queriesRun,
    newRecordsAdded: totalDiscovered,
  };
}

// ============================================================
// HEALTH & API INFO
// ============================================================

app.get("/api/health", async (req, res) => {
  try {
    await pool.query("SELECT 1");
    res.json({
      ok: true,
      database: "connected",
      feedsConfigured: FEEDS.filter((feed) => feed.enabled !== false).length,
    });
  } catch (error) {
    res.status(500).json({ ok: false, database: "error", error: error.message });
  }
});

app.get("/api", (req, res) => {
  res.json({
    name: "BreachIntel API",
    endpoints: {
      health: "GET /api/health",
      secureCheck: "POST /api/secure-check",
      stats: "GET /api/admin/stats",
      syncFeeds: "POST /api/admin/sync-feeds",
      discoverFeeds: "POST /api/admin/discover-feeds",
    },
  });
});

// ============================================================
// SECURE CHECK (Admin-Protected)
// ============================================================

app.post("/api/secure-check", requireAdmin, async (req, res) => {
  try {
    const { email, username, first_name, last_name, domain } = req.body || {};
    const fields = { email, username, first_name, last_name, domain };
    const provided = Object.entries(fields).filter(
      ([, value]) => value !== undefined && value !== null && String(value).trim() !== ""
    );

    if (provided.length !== 1) {
      return res.status(400).json({
        error: "Provide exactly one supported identifier.",
      });
    }

    const [field, rawValue] = provided[0];
    const columnMap = {
      email: "email",
      username: "username",
      first_name: "first_name",
      last_name: "last_name",
      domain: "domain",
    };

    const column = columnMap[field];
    const value = normalizeIdentifier(rawValue);

    const result = await pool.query(
      `
      SELECT
        identifier_type,
        first_name,
        last_name,
        username,
        email,
        password,
        domain,
        source_leak,
        breach_date,
        exposure_type,
        leaked_data_snippet,
        created_at
      FROM universal_breaches
      WHERE LOWER(${column}) = $1
      ORDER BY created_at DESC
      LIMIT 100
      `,
      [value]
    );

    res.json({
      pwned: result.rows.length > 0,
      count: result.rows.length,
      matches: result.rows.map((row) => ({
        type: row.identifier_type,
        firstName: row.first_name,
        lastName: row.last_name,
        username: row.username,
        email: row.email,
        password: row.password,
        domain: row.domain,
        source: row.source_leak,
        date: row.breach_date,
        exposureType: row.exposure_type,
        snippet: row.leaked_data_snippet,
        detectedAt: row.created_at,
      })),
    });
  } catch (error) {
    console.error("Secure check error:", error);
    res.status(500).json({ error: "Secure check failed." });
  }
});

// ============================================================
// ADMIN STATS
// ============================================================

app.get("/api/admin/stats", requireAdmin, async (req, res) => {
  try {
    const totalResult = await pool.query(`SELECT COUNT(*)::int AS total FROM universal_breaches`);
    const typeResult = await pool.query(`SELECT identifier_type, COUNT(*)::int AS count FROM universal_breaches GROUP BY identifier_type ORDER BY count DESC`);
    const sourceResult = await pool.query(`SELECT source_leak, COUNT(*)::int AS count FROM universal_breaches GROUP BY source_leak ORDER BY count DESC LIMIT 25`);
    const domainResult = await pool.query(`SELECT domain, COUNT(*)::int AS count FROM universal_breaches WHERE domain IS NOT NULL GROUP BY domain ORDER BY count DESC LIMIT 25`);

    const recentResult = await pool.query(`
      SELECT
        id,
        identifier_type,
        username,
        email,
        password,
        domain,
        source_leak,
        breach_date,
        exposure_type,
        created_at
      FROM universal_breaches
      ORDER BY created_at DESC
      LIMIT 50
    `);

    const totalCount = Number(totalResult.rows[0]?.total || 0);

    res.json({
      total: totalCount,
      totalRecords: totalCount,
      breakdown: typeResult.rows || [],
      sources: sourceResult.rows || [],
      topDomains: domainResult.rows || [],
      recent: (recentResult.rows || []).map(row => ({
        ...row,
        password: row.password || ""
      })),
    });
  } catch (error) {
    console.error("Admin stats error:", error);
    res.status(500).json({ error: "Failed to load admin statistics." });
  }
});

// ============================================================
// ADMIN FEED SYNC (Now triggers static feeds AND Google Search discovery together)
// ============================================================

app.post("/api/admin/sync-feeds", requireAdmin, async (req, res) => {
  const startedAt = Date.now();
  const enabledFeeds = FEEDS.filter((feed) => feed.enabled !== false);
  const results = [];

  let totalInserted = 0;
  let totalDuplicates = 0;
  let totalProcessed = 0;

  // 1. Process static feeds
  for (const feed of enabledFeeds) {
    const feedStartedAt = Date.now();
    try {
      const text = await fetchFeed(feed);
      const parsed = parseFeed(text, feed);
      const insertedResult = await insertRecords(parsed.records);

      totalProcessed += parsed.records.length;
      totalInserted += insertedResult.inserted;
      totalDuplicates += insertedResult.duplicates;

      results.push({
        name: feed.name,
        url: feed.url,
        type: feed.type,
        status: "success",
        inserted: insertedResult.inserted,
        duplicates: insertedResult.duplicates,
        durationMs: Date.now() - feedStartedAt,
      });
    } catch (error) {
      console.error(`Feed sync error for ${feed.name}:`, error.message);
      results.push({
        name: feed.name,
        url: feed.url,
        type: feed.type,
        status: "error",
        error: error.message,
        durationMs: Date.now() - feedStartedAt,
      });
    }
  }

  // 2. Trigger Google Custom Search OSINT Discovery automatically during sync
  let discoveryDetails = null;
  try {
    discoveryDetails = await discoverAndIngestFromSearch();
    totalInserted += discoveryDetails.newRecordsAdded;
  } catch (discoveryError) {
    console.error("Discovery execution warning during sync:", discoveryError.message);
    results.push({
      name: "Google Custom Search OSINT Worker",
      status: "error",
      error: discoveryError.message,
    });
  }

  const failed = results.filter((result) => result.status === "error");

  res.status(failed.length > 0 && totalInserted === 0 ? 207 : 200).json({
    success: failed.length === 0 || totalInserted > 0,
    message: "Feed synchronization and OSINT search discovery cycle completed.",
    durationMs: Date.now() - startedAt,
    totalProcessed,
    totalInserted,
    totalDuplicates,
    discoveryDetails,
    results,
  });
});

// ============================================================
// ADMIN AUTOMATED DISCOVERY ENDPOINT
// ============================================================

app.post(
  "/api/admin/discover-feeds",
  requireAdmin,
  async (req, res) => {
    try {
      const result = await discoverAndIngestFromSearch();
      return res.json({
        success: true,
        message: "Automated OSINT discovery cycle completed successfully.",
        details: result,
      });
    } catch (error) {
      console.error("Discovery trigger error:", error);
      return res.status(500).json({
        error: "Automated discovery failed.",
        detail: error.message,
      });
    }
  }
);

app.use((req, res) => {
  res.status(404).json({ error: "Not found", path: req.path });
});

app.use((error, req, res, next) => {
  console.error("Unhandled API error:", error);

  res.status(500).json({
    error: "Internal server error.",
  });
});

module.exports = app;

