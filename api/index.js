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
// DATABASE INITIALIZATION & CONSTRAINT FIX
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

  // Explicitly ensure unique index exists so ON CONFLICT works without errors
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
// HELPERS
// ============================================================

function normalize(value) {
  return String(value ?? "")
    .trim()
    .toLowerCase();
}

function fingerprint(...parts) {
  return crypto
    .createHash("sha256")
    .update(parts.map((part) => normalize(part)).join("|"))
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

    const domain = normalize(parts[0]);
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
    const value = normalize(rawLine);
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
// INSERT FEED RECORDS
// ============================================================

async function insertRecords(records) {
  const client = await pool.connect();
  let inserted = 0;
  let duplicates = 0;

  try {
    await client.query("BEGIN");

    for (const record of records) {
      const result = await client.query(
        `
        INSERT INTO universal_breaches (
          identifier_type,
          first_name,
          last_name,
          username,
          email,
          password,
          leaked_data_snippet,
          source_leak,
          breach_date,
          domain,
          exposure_type,
          record_fingerprint
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
        ON CONFLICT (record_fingerprint)
        DO NOTHING
        RETURNING id
        `,
        [
          record.identifierType || null,
          record.firstName || null,
          record.lastName || null,
          record.username || null,
          record.email || null,
          record.password || null,
          "Credential-related exposure detected.",
          record.sourceLeak || null,
          record.breachDate || null,
          record.domain || null,
          record.exposureType || null,
          record.recordFingerprint || null,
        ]
      );

      if (result.rowCount > 0) {
        inserted++;
      } else {
        duplicates++;
      }
    }

    await client.query("COMMIT");
    return { inserted, duplicates };
  } catch (error) {
    await client.query("ROLLBACK");
    throw error;
  } finally {
    client.release();
  }
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
    },
  });
});

// ============================================================
// SECURE CHECK
// ============================================================

app.post("/api/secure-check", async (req, res) => {
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
    const value = normalize(rawValue);

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

    res.json({
      total: Number(totalResult.rows[0]?.total || 0),
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
// ADMIN FEED SYNC
// ============================================================

app.post("/api/admin/sync-feeds", requireAdmin, async (req, res) => {
  const startedAt = Date.now();
  const enabledFeeds = FEEDS.filter((feed) => feed.enabled !== false);
  const results = [];

  let totalInserted = 0;
  let totalDuplicates = 0;
  let totalProcessed = 0;

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

  const failed = results.filter((result) => result.status === "error");

  res.status(failed.length > 0 ? 207 : 200).json({
    success: failed.length === 0,
    message: failed.length === 0 ? "Feed synchronization completed." : `Feed synchronization completed with errors: ${failed.map(f => f.error).join(' | ')}`,
    durationMs: Date.now() - startedAt,
    totalInserted,
    totalDuplicates,
    results,
  });
});

app.use((req, res) => {
  res.status(404).json({ error: "Not found", path: req.path });
});

app.use((error, req, res, next) => {
  console.error("Unhandled API error:", error);
  res.status(500).json({ error: "Internal server error." });
});

module.exports = app;
