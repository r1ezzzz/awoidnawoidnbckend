/**
 * Database module using sql.js (pure JS SQLite - no native compilation needed)
 * Stores proxy keys, their permissions, and time-based access rules
 */
const initSqlJs = require('sql.js');
const path = require('path');
const fs = require('fs');

const DATA_DIR = path.join(__dirname, '..', 'data');
const DB_PATH = path.join(DATA_DIR, 'keys.db');

let db = null;
let dbReady = null;

function ensureDataDir() {
  if (!fs.existsSync(DATA_DIR)) {
    fs.mkdirSync(DATA_DIR, { recursive: true });
  }
}

/**
 * Initialize the database (async, but we cache the promise)
 */
function initDb() {
  if (dbReady) return dbReady;

  dbReady = (async () => {
    ensureDataDir();
    const SQL = await initSqlJs();

    // Load existing database or create new one
    if (fs.existsSync(DB_PATH)) {
      const fileBuffer = fs.readFileSync(DB_PATH);
      db = new SQL.Database(fileBuffer);
    } else {
      db = new SQL.Database();
    }

    initializeSchema();
    return db;
  })();

  return dbReady;
}

/**
 * Get the database synchronously (must call initDb() first)
 */
function getDbSync() {
  if (!db) {
    // Synchronous fallback - initialize inline
    ensureDataDir();
    const SQL = require('sql.js');
    // sql.js can also be loaded synchronously in some environments
    // but we'll rely on the async init having been called
    throw new Error('Database not initialized. Call await initDb() first.');
  }
  return db;
}

function saveToFile() {
  if (db) {
    const data = db.export();
    const buffer = Buffer.from(data);
    ensureDataDir();
    fs.writeFileSync(DB_PATH, buffer);
  }
}

function initializeSchema() {
  db.run(`
    CREATE TABLE IF NOT EXISTS proxy_keys (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      key_hash TEXT NOT NULL UNIQUE,
      key_prefix TEXT NOT NULL,
      target_provider TEXT NOT NULL DEFAULT 'anthropic',
      created_at TEXT NOT NULL DEFAULT (datetime('now')),
      expires_at TEXT,
      is_revoked INTEGER NOT NULL DEFAULT 0,
      max_requests_per_minute INTEGER DEFAULT 60,
      max_requests_per_day INTEGER DEFAULT 1000,
      total_requests INTEGER NOT NULL DEFAULT 0,
      last_used_at TEXT,
      notes TEXT
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS request_log (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      key_id INTEGER NOT NULL,
      timestamp TEXT NOT NULL DEFAULT (datetime('now')),
      method TEXT,
      path TEXT,
      status_code INTEGER,
      response_time_ms INTEGER,
      FOREIGN KEY (key_id) REFERENCES proxy_keys(id)
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS encrypted_providers (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      provider_name TEXT NOT NULL UNIQUE,
      encrypted_api_key TEXT NOT NULL,
      base_url TEXT NOT NULL,
      created_at TEXT NOT NULL DEFAULT (datetime('now')),
      updated_at TEXT NOT NULL DEFAULT (datetime('now'))
    )
  `);

  // Create indexes (ignore if they already exist)
  try { db.run('CREATE INDEX IF NOT EXISTS idx_proxy_keys_hash ON proxy_keys(key_hash)'); } catch (e) {}
  try { db.run('CREATE INDEX IF NOT EXISTS idx_request_log_key_timestamp ON request_log(key_id, timestamp)'); } catch (e) {}

  saveToFile();
}

// ─── Helper to run queries ──────────────────────────────────────────

function queryOne(sql, params = []) {
  const stmt = db.prepare(sql);
  stmt.bind(params);
  let result = null;
  if (stmt.step()) {
    const columns = stmt.getColumnNames();
    const values = stmt.get();
    result = {};
    columns.forEach((col, i) => {
      result[col] = values[i];
    });
  }
  stmt.free();
  return result;
}

function queryAll(sql, params = []) {
  const stmt = db.prepare(sql);
  stmt.bind(params);
  const results = [];
  const columns = stmt.getColumnNames();
  while (stmt.step()) {
    const values = stmt.get();
    const row = {};
    columns.forEach((col, i) => {
      row[col] = values[i];
    });
    results.push(row);
  }
  stmt.free();
  return results;
}

function runSql(sql, params = []) {
  db.run(sql, params);
  saveToFile();
  return { changes: db.getRowsModified(), lastInsertRowid: getLastInsertId() };
}

function getLastInsertId() {
  const result = queryOne('SELECT last_insert_rowid() as id');
  return result ? result.id : null;
}

// ─── Proxy Key Operations ───────────────────────────────────────────

function createProxyKey({ name, keyHash, keyPrefix, targetProvider, expiresAt, maxRpm, maxRpd, notes }) {
  runSql(
    `INSERT INTO proxy_keys (name, key_hash, key_prefix, target_provider, expires_at, max_requests_per_minute, max_requests_per_day, notes)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
    [name, keyHash, keyPrefix, targetProvider || 'anthropic', expiresAt || null, maxRpm || 60, maxRpd || 1000, notes || null]
  );
  return getLastInsertId();
}

function findKeyByHash(keyHash) {
  return queryOne('SELECT * FROM proxy_keys WHERE key_hash = ?', [keyHash]);
}

function listKeys() {
  return queryAll(
    'SELECT id, name, key_prefix, target_provider, created_at, expires_at, is_revoked, max_requests_per_minute, max_requests_per_day, total_requests, last_used_at, notes FROM proxy_keys ORDER BY created_at DESC'
  );
}

function revokeKey(id) {
  return runSql('UPDATE proxy_keys SET is_revoked = 1 WHERE id = ?', [id]);
}

function updateKeyUsage(id) {
  return runSql("UPDATE proxy_keys SET total_requests = total_requests + 1, last_used_at = datetime('now') WHERE id = ?", [id]);
}

// ─── Rate Limiting ──────────────────────────────────────────────────

function getRequestCountLastMinute(keyId) {
  const row = queryOne(
    "SELECT COUNT(*) as count FROM request_log WHERE key_id = ? AND timestamp > datetime('now', '-1 minute')",
    [keyId]
  );
  return row ? row.count : 0;
}

function getRequestCountToday(keyId) {
  const row = queryOne(
    "SELECT COUNT(*) as count FROM request_log WHERE key_id = ? AND timestamp > datetime('now', 'start of day')",
    [keyId]
  );
  return row ? row.count : 0;
}

function logRequest({ keyId, method, reqPath, statusCode, responseTimeMs }) {
  runSql(
    'INSERT INTO request_log (key_id, method, path, status_code, response_time_ms) VALUES (?, ?, ?, ?, ?)',
    [keyId, method, reqPath, statusCode || null, responseTimeMs || null]
  );
}

// ─── Provider Operations ────────────────────────────────────────────

function saveProvider({ providerName, encryptedApiKey, baseUrl }) {
  // Check if provider exists
  const existing = queryOne('SELECT id FROM encrypted_providers WHERE provider_name = ?', [providerName]);
  if (existing) {
    return runSql(
      "UPDATE encrypted_providers SET encrypted_api_key = ?, base_url = ?, updated_at = datetime('now') WHERE provider_name = ?",
      [encryptedApiKey, baseUrl, providerName]
    );
  } else {
    return runSql(
      'INSERT INTO encrypted_providers (provider_name, encrypted_api_key, base_url) VALUES (?, ?, ?)',
      [providerName, encryptedApiKey, baseUrl]
    );
  }
}

function getProvider(providerName) {
  return queryOne('SELECT * FROM encrypted_providers WHERE provider_name = ?', [providerName]);
}

function listProviders() {
  return queryAll('SELECT id, provider_name, base_url, created_at, updated_at FROM encrypted_providers');
}

// ─── Cleanup ────────────────────────────────────────────────────────

function cleanOldLogs(daysToKeep = 30) {
  return runSql(
    "DELETE FROM request_log WHERE timestamp < datetime('now', '-' || ? || ' days')",
    [daysToKeep]
  );
}

function close() {
  if (db) {
    saveToFile();
    db.close();
    db = null;
    dbReady = null;
  }
}

module.exports = {
  initDb,
  createProxyKey,
  findKeyByHash,
  listKeys,
  revokeKey,
  updateKeyUsage,
  getRequestCountLastMinute,
  getRequestCountToday,
  logRequest,
  saveProvider,
  getProvider,
  listProviders,
  cleanOldLogs,
  close,
};
