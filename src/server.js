/**
 * API Key Proxy Server
 * 
 * Accepts requests with YOUR proxy keys, decrypts the real API key,
 * and forwards requests to the actual provider (Anthropic, OpenRouter, etc.)
 */
require('dotenv').config({ path: require('path').join(__dirname, '..', '.env') });

const express = require('express');
const http = require('http');
const https = require('https');
const path = require('path');
const { URL } = require('url');
const { decrypt } = require('./crypto');
const { authenticate, logRequestMiddleware } = require('./middleware');
const { registerAdminRoutes } = require('./admin-routes');
const db = require('./database');

const app = express();
const PORT = process.env.PORT || process.env.PROXY_PORT || 3456;
const MASTER_PASSWORD = process.env.MASTER_PASSWORD;

if (!MASTER_PASSWORD) {
  console.error('❌ MASTER_PASSWORD is not set in .env file. Run: npm run setup');
  process.exit(1);
}

// ─── CORS (allow frontend from different origin) ────────────────────
const ALLOWED_ORIGINS = (process.env.CORS_ORIGINS || '*').split(',').map(s => s.trim());

app.use((req, res, next) => {
  const origin = req.headers.origin;
  if (ALLOWED_ORIGINS.includes('*')) {
    res.setHeader('Access-Control-Allow-Origin', origin || '*');
  } else if (origin && ALLOWED_ORIGINS.includes(origin)) {
    res.setHeader('Access-Control-Allow-Origin', origin);
  }
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Admin-Session, x-api-key, anthropic-api-key, anthropic-version');
  res.setHeader('Access-Control-Allow-Credentials', 'true');
  res.setHeader('Access-Control-Max-Age', '86400');

  if (req.method === 'OPTIONS') {
    return res.status(204).end();
  }
  next();
});

// ─── Health Check (no auth required) ────────────────────────────────
app.get('/health', (req, res) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

// ─── Admin UI (static HTML, no auth for the page itself) ────────────
app.get('/admin', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'admin.html'));
});

// ─── Admin API routes (JSON body parsed inside) ─────────────────────
registerAdminRoutes(app, MASTER_PASSWORD);

// ─── Apply proxy middleware ─────────────────────────────────────────
app.use(logRequestMiddleware);
app.use(authenticate);

// ─── Collect raw body for proxying ──────────────────────────────────
app.use((req, res, next) => {
  let body = [];
  req.on('data', (chunk) => body.push(chunk));
  req.on('end', () => {
    req.rawBody = Buffer.concat(body);
    next();
  });
});

// ─── Proxy all authenticated requests ───────────────────────────────
app.all('*', async (req, res) => {
  try {
    const keyRecord = req.proxyKeyRecord;
    const provider = db.getProvider(keyRecord.target_provider);

    if (!provider) {
      return res.status(500).json({
        error: {
          type: 'configuration_error',
          message: `Provider "${keyRecord.target_provider}" is not configured. Run: npm run setup`,
        },
      });
    }

    // Decrypt the real API key
    let realApiKey;
    try {
      realApiKey = decrypt(provider.encrypted_api_key, MASTER_PASSWORD);
    } catch (err) {
      return res.status(500).json({
        error: {
          type: 'decryption_error',
          message: 'Failed to decrypt provider API key. Check MASTER_PASSWORD.',
        },
      });
    }

    // Build the target URL
    const targetBase = provider.base_url.replace(/\/+$/, '');
    const targetUrl = new URL(req.originalUrl, targetBase);

    // Build headers - forward most headers, replace auth
    const proxyHeaders = { ...req.headers };
    delete proxyHeaders['host'];
    delete proxyHeaders['content-length'];

    // Set the real API key in appropriate headers
    if (keyRecord.target_provider === 'anthropic' || keyRecord.target_provider === 'ampere') {
      proxyHeaders['x-api-key'] = realApiKey;
      proxyHeaders['anthropic-api-key'] = realApiKey;
      delete proxyHeaders['authorization'];
    } else if (keyRecord.target_provider === 'openrouter') {
      proxyHeaders['authorization'] = `Bearer ${realApiKey}`;
      delete proxyHeaders['x-api-key'];
      delete proxyHeaders['anthropic-api-key'];
    } else {
      proxyHeaders['authorization'] = `Bearer ${realApiKey}`;
      delete proxyHeaders['x-api-key'];
      delete proxyHeaders['anthropic-api-key'];
    }

    if (req.rawBody && req.rawBody.length > 0) {
      proxyHeaders['content-length'] = req.rawBody.length;
    }

    // Make the proxied request
    const isHttps = targetUrl.protocol === 'https:';
    const transport = isHttps ? https : http;

    const options = {
      hostname: targetUrl.hostname,
      port: targetUrl.port || (isHttps ? 443 : 80),
      path: targetUrl.pathname + targetUrl.search,
      method: req.method,
      headers: proxyHeaders,
    };

    const proxyReq = transport.request(options, (proxyRes) => {
      const isError = proxyRes.statusCode >= 400;
      const contentType = (proxyRes.headers['content-type'] || '').toLowerCase();
      const isJson = contentType.includes('application/json');
      const isStreaming = contentType.includes('text/event-stream');

      if (isError && isJson && !isStreaming) {
        // Buffer error responses to sanitize provider info
        let chunks = [];
        proxyRes.on('data', (chunk) => chunks.push(chunk));
        proxyRes.on('end', () => {
          let body = Buffer.concat(chunks).toString('utf8');
          try {
            // Remove any references to the real provider URL/domain
            const providerUrl = provider.base_url.replace(/\/+$/, '');
            const providerDomain = new URL(providerUrl).hostname;
            body = body.replace(new RegExp(providerUrl.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'gi'), 'https://api.proxy');
            body = body.replace(new RegExp(providerDomain.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'gi'), 'api.proxy');
            body = body.replace(/ampere\.sh/gi, 'api.proxy');
            body = body.replace(/https:\/\/www\.ampere\.sh[^\s"]*/gi, 'https://api.proxy');
          } catch (e) {
            // If sanitization fails, still send the response
          }

          // Copy headers but update content-length
          const sanitizedHeaders = { ...proxyRes.headers };
          sanitizedHeaders['content-length'] = Buffer.byteLength(body);
          // Remove any headers that might reveal the provider
          delete sanitizedHeaders['server'];
          delete sanitizedHeaders['x-request-id'];

          res.writeHead(proxyRes.statusCode, sanitizedHeaders);
          res.end(body);
        });
      } else {
        // For success responses and streaming, pipe directly (no provider info leaked)
        // Still clean up revealing headers
        const cleanHeaders = { ...proxyRes.headers };
        delete cleanHeaders['server'];
        delete cleanHeaders['x-request-id'];
        res.writeHead(proxyRes.statusCode, cleanHeaders);
        proxyRes.pipe(res);
      }
    });

    proxyReq.on('error', (err) => {
      console.error('Proxy request error:', err.message);
      if (!res.headersSent) {
        res.status(502).json({
          error: {
            type: 'proxy_error',
            message: 'Failed to reach upstream provider.',
          },
        });
      }
    });

    if (req.rawBody && req.rawBody.length > 0) {
      proxyReq.write(req.rawBody);
    }
    proxyReq.end();

  } catch (err) {
    console.error('Server error:', err);
    if (!res.headersSent) {
      res.status(500).json({
        error: {
          type: 'server_error',
          message: 'Internal proxy server error.',
        },
      });
    }
  }
});

// ─── Auto-provision from env vars (for ephemeral filesystems like Render) ────
function autoProvision() {
  const { encrypt } = require('./crypto');
  const { generateProxyKey, hashProxyKey } = require('./crypto');

  // Auto-configure providers from env vars
  // Format: PROVIDER_<NAME>_KEY and PROVIDER_<NAME>_URL
  // Also supports the simple format: ANTHROPIC_API_KEY_REAL + ANTHROPIC_BASE_URL_REAL
  const providerConfigs = [
    { envKey: 'PROVIDER_ANTHROPIC_KEY', envUrl: 'PROVIDER_ANTHROPIC_URL', name: 'anthropic', defaultUrl: 'https://api.anthropic.com' },
    { envKey: 'PROVIDER_OPENROUTER_KEY', envUrl: 'PROVIDER_OPENROUTER_URL', name: 'openrouter', defaultUrl: 'https://openrouter.ai/api' },
    { envKey: 'PROVIDER_AMPERE_KEY', envUrl: 'PROVIDER_AMPERE_URL', name: 'ampere', defaultUrl: 'https://api.ampere.sh' },
  ];

  for (const cfg of providerConfigs) {
    const apiKey = process.env[cfg.envKey];
    if (apiKey) {
      const baseUrl = process.env[cfg.envUrl] || cfg.defaultUrl;
      const existing = db.getProvider(cfg.name);
      if (!existing) {
        const encryptedKey = encrypt(apiKey, MASTER_PASSWORD);
        db.saveProvider({ providerName: cfg.name, encryptedApiKey: encryptedKey, baseUrl });
        console.log(`  ✅ Auto-configured provider: ${cfg.name} → ${baseUrl}`);
      }
    }
  }

  // Also support a generic REAL_API_KEY + REAL_BASE_URL for simple single-provider setup
  if (process.env.REAL_API_KEY && process.env.REAL_BASE_URL) {
    const providerName = process.env.REAL_PROVIDER_NAME || 'anthropic';
    const existing = db.getProvider(providerName);
    if (!existing) {
      const encryptedKey = encrypt(process.env.REAL_API_KEY, MASTER_PASSWORD);
      db.saveProvider({ providerName, encryptedApiKey: encryptedKey, baseUrl: process.env.REAL_BASE_URL });
      console.log(`  ✅ Auto-configured provider: ${providerName} → ${process.env.REAL_BASE_URL}`);
    }
  }

  // Auto-generate a default proxy key if none exist
  if (process.env.DEFAULT_PROXY_KEY) {
    const keyHash = hashProxyKey(process.env.DEFAULT_PROXY_KEY);
    const existing = db.findKeyByHash(keyHash);
    if (!existing) {
      db.createProxyKey({
        name: 'Default Key (from env)',
        keyHash,
        keyPrefix: process.env.DEFAULT_PROXY_KEY.substring(0, 12) + '...',
        targetProvider: process.env.DEFAULT_PROXY_PROVIDER || 'anthropic',
        expiresAt: null,
        maxRpm: parseInt(process.env.DEFAULT_PROXY_RPM || '60'),
        maxRpd: parseInt(process.env.DEFAULT_PROXY_RPD || '10000'),
        notes: 'Auto-provisioned from DEFAULT_PROXY_KEY env var',
      });
      console.log(`  ✅ Auto-configured default proxy key`);
    }
  }
}

// ─── Start Server (async to init DB first) ──────────────────────────
async function start() {
  await db.initDb();

  // Auto-provision providers and keys from env vars
  autoProvision();

  app.listen(PORT, '0.0.0.0', () => {
    console.log('');
    console.log('╔══════════════════════════════════════════════════╗');
    console.log('║         🔐 API Key Proxy Server                 ║');
    console.log('╠══════════════════════════════════════════════════╣');
    console.log(`║  Proxy URL:  http://localhost:${PORT}              ║`);
    console.log(`║  Admin UI:   http://localhost:${PORT}/admin        ║`);
    console.log('║  Status:     Running                            ║');
    console.log('╚══════════════════════════════════════════════════╝');
    console.log('');

    const providers = db.listProviders();
    if (providers.length === 0) {
      console.log('⚠️  No providers configured. Use Admin UI or run: npm run setup');
    } else {
      console.log(`✅ ${providers.length} provider(s) configured:`);
      providers.forEach((p) => {
        console.log(`   - ${p.provider_name} → ${p.base_url}`);
      });
    }

    const keys = db.listKeys().filter((k) => !k.is_revoked);
    console.log(`✅ ${keys.length} active proxy key(s)`);
    console.log('');
  });
}

start().catch((err) => {
  console.error('Failed to start server:', err);
  process.exit(1);
});

// Graceful shutdown
process.on('SIGINT', () => {
  console.log('\nShutting down...');
  db.close();
  process.exit(0);
});

process.on('SIGTERM', () => {
  db.close();
  process.exit(0);
});
