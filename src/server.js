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
      res.writeHead(proxyRes.statusCode, proxyRes.headers);
      proxyRes.pipe(res);
    });

    proxyReq.on('error', (err) => {
      console.error('Proxy request error:', err.message);
      if (!res.headersSent) {
        res.status(502).json({
          error: {
            type: 'proxy_error',
            message: `Failed to reach upstream provider: ${err.message}`,
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

// ─── Start Server (async to init DB first) ──────────────────────────
async function start() {
  await db.initDb();

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
