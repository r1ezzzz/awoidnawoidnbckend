/**
 * Admin API Routes
 * Protected by admin username/password session authentication
 */
const crypto = require('crypto');
const { generateProxyKey, hashProxyKey, encrypt, decrypt } = require('./crypto');
const db = require('./database');

// In-memory session store (simple, resets on server restart)
const sessions = new Map();
const SESSION_TTL = 4 * 60 * 60 * 1000; // 4 hours

function generateSessionId() {
  return crypto.randomBytes(32).toString('hex');
}

function cleanExpiredSessions() {
  const now = Date.now();
  for (const [id, session] of sessions) {
    if (now > session.expiresAt) {
      sessions.delete(id);
    }
  }
}

// Run cleanup every 10 minutes
setInterval(cleanExpiredSessions, 10 * 60 * 1000);

/**
 * Parse duration string to future ISO date
 */
function parseDuration(durationStr) {
  if (!durationStr) return null;

  const match = durationStr.match(/^(\d+)([mhdwy])$/i);
  if (match) {
    const value = parseInt(match[1]);
    const unit = match[2].toLowerCase();
    const now = new Date();
    switch (unit) {
      case 'm': now.setMinutes(now.getMinutes() + value); break;
      case 'h': now.setHours(now.getHours() + value); break;
      case 'd': now.setDate(now.getDate() + value); break;
      case 'w': now.setDate(now.getDate() + value * 7); break;
      case 'y': now.setFullYear(now.getFullYear() + value); break;
    }
    return now.toISOString().replace('T', ' ').replace(/\.\d+Z$/, '');
  }

  // Try ISO date
  const date = new Date(durationStr);
  if (!isNaN(date.getTime())) {
    return date.toISOString().replace('T', ' ').replace(/\.\d+Z$/, '');
  }

  return null;
}

/**
 * Middleware: check admin session
 */
function requireAdmin(req, res, next) {
  const sessionId = req.headers['x-admin-session'] || 
                    (req.headers.cookie && extractCookie(req.headers.cookie, 'admin_session'));

  if (!sessionId) {
    return res.status(401).json({ error: 'Not authenticated' });
  }

  const session = sessions.get(sessionId);
  if (!session || Date.now() > session.expiresAt) {
    sessions.delete(sessionId);
    return res.status(401).json({ error: 'Session expired' });
  }

  req.adminSession = session;
  next();
}

function extractCookie(cookieHeader, name) {
  const match = cookieHeader.match(new RegExp(`(?:^|;\\s*)${name}=([^;]*)`));
  return match ? match[1] : null;
}

/**
 * Register admin routes on the Express app
 */
function registerAdminRoutes(app, masterPassword) {
  const ADMIN_USER = process.env.ADMIN_USER || 'admin';
  const ADMIN_PASS = process.env.ADMIN_PASSWORD;

  if (!ADMIN_PASS) {
    console.log('⚠️  ADMIN_PASSWORD not set in .env - admin UI disabled');
    return;
  }

  // ─── JSON body parser for admin routes ────────────────────────────
  const jsonParser = (req, res, next) => {
    if (req.headers['content-type'] && req.headers['content-type'].includes('application/json')) {
      let body = '';
      req.on('data', (chunk) => body += chunk);
      req.on('end', () => {
        try {
          req.body = JSON.parse(body);
        } catch (e) {
          req.body = {};
        }
        next();
      });
    } else {
      req.body = {};
      next();
    }
  };

  // ─── Auth Routes ──────────────────────────────────────────────────

  app.post('/admin/api/login', jsonParser, (req, res) => {
    const { username, password } = req.body;

    if (username === ADMIN_USER && password === ADMIN_PASS) {
      const sessionId = generateSessionId();
      sessions.set(sessionId, {
        username,
        createdAt: Date.now(),
        expiresAt: Date.now() + SESSION_TTL,
      });

      res.setHeader('Set-Cookie', `admin_session=${sessionId}; Path=/admin; HttpOnly; SameSite=Strict; Max-Age=${SESSION_TTL / 1000}`);
      res.json({ success: true, session: sessionId });
    } else {
      res.status(401).json({ error: 'Invalid username or password' });
    }
  });

  app.post('/admin/api/logout', (req, res) => {
    const sessionId = req.headers['x-admin-session'] ||
                      (req.headers.cookie && extractCookie(req.headers.cookie, 'admin_session'));
    if (sessionId) sessions.delete(sessionId);
    res.setHeader('Set-Cookie', 'admin_session=; Path=/admin; HttpOnly; Max-Age=0');
    res.json({ success: true });
  });

  app.get('/admin/api/me', requireAdmin, (req, res) => {
    res.json({ username: req.adminSession.username });
  });

  // ─── Key Management Routes ────────────────────────────────────────

  app.get('/admin/api/keys', requireAdmin, (req, res) => {
    const keys = db.listKeys();
    // Add computed status
    const now = new Date();
    keys.forEach((k) => {
      if (k.is_revoked) {
        k.status = 'revoked';
      } else if (k.expires_at) {
        const exp = new Date(k.expires_at + 'Z');
        k.status = now > exp ? 'expired' : 'active';
      } else {
        k.status = 'active';
      }
    });
    res.json({ keys });
  });

  app.post('/admin/api/keys', requireAdmin, jsonParser, (req, res) => {
    const { name, provider, expires, rpm, rpd, notes } = req.body;

    if (!name) {
      return res.status(400).json({ error: 'Name is required' });
    }

    const expiresAt = parseDuration(expires);
    const proxyKey = generateProxyKey();
    const keyHash = hashProxyKey(proxyKey);
    const keyPrefix = proxyKey.substring(0, 12) + '...';

    const id = db.createProxyKey({
      name,
      keyHash,
      keyPrefix,
      targetProvider: provider || 'anthropic',
      expiresAt,
      maxRpm: parseInt(rpm) || 60,
      maxRpd: parseInt(rpd) || 1000,
      notes: notes || '',
    });

    res.json({
      success: true,
      key: {
        id,
        name,
        proxyKey, // Only shown once!
        prefix: keyPrefix,
        provider: provider || 'anthropic',
        expiresAt: expiresAt || 'Never',
        rpm: parseInt(rpm) || 60,
        rpd: parseInt(rpd) || 1000,
      },
    });
  });

  app.delete('/admin/api/keys/:id', requireAdmin, (req, res) => {
    const id = parseInt(req.params.id);
    const result = db.revokeKey(id);
    res.json({ success: true, changes: result.changes });
  });

  app.get('/admin/api/keys/:id', requireAdmin, (req, res) => {
    const keys = db.listKeys();
    const key = keys.find((k) => k.id === parseInt(req.params.id));
    if (!key) {
      return res.status(404).json({ error: 'Key not found' });
    }
    res.json({ key });
  });

  // ─── Provider Routes ──────────────────────────────────────────────

  app.get('/admin/api/providers', requireAdmin, (req, res) => {
    const providers = db.listProviders();
    res.json({ providers });
  });

  app.post('/admin/api/providers', requireAdmin, jsonParser, (req, res) => {
    const { providerName, apiKey, baseUrl } = req.body;

    if (!providerName || !apiKey || !baseUrl) {
      return res.status(400).json({ error: 'providerName, apiKey, and baseUrl are required' });
    }

    // Encrypt the API key
    const encryptedKey = encrypt(apiKey, masterPassword);

    // Verify
    try {
      const decrypted = decrypt(encryptedKey, masterPassword);
      if (decrypted !== apiKey) throw new Error('Mismatch');
    } catch (err) {
      return res.status(500).json({ error: 'Encryption verification failed' });
    }

    db.saveProvider({ providerName, encryptedApiKey: encryptedKey, baseUrl });
    res.json({ success: true, provider: { providerName, baseUrl } });
  });

  // ─── Stats Route ──────────────────────────────────────────────────

  app.get('/admin/api/stats', requireAdmin, (req, res) => {
    const keys = db.listKeys();
    const providers = db.listProviders();
    const activeKeys = keys.filter((k) => {
      if (k.is_revoked) return false;
      if (k.expires_at) {
        return new Date() <= new Date(k.expires_at + 'Z');
      }
      return true;
    });

    res.json({
      totalKeys: keys.length,
      activeKeys: activeKeys.length,
      revokedKeys: keys.filter((k) => k.is_revoked).length,
      expiredKeys: keys.length - activeKeys.length - keys.filter((k) => k.is_revoked).length,
      totalProviders: providers.length,
      totalRequests: keys.reduce((sum, k) => sum + (k.total_requests || 0), 0),
    });
  });

  console.log(`✅ Admin UI enabled at /admin (user: ${ADMIN_USER})`);
}

module.exports = { registerAdminRoutes };
