/**
 * Authentication & Rate Limiting Middleware
 * Validates proxy keys, checks expiration, and enforces rate limits
 */
const { hashProxyKey } = require('./crypto');
const db = require('./database');

/**
 * Extract the proxy key from the request
 * Supports: Authorization: Bearer proxy_xxx or x-api-key: proxy_xxx
 */
function extractProxyKey(req) {
  // Check Authorization header (Bearer token)
  const authHeader = req.headers['authorization'];
  if (authHeader && authHeader.startsWith('Bearer ')) {
    return authHeader.slice(7).trim();
  }

  // Check x-api-key header
  const apiKeyHeader = req.headers['x-api-key'];
  if (apiKeyHeader) {
    return apiKeyHeader.trim();
  }

  // Check anthropic-api-key header (Anthropic SDK uses this)
  const anthropicHeader = req.headers['anthropic-api-key'];
  if (anthropicHeader) {
    return anthropicHeader.trim();
  }

  return null;
}

/**
 * Main authentication middleware
 */
function authenticate(req, res, next) {
  const proxyKey = extractProxyKey(req);

  if (!proxyKey) {
    return res.status(401).json({
      error: {
        type: 'authentication_error',
        message: 'Missing API key. Provide it via Authorization: Bearer <key> or x-api-key header.',
      },
    });
  }

  // Hash the key and look it up
  const keyHash = hashProxyKey(proxyKey);
  const keyRecord = db.findKeyByHash(keyHash);

  if (!keyRecord) {
    return res.status(401).json({
      error: {
        type: 'authentication_error',
        message: 'Invalid API key.',
      },
    });
  }

  // Check if revoked
  if (keyRecord.is_revoked) {
    return res.status(403).json({
      error: {
        type: 'permission_error',
        message: 'This API key has been revoked.',
      },
    });
  }

  // Check time-based expiration
  if (keyRecord.expires_at) {
    const expiresAt = new Date(keyRecord.expires_at + 'Z'); // Treat as UTC
    const now = new Date();
    if (now > expiresAt) {
      return res.status(403).json({
        error: {
          type: 'permission_error',
          message: `This API key expired at ${keyRecord.expires_at} UTC.`,
        },
      });
    }
  }

  // Check rate limits
  const requestsLastMinute = db.getRequestCountLastMinute(keyRecord.id);
  if (requestsLastMinute >= keyRecord.max_requests_per_minute) {
    return res.status(429).json({
      error: {
        type: 'rate_limit_error',
        message: `Rate limit exceeded. Max ${keyRecord.max_requests_per_minute} requests per minute.`,
      },
    });
  }

  const requestsToday = db.getRequestCountToday(keyRecord.id);
  if (requestsToday >= keyRecord.max_requests_per_day) {
    return res.status(429).json({
      error: {
        type: 'rate_limit_error',
        message: `Daily limit exceeded. Max ${keyRecord.max_requests_per_day} requests per day.`,
      },
    });
  }

  // Attach key info to request for downstream use
  req.proxyKeyRecord = keyRecord;
  next();
}

/**
 * Request logging middleware (runs after proxy response)
 */
function logRequestMiddleware(req, res, next) {
  const startTime = Date.now();

  // Hook into response finish
  res.on('finish', () => {
    if (req.proxyKeyRecord) {
      const responseTimeMs = Date.now() - startTime;
      try {
        db.logRequest({
          keyId: req.proxyKeyRecord.id,
          method: req.method,
          reqPath: req.originalUrl,
          statusCode: res.statusCode,
          responseTimeMs,
        });
        db.updateKeyUsage(req.proxyKeyRecord.id);
      } catch (err) {
        console.error('Failed to log request:', err.message);
      }
    }
  });

  next();
}

module.exports = {
  authenticate,
  logRequestMiddleware,
  extractProxyKey,
};
