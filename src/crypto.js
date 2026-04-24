/**
 * Encryption/Decryption module for API keys
 * Uses AES-256-GCM for authenticated encryption
 */
const crypto = require('crypto');

const ALGORITHM = 'aes-256-gcm';
const IV_LENGTH = 16;
const AUTH_TAG_LENGTH = 16;
const SALT_LENGTH = 32;
const KEY_LENGTH = 32;
const ITERATIONS = 100000;

/**
 * Derive an encryption key from a master password using PBKDF2
 */
function deriveKey(masterPassword, salt) {
  return crypto.pbkdf2Sync(masterPassword, salt, ITERATIONS, KEY_LENGTH, 'sha512');
}

/**
 * Encrypt a plaintext API key
 * Returns: base64 encoded string containing salt + iv + authTag + ciphertext
 */
function encrypt(plaintext, masterPassword) {
  const salt = crypto.randomBytes(SALT_LENGTH);
  const key = deriveKey(masterPassword, salt);
  const iv = crypto.randomBytes(IV_LENGTH);

  const cipher = crypto.createCipheriv(ALGORITHM, key, iv);
  let encrypted = cipher.update(plaintext, 'utf8');
  encrypted = Buffer.concat([encrypted, cipher.final()]);
  const authTag = cipher.getAuthTag();

  // Combine: salt (32) + iv (16) + authTag (16) + ciphertext
  const combined = Buffer.concat([salt, iv, authTag, encrypted]);
  return combined.toString('base64');
}

/**
 * Decrypt an encrypted API key
 * Input: base64 encoded string from encrypt()
 */
function decrypt(encryptedBase64, masterPassword) {
  const combined = Buffer.from(encryptedBase64, 'base64');

  // Extract components
  const salt = combined.subarray(0, SALT_LENGTH);
  const iv = combined.subarray(SALT_LENGTH, SALT_LENGTH + IV_LENGTH);
  const authTag = combined.subarray(SALT_LENGTH + IV_LENGTH, SALT_LENGTH + IV_LENGTH + AUTH_TAG_LENGTH);
  const ciphertext = combined.subarray(SALT_LENGTH + IV_LENGTH + AUTH_TAG_LENGTH);

  const key = deriveKey(masterPassword, salt);

  const decipher = crypto.createDecipheriv(ALGORITHM, key, iv);
  decipher.setAuthTag(authTag);

  let decrypted = decipher.update(ciphertext);
  decrypted = Buffer.concat([decrypted, decipher.final()]);

  return decrypted.toString('utf8');
}

/**
 * Generate a random proxy API key (your own custom key format)
 * Format: proxy_<random_hex>
 */
function generateProxyKey() {
  const randomPart = crypto.randomBytes(32).toString('hex');
  return `proxy_${randomPart}`;
}

/**
 * Hash a proxy key for storage (we never store proxy keys in plain text)
 */
function hashProxyKey(proxyKey) {
  return crypto.createHash('sha256').update(proxyKey).digest('hex');
}

module.exports = {
  encrypt,
  decrypt,
  generateProxyKey,
  hashProxyKey,
};
