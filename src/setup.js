#!/usr/bin/env node
/**
 * Interactive Setup Script
 * Configures the proxy server with encrypted provider API keys
 */
const readline = require('readline');
const path = require('path');
const fs = require('fs');
const { encrypt, decrypt } = require('./crypto');
const db = require('./database');

const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout,
});

function ask(question) {
  return new Promise((resolve) => {
    rl.question(question, (answer) => resolve(answer.trim()));
  });
}

function askHidden(question) {
  return new Promise((resolve) => {
    process.stdout.write(question);
    const stdin = process.stdin;
    const wasRaw = stdin.isRaw;
    if (stdin.setRawMode) {
      stdin.setRawMode(true);
    }
    stdin.resume();

    let input = '';
    const onData = (char) => {
      const c = char.toString();
      if (c === '\n' || c === '\r') {
        if (stdin.setRawMode) stdin.setRawMode(wasRaw);
        stdin.removeListener('data', onData);
        process.stdout.write('\n');
        resolve(input);
      } else if (c === '\u0003') {
        process.exit();
      } else if (c === '\u007f' || c === '\b') {
        if (input.length > 0) {
          input = input.slice(0, -1);
          process.stdout.write('\b \b');
        }
      } else {
        input += c;
        process.stdout.write('*');
      }
    };
    stdin.on('data', onData);
  });
}

async function main() {
  // Initialize database first
  await db.initDb();

  console.log('');
  console.log('╔══════════════════════════════════════════════════╗');
  console.log('║         🔐 API Key Proxy - Setup                ║');
  console.log('╚══════════════════════════════════════════════════╝');
  console.log('');

  const envPath = path.join(__dirname, '..', '.env');
  let masterPassword;
  let proxyPort = '3456';

  // Check if .env already exists
  if (fs.existsSync(envPath)) {
    console.log('ℹ️  Existing .env file found.');
    const reuse = await ask('Use existing master password? (y/n): ');
    if (reuse.toLowerCase() === 'y') {
      const envContent = fs.readFileSync(envPath, 'utf8');
      const match = envContent.match(/MASTER_PASSWORD=(.+)/);
      if (match) {
        masterPassword = match[1];
        console.log('✅ Using existing master password.');
      }
      const portMatch = envContent.match(/PROXY_PORT=(\d+)/);
      if (portMatch) proxyPort = portMatch[1];
    }
  }

  if (!masterPassword) {
    console.log('');
    console.log('Step 1: Set a Master Password');
    console.log('This password encrypts all your API keys. Keep it safe!');
    console.log('');
    masterPassword = await askHidden('Enter master password: ');
    if (masterPassword.length < 8) {
      console.error('❌ Password must be at least 8 characters.');
      rl.close();
      db.close();
      process.exit(1);
    }
    const confirm = await askHidden('Confirm master password: ');
    if (masterPassword !== confirm) {
      console.error('❌ Passwords do not match.');
      rl.close();
      db.close();
      process.exit(1);
    }
    console.log('✅ Master password set.');
  }

  // Port
  console.log('');
  const portInput = await ask(`Proxy port (default: ${proxyPort}): `);
  if (portInput) proxyPort = portInput;

  // Save .env
  const envContent = `# API Key Proxy Configuration
# Generated on ${new Date().toISOString()}

# Master password for encrypting/decrypting API keys
MASTER_PASSWORD=${masterPassword}

# Port for the proxy server
PROXY_PORT=${proxyPort}
`;

  fs.writeFileSync(envPath, envContent);
  console.log('✅ .env file saved.');

  // Configure providers
  console.log('');
  console.log('Step 2: Configure API Providers');
  console.log('');

  const providers = [
    { name: 'anthropic', label: 'Anthropic', defaultUrl: 'https://api.anthropic.com' },
    { name: 'openrouter', label: 'OpenRouter', defaultUrl: 'https://openrouter.ai/api' },
    { name: 'ampere', label: 'Ampere (current)', defaultUrl: 'https://api.ampere.sh' },
  ];

  for (const provider of providers) {
    console.log(`\n── ${provider.label} ──`);
    const configure = await ask(`Configure ${provider.label}? (y/n): `);

    if (configure.toLowerCase() === 'y') {
      const apiKey = await askHidden(`  ${provider.label} API Key: `);
      if (!apiKey) {
        console.log('  Skipped (no key provided).');
        continue;
      }

      const baseUrl = await ask(`  Base URL (default: ${provider.defaultUrl}): `) || provider.defaultUrl;

      // Encrypt the API key
      const encryptedKey = encrypt(apiKey, masterPassword);

      // Verify encryption works
      try {
        const decrypted = decrypt(encryptedKey, masterPassword);
        if (decrypted !== apiKey) {
          throw new Error('Decryption mismatch');
        }
      } catch (err) {
        console.error(`  ❌ Encryption verification failed: ${err.message}`);
        continue;
      }

      db.saveProvider({
        providerName: provider.name,
        encryptedApiKey: encryptedKey,
        baseUrl: baseUrl,
      });

      console.log(`  ✅ ${provider.label} configured and API key encrypted.`);
      console.log(`     Key stored as: ${encryptedKey.substring(0, 20)}...`);
    }
  }

  // Custom provider
  console.log('');
  const addCustom = await ask('Add a custom provider? (y/n): ');
  if (addCustom.toLowerCase() === 'y') {
    const customName = await ask('  Provider name (lowercase, no spaces): ');
    const customKey = await askHidden('  API Key: ');
    const customUrl = await ask('  Base URL: ');

    if (customName && customKey && customUrl) {
      const encryptedKey = encrypt(customKey, masterPassword);
      db.saveProvider({
        providerName: customName,
        encryptedApiKey: encryptedKey,
        baseUrl: customUrl,
      });
      console.log(`  ✅ ${customName} configured.`);
    }
  }

  // Summary
  console.log('');
  console.log('╔══════════════════════════════════════════════════╗');
  console.log('║              ✅ Setup Complete!                  ║');
  console.log('╚══════════════════════════════════════════════════╝');
  console.log('');
  console.log('Configured providers:');
  const allProviders = db.listProviders();
  allProviders.forEach((p) => {
    console.log(`  ✅ ${p.provider_name} → ${p.base_url}`);
  });
  console.log('');
  console.log('Next steps:');
  console.log('  1. Generate a proxy key:  npm run keygen -- --name "My Key" --expires 7d');
  console.log('  2. Start the server:      npm start');
  console.log('  3. Use in your config:');
  console.log('     "env": {');
  console.log(`       "ANTHROPIC_API_KEY": "proxy_<your_key>",`);
  console.log(`       "ANTHROPIC_BASE_URL": "http://localhost:${proxyPort}/"`);
  console.log('     }');
  console.log('');

  db.close();
  rl.close();
}

main().catch((err) => {
  console.error('Setup error:', err);
  rl.close();
  db.close();
  process.exit(1);
});
