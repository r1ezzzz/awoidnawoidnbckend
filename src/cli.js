#!/usr/bin/env node
/**
 * CLI Tool for managing proxy API keys
 * 
 * Usage:
 *   node src/cli.js generate --name "My Key" --expires "2h" --rpm 30 --rpd 500
 *   node src/cli.js list
 *   node src/cli.js revoke --id 1
 *   node src/cli.js info --id 1
 */
require('dotenv').config({ path: require('path').join(__dirname, '..', '.env') });

const { generateProxyKey, hashProxyKey } = require('./crypto');
const db = require('./database');

const args = process.argv.slice(2);
const command = args[0];

function getArg(name) {
  const idx = args.indexOf(`--${name}`);
  if (idx === -1 || idx + 1 >= args.length) return null;
  return args[idx + 1];
}

/**
 * Parse a duration string into a future Date
 * Supports: 30m, 2h, 1d, 7d, 30d, 1y, or ISO date string
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

  // Try parsing as ISO date
  const date = new Date(durationStr);
  if (!isNaN(date.getTime())) {
    return date.toISOString().replace('T', ' ').replace(/\.\d+Z$/, '');
  }

  console.error(`❌ Invalid duration format: "${durationStr}"`);
  console.error('   Use: 30m, 2h, 1d, 7d, 30d, 1y, or ISO date');
  process.exit(1);
}

// ─── Commands ───────────────────────────────────────────────────────

function generateKey() {
  const name = getArg('name') || `Key-${Date.now()}`;
  const provider = getArg('provider') || 'anthropic';
  const expires = getArg('expires');
  const rpm = parseInt(getArg('rpm') || '60');
  const rpd = parseInt(getArg('rpd') || '1000');
  const notes = getArg('notes') || '';

  const expiresAt = parseDuration(expires);
  const proxyKey = generateProxyKey();
  const keyHash = hashProxyKey(proxyKey);
  const keyPrefix = proxyKey.substring(0, 12) + '...';

  const id = db.createProxyKey({
    name,
    keyHash,
    keyPrefix,
    targetProvider: provider,
    expiresAt,
    maxRpm: rpm,
    maxRpd: rpd,
    notes,
  });

  console.log('');
  console.log('╔══════════════════════════════════════════════════════════════════╗');
  console.log('║                 🔑 New Proxy Key Generated                      ║');
  console.log('╠══════════════════════════════════════════════════════════════════╣');
  console.log(`║  ID:        ${id}`);
  console.log(`║  Name:      ${name}`);
  console.log(`║  Provider:  ${provider}`);
  console.log(`║  Expires:   ${expiresAt || 'Never'}`);
  console.log(`║  Rate:      ${rpm} req/min, ${rpd} req/day`);
  console.log('╠══════════════════════════════════════════════════════════════════╣');
  console.log('║  ⚠️  SAVE THIS KEY - IT WILL NOT BE SHOWN AGAIN!               ║');
  console.log('╠══════════════════════════════════════════════════════════════════╣');
  console.log(`║  ${proxyKey}`);
  console.log('╚══════════════════════════════════════════════════════════════════╝');
  console.log('');
  console.log('Use this in your client config:');
  console.log('  "env": {');
  console.log(`    "ANTHROPIC_API_KEY": "${proxyKey}",`);
  console.log(`    "ANTHROPIC_BASE_URL": "http://localhost:${process.env.PROXY_PORT || 3456}/"`);
  console.log('  }');
  console.log('');
}

function listKeysCmd() {
  const keys = db.listKeys();

  if (keys.length === 0) {
    console.log('No proxy keys found. Generate one with: node src/cli.js generate --name "My Key"');
    return;
  }

  console.log('');
  console.log('┌────┬──────────────────┬──────────────┬────────────┬─────────────────────┬─────────────────────┬──────────┬──────────┐');
  console.log('│ ID │ Name             │ Provider     │ Status     │ Created             │ Expires             │ Requests │ RPM/RPD  │');
  console.log('├────┼──────────────────┼──────────────┼────────────┼─────────────────────┼─────────────────────┼──────────┼──────────┤');

  keys.forEach((k) => {
    let status = '✅ Active';
    if (k.is_revoked) {
      status = '🚫 Revoked';
    } else if (k.expires_at) {
      const exp = new Date(k.expires_at + 'Z');
      if (new Date() > exp) {
        status = '⏰ Expired';
      }
    }

    const name = (k.name || '').padEnd(16).substring(0, 16);
    const provider = (k.target_provider || '').padEnd(12).substring(0, 12);
    const statusPad = status.padEnd(10);
    const created = (k.created_at || '').substring(0, 19);
    const expires = k.expires_at ? k.expires_at.substring(0, 19) : 'Never              ';
    const requests = String(k.total_requests || 0).padStart(8);
    const limits = `${k.max_requests_per_minute}/${k.max_requests_per_day}`.padEnd(8);

    console.log(`│ ${String(k.id).padStart(2)} │ ${name} │ ${provider} │ ${statusPad} │ ${created} │ ${expires} │ ${requests} │ ${limits} │`);
  });

  console.log('└────┴──────────────────┴──────────────┴────────────┴─────────────────────┴─────────────────────┴──────────┴──────────┘');
  console.log('');
}

function revokeKeyCmd() {
  const id = getArg('id');
  if (!id) {
    console.error('❌ Please provide --id <key_id>');
    console.error('   Use "node src/cli.js list" to see all keys');
    process.exit(1);
  }

  const result = db.revokeKey(parseInt(id));
  if (result.changes > 0) {
    console.log(`✅ Key #${id} has been revoked.`);
  } else {
    console.log(`❌ Key #${id} not found.`);
  }
}

function showInfo() {
  const id = getArg('id');
  if (!id) {
    console.error('❌ Please provide --id <key_id>');
    process.exit(1);
  }

  const keys = db.listKeys();
  const key = keys.find((k) => k.id === parseInt(id));
  if (!key) {
    console.log(`❌ Key #${id} not found.`);
    return;
  }

  console.log('');
  console.log(`Key #${key.id}: ${key.name}`);
  console.log(`  Prefix:     ${key.key_prefix}`);
  console.log(`  Provider:   ${key.target_provider}`);
  console.log(`  Created:    ${key.created_at}`);
  console.log(`  Expires:    ${key.expires_at || 'Never'}`);
  console.log(`  Revoked:    ${key.is_revoked ? 'Yes' : 'No'}`);
  console.log(`  Requests:   ${key.total_requests}`);
  console.log(`  Last Used:  ${key.last_used_at || 'Never'}`);
  console.log(`  Rate Limit: ${key.max_requests_per_minute} req/min, ${key.max_requests_per_day} req/day`);
  console.log(`  Notes:      ${key.notes || '-'}`);
  console.log('');
}

function showHelp() {
  console.log('');
  console.log('🔐 API Key Proxy - Key Management CLI');
  console.log('');
  console.log('Commands:');
  console.log('  generate   Create a new proxy API key');
  console.log('  list       List all proxy keys');
  console.log('  revoke     Revoke a proxy key');
  console.log('  info       Show details for a key');
  console.log('');
  console.log('Generate Options:');
  console.log('  --name <name>         Key name (default: auto-generated)');
  console.log('  --provider <name>     Target provider: anthropic, openrouter (default: anthropic)');
  console.log('  --expires <duration>  Expiration: 30m, 2h, 1d, 7d, 30d, 1y, or ISO date');
  console.log('  --rpm <number>        Max requests per minute (default: 60)');
  console.log('  --rpd <number>        Max requests per day (default: 1000)');
  console.log('  --notes <text>        Optional notes');
  console.log('');
  console.log('Examples:');
  console.log('  node src/cli.js generate --name "Dev Key" --expires 7d --rpm 30');
  console.log('  node src/cli.js generate --name "Temp Key" --expires 2h');
  console.log('  node src/cli.js list');
  console.log('  node src/cli.js revoke --id 1');
  console.log('');
}

// ─── Main (async for DB init) ───────────────────────────────────────

async function main() {
  await db.initDb();

  switch (command) {
    case 'generate':
      generateKey();
      break;
    case 'list':
      listKeysCmd();
      break;
    case 'revoke':
      revokeKeyCmd();
      break;
    case 'info':
      showInfo();
      break;
    case 'help':
    case '--help':
    case '-h':
      showHelp();
      break;
    default:
      showHelp();
      break;
  }

  db.close();
}

main().catch((err) => {
  console.error('Error:', err);
  db.close();
  process.exit(1);
});
