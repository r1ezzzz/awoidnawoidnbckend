# 🔐 API Key Proxy Server

A secure proxy server that **encrypts your real API keys**, provides **your own custom proxy keys**, and enforces **time-based access control** with rate limiting.

## The Problem

Storing API keys in plain text like this is dangerous:

```json
"env": {
  "ANTHROPIC_API_KEY": "amp_03e6bdbb30b7c28956d81b5192c22c37991975fd72ffb174b976294f282df30c",
  "ANTHROPIC_BASE_URL": "https://api.ampere.sh/",
  "OPENROUTER_API_KEY": "amp_03e6bdbb30b7c28956d81b5192c22c37991975fd72ffb174b976294f282df30c"
}
```

## The Solution

This proxy server:

1. **Encrypts** your real API keys with AES-256-GCM (military-grade encryption)
2. **Generates proxy keys** (`proxy_xxx`) that YOU control
3. **Enforces time limits** - keys can expire after minutes, hours, or days
4. **Rate limits** requests per minute and per day
5. **Logs all usage** for auditing
6. **Revokes keys instantly** when needed

Your new config looks like this:

```json
"env": {
  "ANTHROPIC_API_KEY": "proxy_a1b2c3d4e5f6...",
  "ANTHROPIC_BASE_URL": "http://localhost:3456/"
}
```

## Architecture

```
Client (Claude, etc.)
    │
    │  proxy_xxx key
    ▼
┌─────────────────────────┐
│   API Key Proxy Server  │
│                         │
│  1. Validate proxy key  │
│  2. Check expiration    │
│  3. Check rate limits   │
│  4. Decrypt real key    │
│  5. Forward request     │
└─────────┬───────────────┘
          │  real API key
          ▼
    Anthropic / OpenRouter / etc.
```

## Quick Start

### 1. Install Dependencies

```bash
cd api-proxy
npm install
```

### 2. Run Setup (Interactive)

```bash
npm run setup
```

This will:
- Set your master encryption password
- Configure API providers (Anthropic, OpenRouter, etc.)
- Encrypt and store your real API keys

### 3. Generate a Proxy Key

```bash
# Key that expires in 7 days
npm run keygen -- --name "Dev Key" --expires 7d

# Key that expires in 2 hours
npm run keygen -- --name "Temp Session" --expires 2h

# Key with custom rate limits
npm run keygen -- --name "Limited Key" --expires 30d --rpm 10 --rpd 100

# Key that never expires
npm run keygen -- --name "Permanent Key"
```

### 4. Start the Server

```bash
npm start
```

### 5. Use Your Proxy Key

Replace your config with:

```json
"env": {
  "ANTHROPIC_API_KEY": "proxy_<your_generated_key>",
  "ANTHROPIC_BASE_URL": "http://localhost:3456/"
}
```

## CLI Commands

### Generate a Key

```bash
node src/cli.js generate [options]

Options:
  --name <name>         Key name (for identification)
  --provider <name>     Target: anthropic, openrouter, ampere (default: anthropic)
  --expires <duration>  Expiration: 30m, 2h, 1d, 7d, 30d, 1y, or ISO date
  --rpm <number>        Max requests per minute (default: 60)
  --rpd <number>        Max requests per day (default: 1000)
  --notes <text>        Optional notes
```

### List All Keys

```bash
node src/cli.js list
```

### Revoke a Key

```bash
node src/cli.js revoke --id <key_id>
```

### Key Details

```bash
node src/cli.js info --id <key_id>
```

## Time-Based Access Examples

```bash
# Give someone 2 hours of access
node src/cli.js generate --name "Guest" --expires 2h --rpm 10

# Weekly rotating key
node src/cli.js generate --name "Week 1" --expires 7d

# One-day demo access
node src/cli.js generate --name "Demo" --expires 1d --rpd 50
```

## Security Features

| Feature | Description |
|---------|-------------|
| **AES-256-GCM** | Military-grade authenticated encryption for API keys |
| **PBKDF2** | 100,000 iterations for key derivation from master password |
| **Hashed proxy keys** | Proxy keys are SHA-256 hashed before storage |
| **No plain text** | Real API keys are NEVER stored in plain text |
| **Rate limiting** | Per-minute and per-day request limits |
| **Time expiration** | Keys automatically expire after set duration |
| **Instant revocation** | Revoke any key immediately |
| **Request logging** | Full audit trail of all API usage |

## How Encryption Works

```
Real API Key: "amp_03e6bdbb..."
                │
                ▼
    ┌───────────────────┐
    │  PBKDF2 (100K)    │◄── Master Password
    │  + Random Salt     │
    └───────┬───────────┘
            │ Derived Key
            ▼
    ┌───────────────────┐
    │  AES-256-GCM      │◄── Random IV
    │  Encrypt           │
    └───────┬───────────┘
            │
            ▼
    Encrypted: "base64(salt+iv+tag+ciphertext)"
    Stored in SQLite database
```

## Admin Web UI

A full web-based admin dashboard is available at `http://localhost:3456/admin`.

### Features
- **Login** with admin username/password
- **Dashboard** with stats (active keys, total requests, providers)
- **Create keys** with name, provider, expiration time, and rate limits
- **Revoke keys** instantly with one click
- **Add providers** with encrypted API key storage
- **Client config** snippet ready to copy

### Setup Admin Credentials

Add these to your `.env` file:

```env
ADMIN_USER=admin
ADMIN_PASSWORD=your_secure_password
```

Then visit `http://localhost:3456/admin` and log in.

## Project Structure

```
api-proxy/
├── src/
│   ├── server.js        # Express proxy server
│   ├── crypto.js         # AES-256-GCM encryption/decryption
│   ├── database.js       # SQLite database operations
│   ├── middleware.js      # Auth, rate limiting, logging
│   ├── admin-routes.js   # Admin API endpoints
│   ├── cli.js            # Key management CLI
│   ├── setup.js          # Interactive setup wizard
│   └── public/
│       └── admin.html    # Admin dashboard UI
├── data/                 # SQLite database (auto-created, gitignored)
├── .env                  # Master password & config (gitignored)
├── .env.example          # Example configuration
├── .gitignore
├── package.json
└── README.md
```

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `MASTER_PASSWORD` | Password to encrypt/decrypt API keys | Required |
| `PROXY_PORT` | Port for the proxy server | `3456` |
| `ADMIN_USER` | Admin UI username | `admin` |
| `ADMIN_PASSWORD` | Admin UI password | Required for UI |

## FAQ

**Q: What happens if I lose my master password?**
A: You'll need to re-run setup and re-enter your real API keys. The encrypted keys cannot be recovered without the master password.

**Q: Can I use this with any API provider?**
A: Yes! During setup you can add custom providers with any base URL.

**Q: Is this safe for production?**
A: This is designed for local/development use. For production, add HTTPS (TLS) and deploy behind a reverse proxy.

**Q: Can multiple people use different proxy keys?**
A: Yes! Generate a unique proxy key for each person with different expiration times and rate limits.
