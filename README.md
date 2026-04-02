# atlas-starter-railway

A text-to-SQL data analyst agent powered by [Atlas](https://www.useatlas.dev).

[![Deploy on Railway](https://railway.com/button.svg)](https://railway.com/deploy/_XHuNP?referralCode=N5vD3S)

This project is configured for **PostgreSQL**. Ask natural-language questions, and the agent explores a semantic layer, writes validated SQL, and returns interpreted results.

## Quick Start

1. **Install dependencies:**
   ```bash
   bun install
   ```

2. **Configure environment:** Edit `.env` with your API key and database URL.

3. **Generate semantic layer:**
   ```bash
   bun run atlas -- init          # From your database
   bun run atlas -- init --demo   # Or load demo data
   ```

4. **Run locally:**
   ```bash
   bun run dev
   ```
   API at [http://localhost:3000](http://localhost:3000).

## Deploy to Railway

1. Push to GitHub:
   ```bash
   git init && git add -A && git commit -m "Initial commit"
   gh repo create atlas-starter-railway --public --source=. --push
   ```

2. Create a [Railway project](https://railway.app/) and add a **Postgres** plugin (auto-sets `DATABASE_URL`).

3. Add two services from your GitHub repo:
   - **API** — Root directory, uses `railway.json` + `Dockerfile`
   - **Sidecar** — `sidecar/` directory, uses `sidecar/Dockerfile`

4. Set environment variables on the API service:
   ```
   ATLAS_PROVIDER=anthropic
   ANTHROPIC_API_KEY=sk-ant-...
   ATLAS_DATASOURCE_URL=postgresql://...
   ATLAS_SANDBOX_URL=http://sidecar.railway.internal:8080
   SIDECAR_AUTH_TOKEN=<shared-secret>
   ```
   Set `SIDECAR_AUTH_TOKEN` on the sidecar service too.

5. Deploy. Railway builds from the Dockerfile and runs health checks automatically.

## Project Structure

```
atlas-starter-railway/
├── src/                # Application source (API + UI)
├── bin/                # CLI tools (atlas init, enrich, eval)
├── data/               # Demo datasets (SQL seed files)
├── semantic/           # Semantic layer (YAML — entities, metrics, glossary)
├── .env                # Environment configuration
└── docs/deploy.md      # Full deployment guide
```

## Commands

| Command | Description |
|---------|-------------|
| `bun run dev` | Start dev server |
| `bun run build` | Production build |
| `bun run start` | Start production server |
| `bun run atlas -- init` | Generate semantic layer from database |
| `bun run atlas -- init --demo` | Load simple demo dataset |
| `bun run atlas -- init --demo cybersec` | Load cybersec demo (62 tables) |
| `bun run atlas -- diff` | Compare DB schema vs semantic layer |
| `bun run atlas -- query "question"` | Headless query (table output) |
| `bun run test` | Run tests |

## Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `ATLAS_PROVIDER` | Yes | LLM provider (`anthropic`, `openai`, `bedrock`, `ollama`, `openai-compatible`, `gateway`) |
| Provider API key | Yes | e.g. `ANTHROPIC_API_KEY=sk-ant-...` |
| `ATLAS_DATASOURCE_URL` | Yes | Analytics database connection string |
| `DATABASE_URL` | No | Atlas internal Postgres (auth, audit). Auto-set on most platforms |
| `ATLAS_MODEL` | No | Override the default LLM model |
| `ATLAS_ROW_LIMIT` | No | Max rows per query (default: 1000) |

See `docs/deploy.md` for the full variable reference.

## Learn More

- [Atlas Documentation](https://www.useatlas.dev)
- [GitHub](https://github.com/AtlasDevHQ/atlas)
