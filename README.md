# SOCShield

AI-driven phishing detection & response for Security Operations Centers.

## What it does

Monitors inboxes (IMAP/SMTP), runs each incoming email through an LLM for phishing classification, extracts Indicators of Compromise (malicious domains, URLs, IPs), and optionally quarantines or blocks the threat automatically. Integrates with existing SOC workflows via REST API and can feed alerts to SIEM.

Supports three AI providers (switchable): Google Gemini 2.5, OpenAI GPT-4, Anthropic Claude 3. Real-time dashboard shows threat feed, IOCs, and system health.

## Tech stack

**Backend** (`backend/`) — Python 3.11+
- FastAPI
- PostgreSQL 15+
- Redis (caching)
- Celery (task queue)
- JWT auth + rate limiting
- Swagger / OpenAPI docs

**Frontend** (`frontend/`) — Next.js 14
- Tailwind CSS
- Recharts (real-time visualization)

## Getting started

```bash
npm run install:all          # installs frontend + backend deps
npm run dev:both             # backend (8000) + frontend (3000)
```

Or run them separately:

```bash
npm run dev:backend
npm run dev:frontend
```

Test integration:

```bash
./test-integration.sh
```

See `QUICK_START_NOW.md` and `INTEGRATION_GUIDE.md` for full setup.

## Project structure

```
backend/           FastAPI app, Celery workers, DB models
frontend/          Next.js dashboard
config/            Shared config
scripts/           Service start/stop scripts
docs/              Architecture + integration guides
```

## Status

Active. Backend–frontend integrated. Self-reported detection stats: ~95% accuracy, ~19s detection time. MIT license declared in `package.json`; no top-level LICENSE file yet.
