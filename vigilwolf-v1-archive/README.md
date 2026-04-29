# VigilWolf - Domain Monitoring & Threat Detection

[![Backend Tests](https://img.shields.io/badge/tests-95%20passing-brightgreen)](backend/)
[![Frontend Build](https://img.shields.io/badge/build-passing-brightgreen)](frontend/)
[![License](https://img.shields.io/badge/license-MIT-blue)](LICENSE)

A production-grade domain monitoring and brand impersonation detection system built with FastAPI and Next.js 16.

## Features

- **Domain Monitoring**: Periodic checks with configurable frequency, automatic change detection, and screenshot capture
- **Brand Impersonation Detection**: Fuzzy and regex search against Newly Registered Domain (NRD) lists
- **WHOIS Lookup**: Domain registration information with fallback parsers
- **Snapshot Management**: Full HTML dumps, asset downloads, and screenshot archives
- **Real-time Dashboard**: Web UI with auto-refresh, change detection indicators, and snapshot history
- **Production Security**: API key authentication, rate limiting, HTTPS enforcement, security headers
- **Observability**: Prometheus metrics, structured logging, request tracing

## Architecture

```
┌─────────────┐     ┌──────────────┐     ┌─────────────┐
│   Next.js   │────>│  FastAPI     │────>│   SQLite    │
│  (Frontend) │<────│  (Backend)   │<────│  (WAL mode) │
└─────────────┘     └──────────────┘     └─────────────┘
                           │
                    ┌──────┴──────┐
                    │ APScheduler │
                    │ (in-memory) │
                    └──────┬──────┘
                           │
                    ┌──────┴──────┐
                    │ Playwright  │
                    │   / Selenium │
                    └─────────────┘
```

## Quick Start

### Prerequisites

- Docker & Docker Compose
- Node.js 20+ (for local frontend development)
- Python 3.11+ (for local backend development)

### Docker Deployment

1. Clone the repository:
```bash
git clone https://github.com/your-org/vigilwolf.git
cd vigilwolf/vigilwolf-core
```

2. Configure environment variables:
```bash
cp .env.example .env
# Edit .env and set a strong API_KEY
```

3. Start all services:
```bash
docker-compose up -d
```

4. Access the application:
- Frontend: http://localhost:3000
- Backend API: http://localhost:8000
- Prometheus Metrics: http://localhost:8000/metrics (requires API key)

### Local Development

**Backend:**
```bash
cd backend
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
playwright install chromium
API_KEY=dev-key uvicorn main:app --reload
```

**Frontend:**
```bash
cd frontend
npm install
npm run dev
```

## Security Hardening Checklist

Before deploying to production:

- [ ] Change `API_KEY` from default to a strong random string
- [ ] Set `ENVIRONMENT=production`
- [ ] Configure `TRUSTED_HOSTS` to your domain(s)
- [ ] Enable `FORCE_HTTPS=true` (or use a reverse proxy with TLS)
- [ ] Set `RATE_LIMIT_PER_MINUTE=60` (or your desired limit)
- [ ] Configure `REDIS_URL` for distributed rate limiting
- [ ] Review `ALLOWED_ORIGINS` for CORS
- [ ] Ensure backend container runs as non-root (configured in Dockerfile)

## API Documentation

FastAPI auto-generates OpenAPI documentation at:
- Swagger UI: http://localhost:8000/docs
- ReDoc: http://localhost:8000/redoc

### Authentication

All endpoints require a Bearer token:
```bash
curl -H "Authorization: Bearer your-api-key" http://localhost:8000/health
```

### Key Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/health` | GET | System health check |
| `/config` | GET | Current system configuration |
| `/whois` | GET | WHOIS lookup for a domain |
| `/dump-nrd` | GET | Download NRD data |
| `/brand-search` | POST | Search brand in NRD lists |
| `/monitoring/groups` | GET/POST | List/create monitoring groups |
| `/monitoring/groups/{id}/domains` | GET | List domains in a group |
| `/monitoring/domains/{id}/force-dump` | POST | Trigger manual dump |
| `/metrics` | GET | Prometheus metrics (auth required) |

## Testing

**Backend:**
```bash
cd backend
python -m pytest -v
```

**Frontend:**
```bash
cd frontend
npm run build
```

## Configuration Reference

| Variable | Default | Description |
|----------|---------|-------------|
| `API_KEY` | *(required)* | Authentication token |
| `ENVIRONMENT` | `development` | Runtime environment |
| `RATE_LIMIT_PER_MINUTE` | `60` | Global rate limit |
| `FORCE_HTTPS` | `true` | HTTPS redirect in production |
| `TRUSTED_HOSTS` | `localhost` | Allowed host headers |
| `REDIS_URL` | *(optional)* | Redis for distributed rate limiting |
| `ENABLE_PROMETHEUS` | `true` | Metrics endpoint |
| `SCREENSHOT_ENABLED` | `true` | Enable screenshot capture |
| `MAX_DOMAINS_PER_GROUP` | `100` | Domain limit per group |
| `SNAPSHOT_RETENTION_DAYS` | `90` | Snapshot retention period |

## Roadmap

- [x] SQLite migration from JSON files
- [x] API key authentication
- [x] Rate limiting (in-memory + Redis)
- [x] Security headers & HTTPS enforcement
- [x] Prometheus metrics
- [x] NRD downloader in Python (replaced bash script)
- [x] Thread-safe rate limiter with memory leak fix
- [x] Frontend proxy with path allowlist
- [x] Real Settings page with theme toggle
- [ ] PostgreSQL support for scale
- [ ] Celery-based distributed scheduler
- [ ] S3-compatible object storage for snapshots
- [ ] OAuth / SSO integration
- [ ] Snapshot diff viewer
- [ ] Alert notifications (email, webhook, Slack)

## Contributing

1. Fork the repository
2. Create a feature branch
3. Run tests: `python -m pytest`
4. Build frontend: `npm run build`
5. Submit a pull request

## License

MIT License - see [LICENSE](LICENSE) for details.

## Support

For issues and feature requests, please use the [GitHub Issues](https://github.com/your-org/vigilwolf/issues) page.

---

**Built with:** FastAPI · Next.js · SQLAlchemy · Playwright · Tailwind CSS · shadcn/ui
