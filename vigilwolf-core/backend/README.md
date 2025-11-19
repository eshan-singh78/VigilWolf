# VigilWolf Domain Monitoring System

A comprehensive backend service for monitoring website changes through automated snapshot captures. The system organizes domains into groups, performs periodic checks based on configurable frequencies, and automatically creates dumps when changes are detected.

## Features

- **Group-based Organization**: Organize multiple domains into named groups for easier management
- **Automated Monitoring**: Periodic checks based on configurable frequencies (minimum 60 seconds)
- **Change Detection**: Automatic snapshot creation when HTML changes are detected
- **Manual Snapshots**: Force dump capability for on-demand captures
- **Comprehensive Logging**: Complete audit trail with ping and dump logs
- **Error Isolation**: Domain failures don't affect other domains in the group
- **Flexible Capture Modes**: 
  - HTML only (lightweight)
  - HTML + assets (complete page capture)
- **Screenshot Support**: Visual rendering capture using Playwright
- **RESTful API**: Full-featured API for all monitoring operations

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     FastAPI Endpoints                        │
└────────────────────┬────────────────────────────────────────┘
                     │
┌────────────────────┴────────────────────────────────────────┐
│              Monitoring Service Layer                        │
└────────────────────┬────────────────────────────────────────┘
                     │
┌────────────────────┴────────────────────────────────────────┐
│              Background Scheduler                            │
└────────────────────┬────────────────────────────────────────┘
                     │
┌────────────────────┴────────────────────────────────────────┐
│              Capture Engine                                  │
└────────────────────┬────────────────────────────────────────┘
                     │
┌────────────────────┴────────────────────────────────────────┐
│              Storage Layer (File System + JSON)              │
└─────────────────────────────────────────────────────────────┘
```

## Installation

### Prerequisites

- Python 3.9 or higher
- pip (Python package manager)
- 10GB+ disk space for snapshots
- 2GB+ RAM recommended

### Step 1: Clone the Repository

```bash
git clone <repository-url>
cd vigilwolf-core/backend
```

### Step 2: Create Virtual Environment

```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

### Step 3: Install Dependencies

```bash
pip install -r requirements.txt
```

### Step 4: Install Playwright Browsers

```bash
playwright install chromium
```

### Step 5: Configure Environment (Optional)

Create a `.env` file or set environment variables:

```bash
# Monitoring Configuration
export MONITORING_DATA_DIR="./monitoring/data"
export MAX_CONCURRENT_CHECKS="10"
export DEFAULT_TIMEOUT_SECONDS="30"
export SCREENSHOT_ENABLED="true"
export MAX_DOMAINS_PER_GROUP="100"
export SNAPSHOT_RETENTION_DAYS="90"

# Error Handling
export MAX_RETRIES="3"
export RETRY_DELAY_SECONDS="1.0"
export RETRY_BACKOFF_MULTIPLIER="2.0"

# Screenshot Configuration
export SCREENSHOT_WIDTH="1920"
export SCREENSHOT_HEIGHT="1080"
export BROWSER_TYPE="chromium"

# API Configuration
export ALLOWED_ORIGINS="http://localhost:3000,http://127.0.0.1:3000"

# Logging
export LOG_LEVEL="INFO"
```

## Running the Application

### Development Mode

```bash
uvicorn main:app --reload --host 0.0.0.0 --port 8000
```

### Production Mode

```bash
uvicorn main:app --host 0.0.0.0 --port 8000 --workers 4
```

### Using Docker (Optional)

```bash
docker build -t vigilwolf-backend .
docker run -p 8000:8000 -v $(pwd)/monitoring:/app/monitoring vigilwolf-backend
```

## API Documentation

Once the application is running, access the interactive API documentation:

- **Swagger UI**: http://localhost:8000/docs
- **ReDoc**: http://localhost:8000/redoc

### Key Endpoints

#### Create Monitoring Group
```http
POST /monitoring/groups
Content-Type: application/json

{
  "name": "Brand Monitoring",
  "domains": [
    {
      "url": "https://example.com",
      "dump_mode": "html_and_assets",
      "frequency_seconds": 3600
    }
  ]
}
```

#### List All Groups
```http
GET /monitoring/groups
```

#### Get Group Details
```http
GET /monitoring/groups/{group_id}
```

#### Get Domains in Group
```http
GET /monitoring/groups/{group_id}/domains
```

#### Force Dump a Domain
```http
POST /monitoring/domains/{domain_id}/force-dump
```

#### Get Domain Snapshots
```http
GET /monitoring/domains/{domain_id}/snapshots
```

#### Get Snapshot Details
```http
GET /monitoring/snapshots/{snapshot_id}
```

#### Health Check
```http
GET /health
```

## Configuration Reference

### Directory Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `MONITORING_DATA_DIR` | `./monitoring/data` | Base directory for all monitoring data |

### Monitoring Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `MAX_CONCURRENT_CHECKS` | `10` | Maximum concurrent domain checks |
| `DEFAULT_TIMEOUT_SECONDS` | `30` | HTTP request timeout |
| `SCREENSHOT_ENABLED` | `true` | Enable/disable screenshot capture |
| `MAX_DOMAINS_PER_GROUP` | `100` | Maximum domains per group |
| `SNAPSHOT_RETENTION_DAYS` | `90` | Days to retain snapshots (0 = forever) |
| `MIN_CHECK_FREQUENCY_SECONDS` | `60` | Minimum check frequency |
| `MAX_ASSET_SIZE_BYTES` | `52428800` | Maximum asset size (50MB) |

### Error Handling Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `MAX_RETRIES` | `3` | Maximum retry attempts |
| `RETRY_DELAY_SECONDS` | `1.0` | Initial retry delay |
| `RETRY_BACKOFF_MULTIPLIER` | `2.0` | Exponential backoff multiplier |
| `ALERT_THRESHOLD` | `5` | Consecutive failures before alert |

### Screenshot Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `SCREENSHOT_WIDTH` | `1920` | Screenshot width in pixels |
| `SCREENSHOT_HEIGHT` | `1080` | Screenshot height in pixels |
| `SCREENSHOT_FORMAT` | `png` | Screenshot format (png/jpeg) |
| `BROWSER_TYPE` | `chromium` | Browser type (chromium/firefox/webkit) |
| `BROWSER_HEADLESS` | `true` | Run browser in headless mode |

### Scheduler Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `SCHEDULER_TIMEZONE` | `UTC` | Scheduler timezone |
| `SCHEDULER_MAX_INSTANCES` | `3` | Max missed job executions to keep |
| `SCHEDULER_COALESCE` | `true` | Coalesce missed jobs |

### API Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `ALLOWED_ORIGINS` | `http://localhost:3000,...` | CORS allowed origins (comma-separated) |
| `RATE_LIMIT_PER_MINUTE` | `0` | API rate limit (0 = no limit) |

### Logging Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `LOG_LEVEL` | `INFO` | Log level (DEBUG/INFO/WARNING/ERROR/CRITICAL) |
| `LOG_FILE` | `` | Log file path (empty = stdout only) |
| `JSON_LOGGING` | `false` | Enable structured JSON logging |

## Data Storage Structure

```
monitoring/
└── data/
    ├── groups.json              # Group metadata
    ├── domains.json             # Domain configurations
    └── snapshots/
        └── {domain_id}/
            ├── {timestamp}/
            │   ├── metadata.json
            │   ├── page.html
            │   ├── screenshot.png
            │   └── assets/
            │       ├── style.css
            │       ├── script.js
            │       └── ...
            ├── ping.log
            └── dump.log
```

## Testing

### Run All Tests

```bash
pytest
```

### Run Specific Test Files

```bash
pytest test_models.py
pytest test_storage_manager.py
pytest test_capture_engine.py
pytest test_monitoring_service.py
pytest test_scheduler.py
pytest test_api_endpoints.py
```

### Run Property-Based Tests

```bash
pytest -v -k "property"
```

### Run with Coverage

```bash
pytest --cov=. --cov-report=html
```

## Troubleshooting

### Playwright Installation Issues

If screenshot capture fails:

```bash
# Reinstall Playwright browsers
playwright install chromium

# Or disable screenshots
export SCREENSHOT_ENABLED="false"
```

### Permission Errors

Ensure the application has write permissions:

```bash
chmod -R 755 monitoring/
```

### Scheduler Not Starting

Check logs for errors:

```bash
export LOG_LEVEL="DEBUG"
uvicorn main:app --reload
```

### High Memory Usage

Reduce concurrent checks:

```bash
export MAX_CONCURRENT_CHECKS="5"
```

### Disk Space Issues

Enable snapshot retention:

```bash
export SNAPSHOT_RETENTION_DAYS="30"
```

## Performance Considerations

### Scalability

- Designed for up to 1000 monitored domains
- Concurrent checks limited to prevent resource exhaustion
- Lazy loading of snapshot content

### Optimization Tips

1. **Reduce Screenshot Resolution**: Lower `SCREENSHOT_WIDTH` and `SCREENSHOT_HEIGHT`
2. **Use HTML-Only Mode**: Set `dump_mode` to `html_only` for lightweight monitoring
3. **Increase Check Frequency**: Use longer intervals for less critical domains
4. **Enable Retention**: Set `SNAPSHOT_RETENTION_DAYS` to automatically clean old snapshots
5. **Limit Asset Size**: Adjust `MAX_ASSET_SIZE_BYTES` to skip large files

## Security Considerations

### Input Validation

- All URLs are validated to prevent SSRF attacks
- Group names and domain IDs are sanitized
- Frequency values are validated to prevent resource exhaustion

### Access Control

- Implement authentication for production deployments
- Use API keys or OAuth2 for endpoint protection
- Rate limit force dump requests

### Data Protection

- Snapshots stored in isolated directories per domain
- Path traversal prevention in snapshot retrieval
- Filename sanitization for assets

## Monitoring and Observability

### Health Check

```bash
curl http://localhost:8000/health
```

### Metrics

The health endpoint provides:
- Scheduler status
- Group and domain counts
- Active domain count
- Configuration summary

### Logs

Logs include:
- All operations with timestamps
- Error details with stack traces
- Domain check results
- Dump creation events

## Deployment

### Systemd Service (Linux)

Create `/etc/systemd/system/vigilwolf.service`:

```ini
[Unit]
Description=VigilWolf Domain Monitoring Service
After=network.target

[Service]
Type=simple
User=vigilwolf
WorkingDirectory=/opt/vigilwolf/backend
Environment="PATH=/opt/vigilwolf/venv/bin"
ExecStart=/opt/vigilwolf/venv/bin/uvicorn main:app --host 0.0.0.0 --port 8000
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

Enable and start:

```bash
sudo systemctl enable vigilwolf
sudo systemctl start vigilwolf
sudo systemctl status vigilwolf
```

### Docker Compose

```yaml
version: '3.8'

services:
  vigilwolf-backend:
    build: .
    ports:
      - "8000:8000"
    volumes:
      - ./monitoring:/app/monitoring
    environment:
      - MONITORING_DATA_DIR=/app/monitoring/data
      - LOG_LEVEL=INFO
    restart: unless-stopped
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Write tests for new functionality
4. Ensure all tests pass
5. Submit a pull request

## License

[Your License Here]

## Support

For issues and questions:
- GitHub Issues: [repository-url]/issues
- Documentation: [documentation-url]
- Email: support@vigilwolf.com
