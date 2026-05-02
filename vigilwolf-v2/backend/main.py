from contextlib import asynccontextmanager

from fastapi import FastAPI, APIRouter, Depends
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.trustedhost import TrustedHostMiddleware
from starlette.middleware.httpsredirect import HTTPSRedirectMiddleware

from middleware.auth import verify_api_key
from middleware.rate_limit import RateLimitMiddleware
from middleware.response_envelope import EnvelopeMiddleware
from routes.v2.domains import router as domains_router
from routes.v2.webhooks import router as webhooks_router
from routes.v2.alerts import router as alerts_router
from routes.v2.search import router as search_router
from routes.v2.plugins import router as plugins_router
from routes.v2.monitoring import router as monitoring_router
from routes.v2.nrd import router as nrd_router
from routes.v2.iocs import router as iocs_router
from routes.v2.clusters import router as clusters_router
from routes.v2.campaigns import router as campaigns_router
from routes.v2.actors import router as actors_router
from routes.v2.events import router as events_router
import config

# ---------------------------------------------------------------------------
# Prometheus metrics (defined at module level so they can be imported by
# worker.py via lazy import)
# ---------------------------------------------------------------------------

PIPELINE_DOMAINS_PROCESSED = None
PIPELINE_DURATION = None
PIPELINE_QUEUE_DEPTH = None

if config.ENABLE_PROMETHEUS:
    from prometheus_client import Counter, Gauge, Histogram

    PIPELINE_DOMAINS_PROCESSED = Counter(
        "vigilwolf_pipeline_domains_processed_total",
        "Total domains processed",
    )
    PIPELINE_DURATION = Histogram(
        "vigilwolf_pipeline_processing_duration_seconds",
        "Processing duration",
        ["plugin"],
    )
    PIPELINE_QUEUE_DEPTH = Gauge(
        "vigilwolf_pipeline_queue_depth",
        "Current queue depth",
    )


# ---------------------------------------------------------------------------
# Lifespan — runs on startup / shutdown
# ---------------------------------------------------------------------------

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup: seed default plugin weights into the database."""
    from database import init_db, verify_production_schema
    from seed_weights import seed_weights

    if config.ENVIRONMENT == "production":
        if not config.API_KEY:
            raise RuntimeError(
                "FATAL: API_KEY is not set in production. "
                "Set the API_KEY environment variable before starting the server."
            )
        verify_production_schema()
    else:
        init_db()
    seed_weights()
    yield


app = FastAPI(title="VigilWolf v2", version="2.0.0", lifespan=lifespan)

if config.TRUSTED_HOSTS:
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=config.TRUSTED_HOSTS)
if config.FORCE_HTTPS:
    app.add_middleware(HTTPSRedirectMiddleware)

# CORS — allow frontend origin(s) configured via ALLOWED_ORIGINS
app.add_middleware(
    CORSMiddleware,
    allow_origins=config.ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Middleware — registered in reverse-execution order: envelope runs innermost
# (closest to the route handler), rate-limit runs outermost (first on request).
app.add_middleware(RateLimitMiddleware)
app.add_middleware(EnvelopeMiddleware)

# v2 router with shared auth dependency
v2_router = APIRouter(prefix="/api/v2", dependencies=[Depends(verify_api_key)])
v2_router.include_router(domains_router)
v2_router.include_router(webhooks_router)
v2_router.include_router(alerts_router)
v2_router.include_router(search_router)
v2_router.include_router(plugins_router)
v2_router.include_router(monitoring_router)
v2_router.include_router(nrd_router)
v2_router.include_router(iocs_router)
v2_router.include_router(clusters_router)
v2_router.include_router(campaigns_router)
v2_router.include_router(actors_router)
v2_router.include_router(events_router)

app.include_router(v2_router)


@app.get("/health")
async def health():
    return {"status": "ok", "version": "2.0.0"}


# ---------------------------------------------------------------------------
# Prometheus /metrics endpoint (behind ENABLE_PROMETHEUS flag)
# ---------------------------------------------------------------------------

if config.ENABLE_PROMETHEUS:
    from prometheus_client import generate_latest, CONTENT_TYPE_LATEST
    from starlette.responses import Response

    @app.get("/metrics", tags=["observability"])
    async def metrics():
        """Expose Prometheus metrics."""
        return Response(content=generate_latest(), media_type=CONTENT_TYPE_LATEST)