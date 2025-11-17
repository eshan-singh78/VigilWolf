from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
import subprocess
import os

# Import plugins
from plugins.file_utils import get_latest_nrd_domains
from plugins.brand_search import brand_search as run_brand_search
from plugins.log_utils import clean_log
from plugins.whois_query import get_whois_info
from fastapi import Query


app = FastAPI()

allowed_origins = os.getenv(
    'ALLOWED_ORIGINS', 'http://localhost:3000,http://127.0.0.1:3000'
).split(',')

app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get('/whois')
async def whois_query(domain: str = Query(...)):
    result = get_whois_info(domain)
    return result

@app.get("/health")
async def health_check():
    return {"status": "ok"}


@app.get('/nrd-latest')
async def nrd_latest(limit: int | None = Query(None), offset: int = Query(0)):
    filename, domains, total = get_latest_nrd_domains(limit=limit, offset=offset)
    return {"filename": filename, "domains": domains, "total": total}


@app.post('/brand-search')
async def brand_search(payload: dict, limit: int = Query(100), offset: int = Query(0)):
    from plugins.file_utils import find_latest_nrd_file

    brand = payload.get('brand') if isinstance(payload, dict) else None
    if not brand or not isinstance(brand, str):
        return {"results": [], "total": 0}

    filepath = find_latest_nrd_file()
    if not filepath:
        return {"results": [], "total": 0}

    data = run_brand_search(brand, filepath, limit=limit, offset=offset)
    return {"results": data.get("results", []), "total": data.get("total", 0)}


@app.get("/dump-nrd")
async def dump_nrd():
    try:
        result = subprocess.run(
            ["bash", "./nrd-fix-portable.sh"],
            capture_output=True,
            text=True,
            check=True
        )

        cleaned = clean_log(result.stdout)
        return {"status": "Download Successful", "output": cleaned}
    except subprocess.CalledProcessError as e:
        cleaned_err = clean_log(e.stderr)
        return {"status": "Download Failed", "error": cleaned_err}

