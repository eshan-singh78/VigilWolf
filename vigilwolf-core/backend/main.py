from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
import subprocess
import os

# Import plugins
from plugins.file_utils import get_latest_nrd_domains
from plugins.brand_search import brand_search as run_brand_search
from plugins.log_utils import clean_log

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


@app.get("/health")
async def health_check():
    return {"status": "ok"}


@app.get('/nrd-latest')
async def nrd_latest():
    filename, domains = get_latest_nrd_domains()
    return {"filename": filename, "domains": domains}


@app.post('/brand-search')
async def brand_search(payload: dict):
    from plugins.file_utils import find_latest_nrd_file

    brand = payload.get('brand') if isinstance(payload, dict) else None
    if not brand or not isinstance(brand, str):
        return {"results": []}

    filepath = find_latest_nrd_file()
    if not filepath:
        return {"results": []}

    results = run_brand_search(brand, filepath)
    return {"results": results}


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

