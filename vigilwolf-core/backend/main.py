# main.py
from fastapi import FastAPI
import subprocess

app = FastAPI()

@app.get("/health")
async def health_check():
    return {"status": "ok"}

@app.get("/dump-nrd")
async def dump_nrd():
    try:
        result = subprocess.run(
            ["bash", "./nrd-fix-portable.sh"],
            capture_output=True,
            text=True,
            check=True
        )

        return {"status": "Download Successful", "output": result.stdout}
    except subprocess.CalledProcessError as e:

        return {"status": "Download Failed", "error": e.stderr}
