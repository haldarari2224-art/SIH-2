"""
IPsec VPN Protocol Analyzer — Unified Full-Stack Backend
Serves both the REST API and the compiled React production frontend.
"""

import sys
import os
from pathlib import Path

# Add backend directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse

from api.routes import router

app = FastAPI(
    title="IPsec VPN Protocol Analyzer",
    description="AI-Powered IPsec VPN Protocol Analysis & Security Assessment Framework",
    version="1.0.0",
)

# CORS — allow cross-origin requests
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# 1. Register API routes FIRST so API endpoints take priority
app.include_router(router)

# 2. Locate compiled frontend dist folder
BASE_DIR = Path(__file__).resolve().parent
DIST_DIR = BASE_DIR / "dist"
if not DIST_DIR.exists():
    DIST_DIR = BASE_DIR.parent / "frontend" / "dist"

if DIST_DIR.exists():
    # Mount assets folder for JS/CSS chunks
    assets_dir = DIST_DIR / "assets"
    if assets_dir.exists():
        app.mount("/assets", StaticFiles(directory=str(assets_dir)), name="assets")

    # Serve static files like favicon or fallback to index.html for SPA routing
    @app.get("/{full_path:path}")
    async def serve_frontend(request: Request, full_path: str):
        # Don't intercept API or docs routes
        if full_path.startswith("api") or full_path.startswith("docs") or full_path.startswith("openapi.json"):
            return None

        file_path = DIST_DIR / full_path
        if file_path.is_file():
            return FileResponse(str(file_path))

        index_file = DIST_DIR / "index.html"
        if index_file.is_file():
            return FileResponse(str(index_file))

        return {"error": "Frontend build not found"}
else:
    @app.get("/")
    async def root():
        return {
            "name": "IPsec VPN Protocol Analyzer",
            "version": "1.0.0",
            "description": "AI-Powered Security Assessment Framework",
            "docs": "/docs",
            "endpoints": {
                "health": "/api/health",
                "demo": "/api/demo",
                "upload": "/api/upload",
                "dashboard": "/api/dashboard/stats",
                "scenarios": "/api/scenarios",
            },
            "note": "Frontend dist not found. Run 'npm run build' inside frontend.",
        }


if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PORT", 8000))
    uvicorn.run("main:app", host="0.0.0.0", port=port, reload=False)
