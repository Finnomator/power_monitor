import asyncio
import hashlib
from datetime import datetime, timedelta

import httpx
import orjson
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from client_secrets import NEOOM_CONNECT_COOKIE

# Neoom API credentials
NEOOM_API_BASE = "https://connect.neoom.com"

app = FastAPI()
session = httpx.AsyncClient(follow_redirects=True)

# In-memory cache
cache = {}
cache_lock = asyncio.Lock()
CACHE_TTL = 60 * 5  # Cache expiry time in seconds


def generate_cache_key(request: Request) -> str:
    """Generate a unique cache key based on request method, path, and query params."""
    key_data = f"{request.method}:{request.url.path}?{request.url.query}"
    return hashlib.md5(key_data.encode()).hexdigest()


@app.get("/health-check")
async def health_check():
    return {"status": "ok"}


@app.middleware("http")
async def proxy_request(request: Request, call_next):
    """Intercept requests and use caching to avoid redundant API calls."""

    if request.url.path == "/health-check":
        return await call_next(request)

    cache_key = generate_cache_key(request)

    async with cache_lock:
        cached_response = cache.get(cache_key)
        if cached_response and cached_response["expires"] > datetime.now():
            return JSONResponse(content=cached_response["data"], status_code=200)

    sep = "/"
    if request.url.path.startswith("/"):
        sep = ""

    url = NEOOM_API_BASE + sep + request.url.path

    headers = {"Cookie": NEOOM_CONNECT_COOKIE}

    response = await session.request(
        method=request.method,
        url=url,
        headers=headers,
        timeout=120,
        params=request.query_params,
    )

    if response.status_code == 200:
        response_data = orjson.loads(response.content)
        async with cache_lock:
            cache[cache_key] = {
                "data": response_data,
                "expires": datetime.now() + timedelta(seconds=CACHE_TTL),
            }
        return JSONResponse(content=response_data, status_code=200)

    return JSONResponse(
        content={"detail": "Error in API request"}, status_code=response.status_code
    )
