import base64
import hashlib
import os

import httpx
import orjson
from fastapi import FastAPI, Request
from starlette.responses import JSONResponse

from client_secrets import NEOOM_EMAIL, NEOOM_PASSWORD, NEOOM_CLIENT_ID

REDIRECT_URI = "https://app.neoom.com/oauth/authorize"
NEOOM_API_BASE = "https://api.neoom.com"

app = FastAPI()
session = httpx.AsyncClient(follow_redirects=True)

# Token storage (simple but effective)
access_token = None
refresh_token = None


def generate_pkce():
    """Generate a code_verifier and its corresponding code_challenge for PKCE."""
    code_verifier = base64.urlsafe_b64encode(os.urandom(32)).decode("utf-8").rstrip("=")
    code_challenge = (
        base64.urlsafe_b64encode(hashlib.sha256(code_verifier.encode("utf-8")).digest())
        .decode("utf-8")
        .rstrip("=")
    )

    return code_verifier, code_challenge


async def get_csrf_token():
    """Retrieve CSRF token for login."""
    url = "https://id.neoom.com/users/sign_in"
    response = await session.get(url)

    csrf_token = response.text.split('<meta name="csrf-token" content="')[1].split(
        '" />'
    )[0]
    return csrf_token


async def post_sign_in(csrf_token: str):
    """Perform login and establish session."""
    url = "https://id.neoom.com/users/sign_in"
    payload = {
        "authenticity_token": csrf_token,
        "user[email]": NEOOM_EMAIL,
        "user[password]": NEOOM_PASSWORD,
        "commit": "Anmelden",
    }
    headers = {"Content-Type": "application/x-www-form-urlencoded"}

    response = await session.post(
        url, headers=headers, data=payload, follow_redirects=False
    )
    return response.status_code == 302  # Successful login


async def get_authorization_code(code_challenge: str):
    """Retrieve OAuth authorization code."""
    url = (
        f"https://id.neoom.com/oauth/authorize?client_id={NEOOM_CLIENT_ID}"
        f"&code_challenge={code_challenge}&code_challenge_method=S256"
        f"&redirect_uri={REDIRECT_URI}&response_type=code"
    )

    response = await session.get(url, follow_redirects=False)
    if "location" in response.headers:
        return response.headers["location"].split("code=")[1].split("&")[0]
    return None


async def get_access_token():
    """Obtain or refresh the OAuth access token."""
    global access_token, refresh_token

    # Generate PKCE values
    code_verifier, code_challenge = generate_pkce()

    # Login
    csrf = await get_csrf_token()
    if not await post_sign_in(csrf):
        raise Exception("Login failed")

    # Get authorization code
    code = await get_authorization_code(code_challenge)
    if not code:
        raise Exception("Failed to retrieve authorization code")

    # Exchange authorization code for access token
    url = "https://connect.neoom.com/oauth/token"
    payload = {
        "grant_type": "authorization_code",
        "client_id": NEOOM_CLIENT_ID,
        "code_verifier": code_verifier,
        "redirect_uri": REDIRECT_URI,
        "code": code,
    }
    headers = {"Content-Type": "application/x-www-form-urlencoded"}

    response = await session.post(url, headers=headers, data=payload)
    data = response.json()

    if "access_token" in data:
        access_token = data["access_token"]
        refresh_token = data.get("refresh_token", None)
    else:
        raise Exception(f"Failed to obtain access token: {data}")


@app.get("/health-check")
async def health_check():
    return {"status": "ok"}


@app.middleware("http")
async def proxy_request(request: Request, call_next):
    """Intercept all requests and proxy them to Neoom API with authentication."""

    if request.url.path == "/health-check":
        return await call_next(request)

    global access_token

    if not access_token:
        await get_access_token()

    url = f"{NEOOM_API_BASE}{request.url.path}"

    headers = {
        "Authorization": f"Bearer {access_token}",
    }

    allowed_headers = [
        "content-length",
        "accept",
        "accept-encoding",
        "content-type",
        "user-agent",
    ]

    for allowed_header in allowed_headers:
        for header in request.headers:
            if header.lower() == allowed_header.lower():
                headers[header] = request.headers[header]

    request_body = await request.body()

    headers["content-length"] = str(len(request_body))

    response = await session.request(
        method=request.method,
        url=url,
        headers=headers,
        params=request.query_params,
        content=request_body,
    )

    if response.status_code == 401:
        # Refresh access token and retry
        print("Refreshing access token...")
        await get_access_token()
        headers["Authorization"] = f"Bearer {access_token}"
        response = await session.request(
            method=request.method,
            url=url,
            headers=headers,
            params=request.query_params,
            content=request_body,
        )

    return JSONResponse(
        content=orjson.loads(response.content), status_code=response.status_code
    )
