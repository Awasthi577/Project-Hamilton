"""
Hamilton Core – Secure Token Processor (Production Hardened)

Security Features:
- HMAC client authentication
- Ed25519 transaction verification
- Role-based access control
- Replay protection
- Redis-backed rate limiting
- Secure idempotency
"""

import os
import json
import hmac
import time
import uuid
import logging
from decimal import Decimal, ROUND_DOWN
from datetime import datetime, timezone
from typing import Dict, List
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request, HTTPException, Depends, Header
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
import redis.asyncio as aioredis
from nacl.signing import VerifyKey
from nacl.exceptions import BadSignatureError

# ==========================================================
# CONFIG
# ==========================================================

class Settings(BaseModel):
    redis_url: str
    allowed_origins: List[str]
    replay_window_seconds: int = 30
    rate_limit_per_minute: int = 120


settings = Settings(
    redis_url=os.environ["REDIS_URL"],  # rediss://user:pass@host:6379/0
    allowed_origins=os.environ.get(
        "ALLOWED_ORIGINS",
        "https://wallet.hamilton.finance"
    ).split(","),
)

# ==========================================================
# LOGGING (NO SENSITIVE DATA)
# ==========================================================

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("hamilton")

def safe_id(value: str):
    return value[:6]

# ==========================================================
# CLIENT REGISTRY (MOVE TO DB IN PROD)
# ==========================================================

CLIENTS: Dict[str, Dict] = {
    "liquidity-bridge": {
        "secret": os.environ["CLIENT_SECRET_BRIDGE"],
        "role": "ISSUER"
    },
    "wallet-service": {
        "secret": os.environ["CLIENT_SECRET_WALLET"],
        "role": "PROCESSOR"
    }
}

# ==========================================================
# MODELS
# ==========================================================

def quantize_money(v: Decimal):
    return v.quantize(Decimal("0.01"), rounding=ROUND_DOWN)

class Transaction(BaseModel):
    transaction_id: str
    amount: Decimal = Field(gt=0)
    currency: str
    sender_public_key: str
    receiver_public_key: str
    signature: str

class MintRequest(BaseModel):
    amount: Decimal
    currency: str
    public_key: str

class BurnRequest(BaseModel):
    token_ids: List[str]
    owner_public_key: str
    signature: str

# ==========================================================
# REDIS LIFECYCLE
# ==========================================================

@asynccontextmanager
async def lifespan(app: FastAPI):
    redis = aioredis.from_url(settings.redis_url, decode_responses=True)
    app.state.redis = redis
    await redis.ping()
    yield
    await redis.close()

# ==========================================================
# SECURITY — AUTHENTICATION
# ==========================================================

async def authenticate(
    request: Request,
    x_client_id: str = Header(...),
    x_signature: str = Header(...),
    x_timestamp: str = Header(...)
):

    if x_client_id not in CLIENTS:
        raise HTTPException(401, "Unknown client")

    client = CLIENTS[x_client_id]

    # Replay protection
    now = int(time.time())
    if abs(now - int(x_timestamp)) > settings.replay_window_seconds:
        raise HTTPException(401, "Request expired")

    body = await request.body()

    payload = (
        request.method +
        request.url.path +
        body.decode() +
        x_timestamp
    ).encode()

    expected = hmac.new(
        client["secret"].encode(),
        payload,
        "sha256"
    ).hexdigest()

    if not hmac.compare_digest(expected, x_signature):
        raise HTTPException(401, "Invalid signature")

    request.state.client_role = client["role"]
    request.state.client_id = x_client_id

# ==========================================================
# ROLE GUARD
# ==========================================================

def require_role(role: str):
    def checker(request: Request):
        if request.state.client_role != role:
            raise HTTPException(403, "Forbidden")
    return checker

# ==========================================================
# RATE LIMITING
# ==========================================================

async def rate_limit(request: Request):
    redis = request.app.state.redis
    key = f"rl:{request.state.client_id}:{int(time.time()/60)}"
    count = await redis.incr(key)
    if count == 1:
        await redis.expire(key, 60)

    if count > settings.rate_limit_per_minute:
        raise HTTPException(429, "Rate limit exceeded")

# ==========================================================
# IDEMPOTENCY
# ==========================================================

async def idempotency(
    request: Request,
    idempotency_key: str = Header(...)
):
    redis = request.app.state.redis

    key = f"idem:{request.state.client_id}:{idempotency_key}"

    ok = await redis.set(key, "processing", nx=True, ex=86400)

    if not ok:
        raise HTTPException(409, "Duplicate request")

    request.state.idem_key = key

async def mark_complete(request: Request):
    await request.app.state.redis.set(
        request.state.idem_key,
        "done",
        ex=86400
    )

# ==========================================================
# CRYPTOGRAPHY
# ==========================================================

def verify_ed25519(pubkey_hex: str, message: bytes, signature_hex: str):
    try:
        VerifyKey(bytes.fromhex(pubkey_hex)).verify(
            message,
            bytes.fromhex(signature_hex)
        )
    except BadSignatureError:
        raise HTTPException(400, "Invalid transaction signature")

# ==========================================================
# APP
# ==========================================================

app = FastAPI(lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.allowed_origins,
    allow_methods=["POST", "GET"],
    allow_headers=["*"],
)

# ==========================================================
# ENDPOINTS
# ==========================================================

@app.post("/transactions/process")
async def process_tx(
    request: Request,
    tx: Transaction,
    _: None = Depends(authenticate),
    __: None = Depends(rate_limit),
    ___: None = Depends(idempotency),
):

    tx.amount = quantize_money(tx.amount)

    message = json.dumps(tx.dict(exclude={"signature"}), sort_keys=True).encode()

    verify_ed25519(
        tx.sender_public_key,
        message,
        tx.signature
    )

    await mark_complete(request)

    logger.info(f"TX OK {safe_id(tx.transaction_id)}")

    return {"status": "COMPLETED"}

# ==========================================================

@app.post("/tokens/mint")
async def mint(
    request: Request,
    mint: MintRequest,
    _: None = Depends(authenticate),
    __: None = Depends(require_role("ISSUER")),
    ___: None = Depends(rate_limit),
    ____: None = Depends(idempotency),
):

    mint.amount = quantize_money(mint.amount)

    await mark_complete(request)

    logger.info("Mint executed")

    return {"status": "COMPLETED"}

# ==========================================================

@app.post("/tokens/burn")
async def burn(
    request: Request,
    burn: BurnRequest,
    _: None = Depends(authenticate),
    __: None = Depends(rate_limit),
    ___: None = Depends(idempotency),
):

    message = json.dumps({
        "tokens": burn.token_ids,
        "owner": burn.owner_public_key
    }, sort_keys=True).encode()

    verify_ed25519(
        burn.owner_public_key,
        message,
        burn.signature
    )

    await mark_complete(request)

    logger.info("Burn executed")

    return {"status": "COMPLETED"}

# ==========================================================

@app.get("/health/internal")
async def health(request: Request):
    await request.app.state.redis.ping()
    return {"status": "healthy", "ts": datetime.now(timezone.utc)}