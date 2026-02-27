from __future__ import annotations

import io
import os
import json
import uuid
import hmac
import time
import hashlib
import logging
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from typing import Optional, Dict, Any

import qrcode
import redis.asyncio as redis

from fastapi import (
    FastAPI,
    HTTPException,
    Request,
    Depends,
    Header,
    Response,
    Path,
)
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.middleware.httpsredirect import HTTPSRedirectMiddleware
from fastapi.security import APIKeyHeader
from pydantic import BaseModel, Field, field_validator

class Settings(BaseModel):
    merchant_id: str
    merchant_name: str
    api_key_hash: str
    webhook_secret: bytes
    qr_secret: bytes
    allowed_hosts: list[str]
    allowed_origins: list[str]
    redis_url: str = "redis://localhost:6379/1"


settings = Settings(
    merchant_id=os.getenv("MERCHANT_ID", "merchant_demo"),
    merchant_name=os.getenv("MERCHANT_NAME", "Merchant"),
    api_key_hash=os.environ["MERCHANT_API_KEY_HASH"],
    webhook_secret=os.environ["WEBHOOK_SECRET"].encode(),
    qr_secret=os.environ["QR_SIGNING_SECRET"].encode(),
    allowed_hosts=os.getenv("ALLOWED_HOSTS", "localhost").split(","),
    allowed_origins=os.getenv("ALLOWED_ORIGINS", "https://merchant.local").split(","),
)


logging.basicConfig(level=logging.INFO)
log = logging.getLogger("merchant")

app = FastAPI(title="Merchant API")

app.add_middleware(HTTPSRedirectMiddleware)

app.add_middleware(
    TrustedHostMiddleware,
    allowed_hosts=settings.allowed_hosts,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.allowed_origins,
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
    allow_credentials=True,
)

@app.on_event("startup")
async def startup():
    app.state.redis = redis.from_url(
        settings.redis_url,
        encoding="utf-8",
        decode_responses=True,
    )
    await app.state.redis.ping()


@app.on_event("shutdown")
async def shutdown():
    await app.state.redis.close()

MAX_BODY = 1_000_000


@app.middleware("http")
async def body_limit(request: Request, call_next):
    body = await request.body()
    if len(body) > MAX_BODY:
        raise HTTPException(413, "payload too large")
    request.state.body = body
    return await call_next(request)

class PaymentCallback(BaseModel):
    payment_request_id: str
    transaction_id: str
    status: str
    amount: Decimal

    @field_validator("payment_request_id", "transaction_id")
    @classmethod
    def validate_uuid(cls, v: str):
        uuid.UUID(v)
        return v

def sha256(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def client_ip(request: Request) -> str:
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host


api_key_header = APIKeyHeader(name="X-Merchant-Key")


async def require_admin(key: str = Depends(api_key_header)):
    if not hmac.compare_digest(sha256(key), settings.api_key_hash):
        raise HTTPException(401, "unauthorized")

RATE_LIMIT = 10
WINDOW = 60


async def enforce_rate_limit(request: Request):
    r = request.app.state.redis
    ip = client_ip(request)

    key = f"rl:{ip}"
    count = await r.incr(key)

    if count == 1:
        await r.expire(key, WINDOW)

    if count > RATE_LIMIT:
        raise HTTPException(429, "rate limit exceeded")

def sign_payload(payload: Dict[str, Any]) -> Dict[str, Any]:
    canonical = json.dumps(
        payload,
        separators=(",", ":"),
        sort_keys=True,
    ).encode()

    sig = hmac.new(
        settings.qr_secret,
        canonical,
        hashlib.sha256,
    ).hexdigest()

    signed = dict(payload)
    signed["sig"] = sig
    return signed

MAX_DRIFT = 300


async def verify_webhook(
    request: Request,
    x_signature: str = Header(...),
    x_timestamp: str = Header(...),
):
    body = request.state.body

    try:
        ts = int(x_timestamp)
    except ValueError:
        raise HTTPException(400, "invalid timestamp")

    if abs(time.time() - ts) > MAX_DRIFT:
        raise HTTPException(401, "expired request")

    expected = hmac.new(
        settings.webhook_secret,
        body + x_timestamp.encode(),
        hashlib.sha256,
    ).hexdigest()

    if not hmac.compare_digest(expected, x_signature):
        raise HTTPException(403, "invalid signature")

UPDATE_SCRIPT = """
local key = KEYS[1]
local status = ARGV[1]
local tx = ARGV[2]

local data = redis.call("GET", key)
if not data then return 0 end

local obj = cjson.decode(data)
if obj.status ~= "PENDING" then return 2 end

obj.status = status
obj.transaction_id = tx

redis.call("SET", key, cjson.encode(obj), "EX", 86400)
return 1
"""

@app.post("/payments/create", dependencies=[Depends(require_admin)])
async def create_payment(request: Request, amount: Decimal):

    await enforce_rate_limit(request)

    r = request.app.state.redis

    request_id = str(uuid.uuid4())
    expiry = utc_now() + timedelta(minutes=5)

    payment = {
        "merchant_id": settings.merchant_id,
        "amount": str(amount),
        "status": "PENDING",
        "expires_at": expiry.isoformat(),
    }

    await r.set(
        f"payment:{request_id}",
        json.dumps(payment),
        ex=3600,
    )

    qr_payload = sign_payload(
        {
            "intent": "pay",
            "request_id": request_id,
            "amount": str(amount),
            "merchant_id": settings.merchant_id,
        }
    )

    img = qrcode.make(json.dumps(qr_payload))
    buf = io.BytesIO()
    img.save(buf, format="PNG")

    return Response(buf.getvalue(), media_type="image/png")


@app.post("/payments/callback")
async def payment_callback(
    request: Request,
    cb: PaymentCallback,
    _: None = Depends(verify_webhook),
):
    r = request.app.state.redis

    result = await r.eval(
        UPDATE_SCRIPT,
        1,
        f"payment:{cb.payment_request_id}",
        cb.status,
        cb.transaction_id,
    )

    if result == 0:
        raise HTTPException(404, "payment not found")

    return {"status": "accepted"}


@app.get("/payments/{request_id}")
async def payment_status(
    request: Request,
    request_id: str = Path(...),
):
    await enforce_rate_limit(request)

    uuid.UUID(request_id)

    r = request.app.state.redis
    data = await r.get(f"payment:{request_id}")

    if not data:
        raise HTTPException(404)

    return json.loads(data)


@app.get("/health")
async def health():
    return {"status": "ok"}
