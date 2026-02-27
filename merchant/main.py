import io
import os
import json
import uuid
import hmac
import time
import base64
import hashlib
import logging
import sqlite3
import secrets
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from typing import Any, Dict

import qrcode
import redis.asyncio as redis
from fastapi import (
    FastAPI,
    HTTPException,
    Request,
    Depends,
    Header,
    Path,
)
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from pydantic import BaseModel, field_validator

class Settings(BaseModel):
    merchant_id: str
    merchant_name: str
    api_key_hash: str
    webhook_secret: bytes
    qr_secret: bytes
    allowed_hosts: list[str]
    allowed_origins: list[str]
    redis_url: str = "redis://localhost:6379/0"
    db_path: str = "payments.db"

settings = Settings(
    merchant_id=os.getenv("MERCHANT_ID", "local_dev_merchant"),
    merchant_name=os.getenv("MERCHANT_NAME", "Local Dev Corp"),
    api_key_hash=os.getenv("MERCHANT_API_KEY_HASH", hashlib.sha256(b"dev_key").hexdigest()),
    webhook_secret=os.getenv("WEBHOOK_SECRET", "dev_webhook_secret").encode(),
    qr_secret=os.getenv("QR_SIGNING_SECRET", "dev_qr_secret").encode(),
    allowed_hosts=os.getenv("ALLOWED_HOSTS", "*").split(","),
    allowed_origins=os.getenv("ALLOWED_ORIGINS", "*").split(","),
    redis_url=os.getenv("REDIS_URL", "redis://localhost:6379/1"),
    db_path=os.getenv("DB_PATH", "payments.db")
)

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger("payment_core")

app = FastAPI(title=f"{settings.merchant_name} Payment Core", version="2.0.0")

app.add_middleware(TrustedHostMiddleware, allowed_hosts=settings.allowed_hosts)
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.allowed_origins,
    allow_methods=["*"],
    allow_headers=["*"],
    allow_credentials=True,
)

MAX_BODY_SIZE = 1_000_000

@app.middleware("http")
async def limit_body_size_and_preserve_stream(request: Request, call_next):
    body = await request.body()
    if len(body) > MAX_BODY_SIZE:
        return JSONResponse(status_code=413, content={"detail": "Payload too large"})
    
    request.state.body = body

    async def receive():
        return {"type": "http.request", "body": body}
    
    request._receive = receive
    return await call_next(request)

class PaymentCallback(BaseModel):
    payment_request_id: str
    transaction_id: str
    status: str
    amount: Decimal

    @field_validator("payment_request_id", "transaction_id")
    @classmethod
    def validate_uuid(cls, v: str):
        try:
            uuid.UUID(v)
            return v
        except ValueError:
            raise ValueError("invalid uuid")

def get_db():
    conn = sqlite3.connect(settings.db_path, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
    finally:
        conn.close()

def init_db():
    with sqlite3.connect(settings.db_path) as conn:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS payments (
                id TEXT PRIMARY KEY,
                merchant_id TEXT NOT NULL,
                amount_cents INTEGER NOT NULL,
                status TEXT NOT NULL,
                expires_at TIMESTAMP NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE IF NOT EXISTS payment_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                payment_id TEXT NOT NULL,
                status TEXT NOT NULL,
                event_type TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(payment_id) REFERENCES payments(id)
            );
            CREATE TABLE IF NOT EXISTS processed_webhooks (
                event_id TEXT PRIMARY KEY,
                processed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
            CREATE INDEX IF NOT EXISTS idx_payments_merchant ON payments(merchant_id);
        """)

@app.on_event("startup")
async def startup():
    init_db()
    app.state.redis = redis.from_url(settings.redis_url, encoding="utf-8", decode_responses=True)
    await app.state.redis.ping()

@app.on_event("shutdown")
async def shutdown():
    await app.state.redis.close()

def get_client_ip(request: Request) -> str:
    return request.headers.get("x-forwarded-for", "").split(",")[0].strip() or request.client.host or "127.0.0.1"

async def require_admin(request: Request):
    key = request.headers.get("X-Merchant-Key")
    if not key:
        raise HTTPException(status_code=401, detail="missing key")
    
    if not hmac.compare_digest(hashlib.sha256(key.encode()).hexdigest(), settings.api_key_hash):
        raise HTTPException(status_code=401, detail="unauthorized")

async def enforce_rate_limit(request: Request):
    r = request.app.state.redis
    ip = get_client_ip(request)
    key = f"rl:{settings.merchant_id}:{ip}"
    
    count = await r.incr(key)
    if count == 1:
        await r.expire(key, 60)

    if count > 20:
        raise HTTPException(status_code=429, detail="rate limit exceeded")

async def verify_webhook_signature(
    request: Request,
    x_signature: str = Header(..., alias="X-Signature"),
    x_timestamp: str = Header(..., alias="X-Timestamp"),
    x_event_id: str = Header(..., alias="X-Event-ID"),
):
    body = getattr(request.state, "body", b"")
    
    try:
        ts = int(x_timestamp)
    except ValueError:
        raise HTTPException(status_code=400, detail="invalid timestamp")

    if abs(time.time() - ts) > 300:
        raise HTTPException(status_code=401, detail="request expired")

    expected_sig = hmac.new(settings.webhook_secret, body + x_timestamp.encode(), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected_sig, x_signature):
        raise HTTPException(status_code=403, detail="invalid signature")

def sign_qr_payload(payload: Dict[str, Any]) -> Dict[str, Any]:
    canonical = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()
    return {**payload, "sig": hmac.new(settings.qr_secret, canonical, hashlib.sha256).hexdigest()}

@app.post("/payments/create", dependencies=[Depends(require_admin)])
async def create_payment(request: Request, amount: Decimal, db: sqlite3.Connection = Depends(get_db)):
    await enforce_rate_limit(request)
    
    if amount <= 0:
        raise HTTPException(status_code=400, detail="invalid amount")

    request_id = str(uuid.uuid4())
    amount_cents = int(amount * 100)
    expiry = datetime.now(timezone.utc) + timedelta(minutes=10)

    cursor = db.cursor()
    try:
        cursor.execute("BEGIN TRANSACTION")
        cursor.execute(
            "INSERT INTO payments (id, merchant_id, amount_cents, status, expires_at) VALUES (?, ?, ?, ?, ?)",
            (request_id, settings.merchant_id, amount_cents, "PENDING", expiry.isoformat())
        )
        cursor.execute(
            "INSERT INTO payment_events (payment_id, status, event_type) VALUES (?, ?, ?)",
            (request_id, "PENDING", "PAYMENT_CREATED")
        )
        db.commit()
    except Exception as e:
        db.rollback()
        logger.error(f"Failed to create payment: {e}")
        raise HTTPException(status_code=500, detail="internal error")

    qr_payload = sign_qr_payload({
        "domain": "MERCHANT_QR_V1",
        "request_id": request_id,
        "merchant_id": settings.merchant_id,
        "amount_cents": amount_cents,
        "expires_at": expiry.isoformat(),
        "nonce": secrets.token_hex(8)
    })

    img = qrcode.make(json.dumps(qr_payload))
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    
    return {
        "request_id": request_id,
        "amount": str(amount),
        "status": "PENDING",
        "expires_at": expiry.isoformat(),
        "qr_code_base64": f"data:image/png;base64,{base64.b64encode(buf.getvalue()).decode()}"
    }

@app.post("/payments/callback", dependencies=[Depends(verify_webhook_signature)])
async def payment_callback(
    request: Request, 
    cb: PaymentCallback, 
    x_event_id: str = Header(..., alias="X-Event-ID"),
    db: sqlite3.Connection = Depends(get_db)
):
    cursor = db.cursor()
    try:
        cursor.execute("BEGIN TRANSACTION")
        
        cursor.execute("SELECT 1 FROM processed_webhooks WHERE event_id = ?", (x_event_id,))
        if cursor.fetchone():
            return {"status": "ignored", "detail": "webhook already processed"}

        cursor.execute(
            "SELECT amount_cents, status, expires_at FROM payments WHERE id = ? AND merchant_id = ?", 
            (cb.payment_request_id, settings.merchant_id)
        )
        payment = cursor.fetchone()
        
        if not payment:
            raise HTTPException(status_code=404, detail="payment not found")

        if payment["status"] != "PENDING":
            cursor.execute("INSERT INTO processed_webhooks (event_id) VALUES (?)", (x_event_id,))
            db.commit()
            return {"status": "ignored", "detail": f"payment already in terminal state: {payment['status']}"}

        cb_amount_cents = int(cb.amount * 100)
        if cb_amount_cents != payment["amount_cents"]:
            logger.critical(f"Amount mismatch on {cb.payment_request_id}: expected {payment['amount_cents']}, got {cb_amount_cents}")
            raise HTTPException(status_code=400, detail="amount mismatch")

        if datetime.now(timezone.utc) > datetime.fromisoformat(payment["expires_at"]):
            new_status = "EXPIRED"
        else:
            new_status = cb.status if cb.status in ("SUCCESS", "FAILED") else "FAILED"

        cursor.execute("UPDATE payments SET status = ? WHERE id = ?", (new_status, cb.payment_request_id))
        cursor.execute(
            "INSERT INTO payment_events (payment_id, status, event_type) VALUES (?, ?, ?)",
            (cb.payment_request_id, new_status, "WEBHOOK_PROCESSED")
        )
        cursor.execute("INSERT INTO processed_webhooks (event_id) VALUES (?)", (x_event_id,))
        
        db.commit()
    except HTTPException:
        db.rollback()
        raise
    except Exception as e:
        db.rollback()
        logger.error(f"Callback processing failed: {e}")
        raise HTTPException(status_code=500, detail="internal error")

    return {"status": "accepted"}

@app.get("/payments/{request_id}")
async def get_payment_status(request: Request, request_id: str = Path(...), db: sqlite3.Connection = Depends(get_db)):
    await enforce_rate_limit(request)
    
    try:
        uuid.UUID(request_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="invalid request id")

    cursor = db.cursor()
    cursor.execute(
        "SELECT id, amount_cents, status, expires_at FROM payments WHERE id = ? AND merchant_id = ?",
        (request_id, settings.merchant_id)
    )
    payment = cursor.fetchone()

    if not payment:
        raise HTTPException(status_code=404, detail="payment not found")

    return {
        "id": payment["id"],
        "amount": str(Decimal(payment["amount_cents"]) / 100),
        "status": payment["status"],
        "expires_at": payment["expires_at"]
    }

@app.get("/health")
async def health_check():
    return {"status": "healthy", "timestamp": datetime.now(timezone.utc).isoformat()}
