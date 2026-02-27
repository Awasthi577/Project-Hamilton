import os
import uuid
import hmac
import hashlib
import logging
import sqlite3
from decimal import Decimal, getcontext
from datetime import datetime, timezone
from enum import Enum
from contextlib import contextmanager
from typing import Dict, List, Optional

from fastapi import FastAPI, HTTPException, Request, Depends, Header
from fastapi.security import APIKeyHeader
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.middleware.httpsredirect import HTTPSRedirectMiddleware
from pydantic import BaseModel, Field, validator

# MONEY SAFETY

getcontext().prec = 28 
# CONFIG

API_KEY_HASH = os.environ["BRIDGE_API_KEY_HASH"]
SIGNING_SECRET = os.environ["BRIDGE_SIGNING_SECRET"].encode()

ALLOWED_HOSTS = os.getenv("ALLOWED_HOSTS", "localhost").split(",")
ALLOWED_ORIGINS = os.getenv("ALLOWED_ORIGINS", "https://core.local").split(",")

DB_PATH = os.getenv("BRIDGE_DATABASE_URL", "bridge_state.db")

# LOGGING

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("bridge-secure")

# FASTAPI IS HERE

app = FastAPI(title="Liquidity Bridge Secure", version="2.0")

app.add_middleware(HTTPSRedirectMiddleware)

app.add_middleware(
    TrustedHostMiddleware,
    allowed_hosts=ALLOWED_HOSTS
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["POST", "GET"],
    allow_headers=["*"],
)

# SIZE LIMITER

@app.middleware("http")
async def limit_body(request: Request, call_next):
    body = await request.body()
    if len(body) > 1_000_000:
        raise HTTPException(413, "Payload too large")
    request._body = body
    return await call_next(request)

# DB

@contextmanager
def db():
    conn = sqlite3.connect(DB_PATH, isolation_level=None)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
    finally:
        conn.close()

def init_db():
    with db() as conn:
        c = conn.cursor()

        c.execute("""
        CREATE TABLE IF NOT EXISTS transactions(
            transaction_id TEXT PRIMARY KEY,
            bank_reference TEXT UNIQUE,
            type TEXT,
            account_id TEXT,
            amount TEXT,
            currency TEXT,
            status TEXT,
            timestamp TEXT
        )
        """)

        c.execute("""
        CREATE TABLE IF NOT EXISTS liquidity(
            currency TEXT PRIMARY KEY,
            total TEXT,
            available TEXT,
            locked TEXT
        )
        """)

init_db()


class Currency(str, Enum):
    INR = "INR"
    USD = "USD"

BALANCE_COLUMN = {
    Currency.INR: "inr_balance",
    Currency.USD: "usd_balance",
}

# MODELS ?

class MintRequest(BaseModel):
    account_id: str
    amount: Decimal = Field(..., gt=0)
    currency: Currency
    bank_reference: str

class BurnRequest(BaseModel):
    account_id: str
    token_ids: List[str]
    currency: Currency
    amount: Decimal
    bank_reference: str

    @validator("token_ids")
    def validate_tokens(cls, v):
        for t in v:
            uuid.UUID(t)
        return v

# SECURITY ?

api_key_header = APIKeyHeader(name="X-API-Key")

def sha256(x: str):
    return hashlib.sha256(x.encode()).hexdigest()

def verify_api_key(key: str = Depends(api_key_header)):
    if not hmac.compare_digest(sha256(key), API_KEY_HASH):
        raise HTTPException(401, "Unauthorized")

# ---------- Signed Request Verification ----------

async def verify_signature(
    request: Request,
    x_signature: str = Header(...),
    x_timestamp: str = Header(...)
):
    body = await request.body()

    ts = datetime.fromtimestamp(int(x_timestamp), tz=timezone.utc)

    if abs((datetime.now(timezone.utc) - ts).total_seconds()) > 300:
        raise HTTPException(401, "Expired request")

    expected = hmac.new(
        SIGNING_SECRET,
        body + x_timestamp.encode(),
        hashlib.sha256
    ).hexdigest()

    if not hmac.compare_digest(expected, x_signature):
        raise HTTPException(403, "Invalid signature")

# =====================================================
# RATE LIMIT
# =====================================================

RATE_BUCKET: Dict[str, int] = {}

def rate_limit(request: Request):
    ip = request.headers.get("x-forwarded-for", request.client.host)
    RATE_BUCKET[ip] = RATE_BUCKET.get(ip, 0) + 1
    if RATE_BUCKET[ip] > 60:
        raise HTTPException(429, "Too many requests")

# =====================================================
# LEDGER INVARIANT
# =====================================================

def verify_liquidity_invariant(conn, currency: Currency):
    c = conn.cursor()
    c.execute("SELECT total,available,locked FROM liquidity WHERE currency=?",(currency,))
    row = c.fetchone()
    if not row:
        return
    total = Decimal(row["total"])
    if total != Decimal(row["available"]) + Decimal(row["locked"]):
        raise RuntimeError("Liquidity invariant violated")

# =====================================================
# ENDPOINTS
# =====================================================

@app.post("/mint",
    dependencies=[Depends(verify_api_key), Depends(verify_signature)]
)
def mint(req: MintRequest):

    tx_id = str(uuid.uuid4())

    with db() as conn:
        c = conn.cursor()
        c.execute("BEGIN IMMEDIATE")

        # idempotency check
        c.execute(
            "SELECT 1 FROM transactions WHERE bank_reference=?",
            (req.bank_reference,)
        )
        if c.fetchone():
            raise HTTPException(409, "Duplicate request")

        c.execute(
            "INSERT INTO transactions VALUES (?,?,?,?,?,?,?,?)",
            (
                tx_id,
                req.bank_reference,
                "mint",
                req.account_id,
                str(req.amount),
                req.currency.value,
                "COMPLETED",
                datetime.now(timezone.utc).isoformat()
            )
        )

        verify_liquidity_invariant(conn, req.currency)

        conn.commit()

    return {"transaction_id": tx_id, "status": "COMPLETED"}

# -----------------------------------------------------

@app.post("/burn",
    dependencies=[Depends(verify_api_key), Depends(verify_signature)]
)
def burn(req: BurnRequest):

    tx_id = str(uuid.uuid4())

    with db() as conn:
        c = conn.cursor()
        c.execute("BEGIN IMMEDIATE")

        c.execute(
            "SELECT 1 FROM transactions WHERE bank_reference=?",
            (req.bank_reference,)
        )
        if c.fetchone():
            raise HTTPException(409, "Duplicate request")

        verify_liquidity_invariant(conn, req.currency)

        c.execute(
            "INSERT INTO transactions VALUES (?,?,?,?,?,?,?,?)",
            (
                tx_id,
                req.bank_reference,
                "burn",
                req.account_id,
                str(req.amount),
                req.currency.value,
                "COMPLETED",
                datetime.now(timezone.utc).isoformat()
            )
        )

        conn.commit()

    return {"transaction_id": tx_id, "status": "COMPLETED"}

# -----------------------------------------------------

@app.get("/health")
def health():
    return {"status": "ok"}
