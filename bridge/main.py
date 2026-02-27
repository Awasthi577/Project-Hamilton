import os
import uuid
import hmac
import time
import sqlite3
import hashlib
import logging
from decimal import Decimal
from datetime import datetime, timezone
from typing import List, Literal

from fastapi import FastAPI, Request, HTTPException, Depends, Header
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.security import APIKeyHeader
from pydantic import BaseModel, Field, field_validator

# ---- Configuration ----
API_KEY_HASH = os.environ.get("BRIDGE_API_KEY_HASH", "mock_hash")
SIGNING_SECRET = os.environ.get("BRIDGE_SIGNING_SECRET", "mock_secret").encode()
DB_PATH = os.getenv("BRIDGE_DATABASE_URL", "bridge_state.db")
ALLOWED_HOSTS = os.getenv("ALLOWED_HOSTS", "localhost").split(",")
ALLOWED_ORIGINS = os.getenv("ALLOWED_ORIGINS", "http://localhost").split(",")

MAX_BODY = 1_000_000
MAX_DRIFT_SECONDS = 300
RATE_LIMIT = 60
RATE_WINDOW = 60

# ---- Logging ----
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("bridge")

# ---- Database Setup ----
def init_db():
    with sqlite3.connect(DB_PATH) as db:
        db.executescript(
            """
            PRAGMA journal_mode=WAL;
            CREATE TABLE IF NOT EXISTS transactions(
                transaction_id TEXT PRIMARY KEY,
                bank_reference TEXT UNIQUE,
                type TEXT,
                account_id TEXT,
                amount TEXT,
                currency TEXT,
                status TEXT,
                created_at TEXT
            );
            CREATE TABLE IF NOT EXISTS liquidity(
                currency TEXT PRIMARY KEY,
                total TEXT,
                available TEXT,
                locked TEXT
            );
            CREATE TABLE IF NOT EXISTS replay_protection(
                signature TEXT PRIMARY KEY,
                created_at INTEGER
            );
            CREATE TABLE IF NOT EXISTS rate_limit(
                ip TEXT,
                ts INTEGER
            );
            CREATE INDEX IF NOT EXISTS idx_rate_limit_ip_ts ON rate_limit(ip, ts);
            """
        )

init_db()

# ---- Dependency Injection ----
def get_db():
    """Yields a properly managed database connection."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
    finally:
        conn.close()

# ---- App Initialization ----
app = FastAPI(title="Liquidity Bridge")

app.add_middleware(TrustedHostMiddleware, allowed_hosts=ALLOWED_HOSTS)
app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_methods=["POST", "GET"],
    allow_headers=["*"],
)

# ---- Middleware ----
@app.middleware("http")
async def body_guard(request: Request, call_next):
    body = await request.body()
    if len(body) > MAX_BODY:
        raise HTTPException(413, "Payload too large")
    request.state.raw_body = body
    return await call_next(request)

# ---- Models (Pydantic V2) ----
class MintRequest(BaseModel):
    account_id: str
    amount: Decimal = Field(..., gt=0)
    currency: str
    bank_reference: str

class BurnRequest(BaseModel):
    account_id: str
    token_ids: List[str]
    currency: str
    amount: Decimal = Field(..., gt=0)
    bank_reference: str

    @field_validator("token_ids")
    @classmethod
    def validate_tokens(cls, v):
        for t in v:
            uuid.UUID(t) 
        return v

# ---- Security Dependencies ----
api_key_header = APIKeyHeader(name="X-API-Key")

def verify_api_key(key: str = Depends(api_key_header)):
    key_hash = hashlib.sha256(key.encode()).hexdigest()
    if not hmac.compare_digest(key_hash, API_KEY_HASH):
        raise HTTPException(401, "Unauthorized")

def check_rate_limit(request: Request, db: sqlite3.Connection = Depends(get_db)):
    """Enforce rate limits before expensive cryptography."""
    ip = request.headers.get("x-forwarded-for", request.client.host)
    current_time = int(time.time())
    cutoff = current_time - RATE_WINDOW

    
    db.execute("INSERT INTO rate_limit (ip, ts) VALUES (?, ?)", (ip, current_time))
    
    if current_time % 20 == 0:
        db.execute("DELETE FROM rate_limit WHERE ts < ?", (cutoff,))
    
    count = db.execute(
        "SELECT COUNT(*) as count FROM rate_limit WHERE ip=? AND ts >= ?", 
        (ip, cutoff)
    ).fetchone()["count"]

    db.commit()

    if count > RATE_LIMIT:
        raise HTTPException(429, "Rate limit exceeded")

async def verify_signature(
    request: Request,
    db: sqlite3.Connection = Depends(get_db),
    x_signature: str = Header(...),
    x_timestamp: str = Header(...)
):
    try:
        ts = int(x_timestamp)
    except ValueError:
        raise HTTPException(400, "Invalid timestamp")

    if abs(time.time() - ts) > MAX_DRIFT_SECONDS:
        raise HTTPException(401, "Request expired")

    canonical = request.method.encode() + request.url.path.encode() + request.state.raw_body + x_timestamp.encode()
    expected = hmac.new(SIGNING_SECRET, canonical, hashlib.sha256).hexdigest()

    if not hmac.compare_digest(expected, x_signature):
        raise HTTPException(403, "Bad signature")

    try:
        db.execute("INSERT INTO replay_protection VALUES (?,?)", (x_signature, ts))
        db.commit()
    except sqlite3.IntegrityError:
        raise HTTPException(409, "Replay detected")

# ---- Core Business Logic ----
def process_liquidity_transaction(
    db: sqlite3.Connection, 
    req: MintRequest | BurnRequest, 
    tx_type: Literal["mint", "burn"]
) -> str:
    """Consolidated transactional logic for both mints and burns."""
    tx_id = str(uuid.uuid4())
    delta = req.amount if tx_type == "mint" else -req.amount

    try:
        db.execute("BEGIN IMMEDIATE")

        # Duplicate check
        if db.execute("SELECT 1 FROM transactions WHERE bank_reference=?", (req.bank_reference,)).fetchone():
            raise HTTPException(409, "Duplicate transaction")

        # Adjust Liquidity
        row = db.execute("SELECT total, available FROM liquidity WHERE currency=?", (req.currency,)).fetchone()
        
        if not row:
            if tx_type == "burn":
                raise HTTPException(400, "Insufficient liquidity")
            db.execute(
                "INSERT INTO liquidity (currency, total, available, locked) VALUES (?, ?, ?, ?)",
                (req.currency, str(delta), str(delta), "0")
            )
        else:
            new_total = Decimal(row["total"]) + delta
            new_available = Decimal(row["available"]) + delta

            if new_available < 0:
                raise HTTPException(400, "Insufficient liquidity")

            db.execute(
                "UPDATE liquidity SET total=?, available=? WHERE currency=?",
                (str(new_total), str(new_available), req.currency)
            )

        # Record Transaction
        db.execute(
            "INSERT INTO transactions VALUES (?,?,?,?,?,?,?,?)",
            (tx_id, req.bank_reference, tx_type, req.account_id, str(req.amount), req.currency, "COMPLETED", datetime.now(timezone.utc).isoformat())
        )
        db.commit()
        return tx_id

    except Exception as e:
        db.rollback()
        logger.error(f"Transaction failed: {str(e)}")
        raise

# ---- Endpoints ----
@app.post(
    "/mint",
    dependencies=[Depends(verify_api_key), Depends(check_rate_limit), Depends(verify_signature)]
)
def mint_endpoint(req: MintRequest, db: sqlite3.Connection = Depends(get_db)):
    tx_id = process_liquidity_transaction(db, req, "mint")
    return {"transaction_id": tx_id, "status": "COMPLETED"}

@app.post(
    "/burn",
    dependencies=[Depends(verify_api_key), Depends(check_rate_limit), Depends(verify_signature)]
)
def burn_endpoint(req: BurnRequest, db: sqlite3.Connection = Depends(get_db)):
    tx_id = process_liquidity_transaction(db, req, "burn")
    return {"transaction_id": tx_id, "status": "COMPLETED"}

@app.get("/health")
def health():
    return {"status": "ok"}
