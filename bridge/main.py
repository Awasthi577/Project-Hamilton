import os
import uuid
import hmac
import time
import sqlite3
import hashlib
import logging
from decimal import Decimal, getcontext
from datetime import datetime, timezone
from typing import List

from fastapi import FastAPI, Request, HTTPException, Depends, Header
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.security import APIKeyHeader
from pydantic import BaseModel, Field, validator



getcontext().prec = 28


# ---- configuration ----

API_KEY_HASH = os.environ["BRIDGE_API_KEY_HASH"]
SIGNING_SECRET = os.environ["BRIDGE_SIGNING_SECRET"].encode()

DB_PATH = os.getenv("BRIDGE_DATABASE_URL", "bridge_state.db")
ALLOWED_HOSTS = os.getenv("ALLOWED_HOSTS", "localhost").split(",")
ALLOWED_ORIGINS = os.getenv("ALLOWED_ORIGINS", "https://core.local").split(",")

MAX_BODY = 1_000_000
MAX_DRIFT_SECONDS = 300
RATE_LIMIT = 60
RATE_WINDOW = 60


# ---- logging ----

logging.basicConfig(level=logging.INFO)
log = logging.getLogger("bridge")


# ---- database ----

def connect():
    conn = sqlite3.connect(DB_PATH, isolation_level=None)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def init_db():
    with connect() as db:
        db.executescript(
            """
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
            """
        )


init_db()


# ---- app ----

app = FastAPI(title="Liquidity Bridge")


app.add_middleware(
    TrustedHostMiddleware,
    allowed_hosts=ALLOWED_HOSTS,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_methods=["POST", "GET"],
    allow_headers=["*"],
    allow_credentials=True,
)


# ---- request limit guard ----

@app.middleware("http")
async def body_guard(request: Request, call_next):
    body = await request.body()
    if len(body) > MAX_BODY:
        raise HTTPException(413, "payload too large")
    request.state.raw_body = body
    return await call_next(request)


# ---- models ----

class MintRequest(BaseModel):
    account_id: str
    amount: Decimal = Field(..., gt=0)
    currency: str
    bank_reference: str


class BurnRequest(BaseModel):
    account_id: str
    token_ids: List[str]
    currency: str
    amount: Decimal
    bank_reference: str

    @validator("token_ids")
    def validate_tokens(cls, v):
        for t in v:
            uuid.UUID(t)
        return v


# ---- helpers ----

def sha256(x: str) -> str:
    return hashlib.sha256(x.encode()).hexdigest()


def now():
    return datetime.now(timezone.utc).isoformat()


# ---- api key auth ----

api_key = APIKeyHeader(name="X-API-Key")


def require_api_key(key: str = Depends(api_key)):
    if not hmac.compare_digest(sha256(key), API_KEY_HASH):
        raise HTTPException(401, "unauthorized")


# ---- signature verification ----

async def verify_signature(
    request: Request,
    x_signature: str = Header(...),
    x_timestamp: str = Header(...)
):
    try:
        ts = int(x_timestamp)
    except Exception:
        raise HTTPException(400, "invalid timestamp")

    if abs(time.time() - ts) > MAX_DRIFT_SECONDS:
        raise HTTPException(401, "request expired")

    body = request.state.raw_body

    canonical = (
        request.method.encode()
        + request.url.path.encode()
        + body
        + x_timestamp.encode()
    )

    expected = hmac.new(
        SIGNING_SECRET,
        canonical,
        hashlib.sha256,
    ).hexdigest()

    if not hmac.compare_digest(expected, x_signature):
        raise HTTPException(403, "bad signature")

    with connect() as db:
        try:
            db.execute(
                "INSERT INTO replay_protection VALUES (?,?)",
                (x_signature, ts),
            )
        except sqlite3.IntegrityError:
            raise HTTPException(409, "replay detected")


# ---- rate limiting ----

def enforce_rate_limit(request: Request):
    ip = request.headers.get("x-forwarded-for") or request.client.host
    cutoff = int(time.time()) - RATE_WINDOW

    with connect() as db:
        db.execute("DELETE FROM rate_limit WHERE ts < ?", (cutoff,))
        db.execute(
            "INSERT INTO rate_limit VALUES (?,?)",
            (ip, int(time.time())),
        )

        count = db.execute(
            "SELECT COUNT(*) c FROM rate_limit WHERE ip=?",
            (ip,),
        ).fetchone()["c"]

    if count > RATE_LIMIT:
        raise HTTPException(429, "rate limit exceeded")


# ---- liquidity invariant ----

def assert_liquidity(db, currency: str):
    row = db.execute(
        "SELECT total,available,locked FROM liquidity WHERE currency=?",
        (currency,),
    ).fetchone()

    if not row:
        return

    total = Decimal(row["total"])
    available = Decimal(row["available"])
    locked = Decimal(row["locked"])

    if total != available + locked:
        raise RuntimeError("liquidity invariant failure")


def adjust_liquidity(db, currency: str, delta: Decimal):
    row = db.execute(
        "SELECT * FROM liquidity WHERE currency=?",
        (currency,),
    ).fetchone()

    if not row:
        db.execute(
            "INSERT INTO liquidity VALUES (?,?,?,?)",
            (currency, str(delta), str(delta), "0"),
        )
        return

    total = Decimal(row["total"]) + delta
    available = Decimal(row["available"]) + delta

    if available < 0:
        raise HTTPException(400, "insufficient liquidity")

    db.execute(
        """
        UPDATE liquidity
        SET total=?, available=?
        WHERE currency=?
        """,
        (str(total), str(available), currency),
    )


# ---- endpoints ----

@app.post(
    "/mint",
    dependencies=[
        Depends(require_api_key),
        Depends(verify_signature),
    ],
)
def mint(req: MintRequest, request: Request):

    enforce_rate_limit(request)

    tx_id = str(uuid.uuid4())

    with connect() as db:
        db.execute("BEGIN IMMEDIATE")

        exists = db.execute(
            "SELECT 1 FROM transactions WHERE bank_reference=?",
            (req.bank_reference,),
        ).fetchone()

        if exists:
            raise HTTPException(409, "duplicate")

        adjust_liquidity(db, req.currency, req.amount)
        assert_liquidity(db, req.currency)

        db.execute(
            "INSERT INTO transactions VALUES (?,?,?,?,?,?,?,?)",
            (
                tx_id,
                req.bank_reference,
                "mint",
                req.account_id,
                str(req.amount),
                req.currency,
                "COMPLETED",
                now(),
            ),
        )

        db.commit()

    return {"transaction_id": tx_id, "status": "COMPLETED"}


@app.post(
    "/burn",
    dependencies=[
        Depends(require_api_key),
        Depends(verify_signature),
    ],
)
def burn(req: BurnRequest, request: Request):

    enforce_rate_limit(request)

    tx_id = str(uuid.uuid4())

    with connect() as db:
        db.execute("BEGIN IMMEDIATE")

        exists = db.execute(
            "SELECT 1 FROM transactions WHERE bank_reference=?",
            (req.bank_reference,),
        ).fetchone()

        if exists:
            raise HTTPException(409, "duplicate")

        adjust_liquidity(db, req.currency, -req.amount)
        assert_liquidity(db, req.currency)

        db.execute(
            "INSERT INTO transactions VALUES (?,?,?,?,?,?,?,?)",
            (
                tx_id,
                req.bank_reference,
                "burn",
                req.account_id,
                str(req.amount),
                req.currency,
                "COMPLETED",
                now(),
            ),
        )

        db.commit()

    return {"transaction_id": tx_id, "status": "COMPLETED"}


@app.get("/health")
def health():
    return {"status": "ok"}
