import os
import json
import hmac
import time
import uuid
import sqlite3
import logging
from decimal import Decimal, ROUND_DOWN
from datetime import datetime, timezone
from typing import Dict, List, Any, Annotated
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request, HTTPException, Depends, Header
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from pydantic.functional_validators import AfterValidator
import redis.asyncio as aioredis
from nacl.signing import VerifyKey
from nacl.exceptions import BadSignatureError

DB_PATH = os.getenv("DB_PATH", "hamilton_ledger.db")
MAX_REQUEST_SIZE = 512_000
DOMAIN_PREFIX_TX = b"HAMILTON_CORE_TX_V1:"
DOMAIN_PREFIX_BURN = b"HAMILTON_CORE_BURN_V1:"

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger("hamilton")

class Settings(BaseModel):
    redis_url: str = Field(default_factory=lambda: os.getenv("REDIS_URL", "redis://localhost:6379/0"))
    allowed_origins: List[str] = Field(
        default_factory=lambda: os.getenv("ALLOWED_ORIGINS", "https://wallet.hamilton.finance").split(",")
    )
    replay_window: int = 30
    rate_limit: int = 120

settings = Settings()

def _quantize(v: Decimal) -> Decimal:
    return v.quantize(Decimal("0.01"), rounding=ROUND_DOWN)

MoneyAmount = Annotated[Decimal, Field(gt=0), AfterValidator(_quantize)]

class TxOutput(BaseModel):
    token_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    amount: MoneyAmount
    receiver_public_key: str

class Transaction(BaseModel):
    transaction_id: str
    currency: str
    inputs: List[str] = Field(..., min_length=1)
    outputs: List[TxOutput] = Field(..., min_length=1)
    signer_public_key: str
    signature: str

class MintRequest(BaseModel):
    amount: MoneyAmount
    currency: str
    public_key: str

class BurnRequest(BaseModel):
    token_ids: List[str] = Field(..., min_length=1)
    owner_public_key: str
    signature: str

def init_db():
    with sqlite3.connect(DB_PATH) as conn:
        conn.executescript("""
            PRAGMA journal_mode=WAL;
            CREATE TABLE IF NOT EXISTS clients (
                client_id TEXT PRIMARY KEY,
                secret TEXT,
                role TEXT
            );
            CREATE TABLE IF NOT EXISTS utxos (
                token_id TEXT PRIMARY KEY,
                amount TEXT,
                currency TEXT,
                owner_public_key TEXT,
                status TEXT
            );
            CREATE TABLE IF NOT EXISTS ledger_audit (
                seq INTEGER PRIMARY KEY AUTOINCREMENT,
                tx_id TEXT,
                action TEXT,
                payload TEXT,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE IF NOT EXISTS idempotency (
                client_id TEXT,
                idem_key TEXT,
                status_code INTEGER,
                response TEXT,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                PRIMARY KEY (client_id, idem_key)
            );
        """)
        conn.execute(
            "INSERT OR IGNORE INTO clients (client_id, secret, role) VALUES (?, ?, ?), (?, ?, ?)",
            ("liquidity-bridge", os.getenv("CLIENT_SECRET_BRIDGE", "mock_bridge_secret"), "ISSUER",
             "wallet-service", os.getenv("CLIENT_SECRET_WALLET", "mock_wallet_secret"), "PROCESSOR")
        )

def get_db():
    conn = sqlite3.connect(DB_PATH, isolation_level=None, timeout=10.0)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
    finally:
        conn.close()

@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    redis = aioredis.from_url(settings.redis_url, decode_responses=True)
    app.state.redis = redis
    await redis.ping()
    yield
    await redis.close()

app = FastAPI(lifespan=lifespan, title="Hamilton Core")

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.allowed_origins,
    allow_methods=["POST", "GET"],
    allow_headers=["*"],
)

@app.middleware("http")
async def limit_body_size(request: Request, call_next):
    cl = request.headers.get("content-length")
    if cl and int(cl) > MAX_REQUEST_SIZE:
        return JSONResponse({"detail": "Payload too large"}, status_code=413)
    return await call_next(request)

async def authenticate(
    request: Request,
    db: sqlite3.Connection = Depends(get_db),
    x_client_id: str = Header(...),
    x_signature: str = Header(...),
    x_timestamp: str = Header(...)
) -> None:
    try:
        ts = int(x_timestamp)
    except ValueError:
        raise HTTPException(400, "Invalid timestamp")

    if abs(int(time.time()) - ts) > settings.replay_window:
        raise HTTPException(401, "Request expired")

    client = db.execute("SELECT secret, role FROM clients WHERE client_id = ?", (x_client_id,)).fetchone()
    if not client:
        raise HTTPException(401, "Unknown client")

    body = await request.body()
    payload = request.method.encode() + request.url.path.encode() + body + x_timestamp.encode()
    expected = hmac.new(client["secret"].encode(), payload, "sha256").hexdigest()

    if not hmac.compare_digest(expected, x_signature):
        raise HTTPException(401, "Invalid signature")

    request.state.client_id = x_client_id
    request.state.client_role = client["role"]

class RequireRole:
    def __init__(self, role: str):
        self.role = role
    def __call__(self, request: Request):
        if getattr(request.state, "client_role", None) != self.role:
            raise HTTPException(403, "Forbidden")

async def rate_limit(request: Request):
    redis: aioredis.Redis = request.app.state.redis
    cid = getattr(request.state, "client_id", "anon")
    key = f"rl:{cid}:{int(time.time() // 60)}"
    if await redis.incr(key) == 1:
        await redis.expire(key, 60)
    if int(await redis.get(key)) > settings.rate_limit:
        raise HTTPException(429, "Rate limit exceeded")

def canonicalize(data: Dict[str, Any]) -> bytes:
    return json.dumps(data, sort_keys=True, separators=(",", ":")).encode("utf-8")

def verify_sig(pubkey: str, message: bytes, signature: str, domain: bytes):
    try:
        VerifyKey(bytes.fromhex(pubkey)).verify(domain + message, bytes.fromhex(signature))
    except (BadSignatureError, ValueError):
        raise HTTPException(400, "Cryptographic signature verification failed")

def check_idempotency(db: sqlite3.Connection, client_id: str, idem_key: str):
    row = db.execute("SELECT status_code, response FROM idempotency WHERE client_id=? AND idem_key=?", 
                     (client_id, idem_key)).fetchone()
    if row:
        return JSONResponse(status_code=row["status_code"], content=json.loads(row["response"]))
    return None

def save_idempotency(db: sqlite3.Connection, client_id: str, idem_key: str, status: int, response: dict):
    db.execute("INSERT INTO idempotency (client_id, idem_key, status_code, response) VALUES (?, ?, ?, ?)",
               (client_id, idem_key, status, json.dumps(response)))

@app.post("/transactions/process", dependencies=[Depends(authenticate), Depends(rate_limit)])
async def process_tx(request: Request, tx: Transaction, db: sqlite3.Connection = Depends(get_db), x_idem: str = Header(...)):
    if cached := check_idempotency(db, request.state.client_id, x_idem):
        return cached

    tx_data = tx.model_dump(mode="json", exclude={"signature"})
    verify_sig(tx.signer_public_key, canonicalize(tx_data), tx.signature, DOMAIN_PREFIX_TX)

    try:
        db.execute("BEGIN IMMEDIATE")
        
        in_sum = Decimal("0.00")
        for tid in tx.inputs:
            row = db.execute("SELECT amount, currency, status, owner_public_key FROM utxos WHERE token_id=?", (tid,)).fetchone()
            if not row or row["status"] != "UNSPENT":
                raise ValueError(f"Invalid or spent input: {tid}")
            if row["currency"] != tx.currency:
                raise ValueError(f"Currency mismatch on input: {tid}")
            if row["owner_public_key"] != tx.signer_public_key:
                raise ValueError(f"Unauthorized input spend: {tid}")
            in_sum += Decimal(row["amount"])
            db.execute("UPDATE utxos SET status='SPENT' WHERE token_id=?", (tid,))

        out_sum = sum(out.amount for out in tx.outputs)
        if in_sum != out_sum:
            raise ValueError(f"Value conservation failed: {in_sum} != {out_sum}")

        for out in tx.outputs:
            db.execute("INSERT INTO utxos (token_id, amount, currency, owner_public_key, status) VALUES (?, ?, ?, ?, 'UNSPENT')",
                       (out.token_id, str(out.amount), tx.currency, out.receiver_public_key))

        db.execute("INSERT INTO ledger_audit (tx_id, action, payload) VALUES (?, ?, ?)",
                   (tx.transaction_id, "TRANSFER", json.dumps(tx_data)))

        res = {"status": "COMPLETED", "transaction_id": tx.transaction_id}
        save_idempotency(db, request.state.client_id, x_idem, 200, res)
        db.execute("COMMIT")
        return res

    except ValueError as e:
        db.execute("ROLLBACK")
        raise HTTPException(400, str(e))
    except Exception:
        db.execute("ROLLBACK")
        raise

@app.post("/tokens/mint", dependencies=[Depends(authenticate), Depends(RequireRole("ISSUER")), Depends(rate_limit)])
async def mint_tokens(request: Request, mint: MintRequest, db: sqlite3.Connection = Depends(get_db), x_idem: str = Header(...)):
    if cached := check_idempotency(db, request.state.client_id, x_idem):
        return cached

    tid = str(uuid.uuid4())
    try:
        db.execute("BEGIN IMMEDIATE")
        db.execute("INSERT INTO utxos (token_id, amount, currency, owner_public_key, status) VALUES (?, ?, ?, ?, 'UNSPENT')",
                   (tid, str(mint.amount), mint.currency, mint.public_key))
        db.execute("INSERT INTO ledger_audit (tx_id, action, payload) VALUES (?, ?, ?)",
                   (tid, "MINT", json.dumps(mint.model_dump(mode="json"))))
        
        res = {"status": "COMPLETED", "token_id": tid}
        save_idempotency(db, request.state.client_id, x_idem, 200, res)
        db.execute("COMMIT")
        return res
    except Exception:
        db.execute("ROLLBACK")
        raise

@app.post("/tokens/burn", dependencies=[Depends(authenticate), Depends(rate_limit)])
async def burn_tokens(request: Request, burn: BurnRequest, db: sqlite3.Connection = Depends(get_db), x_idem: str = Header(...)):
    if cached := check_idempotency(db, request.state.client_id, x_idem):
        return cached

    b_data = burn.model_dump(mode="json", exclude={"signature"})
    verify_sig(burn.owner_public_key, canonicalize(b_data), burn.signature, DOMAIN_PREFIX_BURN)

    try:
        db.execute("BEGIN IMMEDIATE")
        for tid in burn.token_ids:
            row = db.execute("SELECT status, owner_public_key FROM utxos WHERE token_id=?", (tid,)).fetchone()
            if not row or row["status"] != "UNSPENT":
                raise ValueError(f"Invalid or spent token: {tid}")
            if row["owner_public_key"] != burn.owner_public_key:
                raise ValueError(f"Unauthorized burn attempt: {tid}")
            db.execute("UPDATE utxos SET status='BURNED' WHERE token_id=?", (tid,))
            
        db.execute("INSERT INTO ledger_audit (tx_id, action, payload) VALUES (?, ?, ?)",
                   (str(uuid.uuid4()), "BURN", json.dumps(b_data)))

        res = {"status": "COMPLETED", "burned_count": len(burn.token_ids)}
        save_idempotency(db, request.state.client_id, x_idem, 200, res)
        db.execute("COMMIT")
        return res
    except ValueError as e:
        db.execute("ROLLBACK")
        raise HTTPException(400, str(e))
    except Exception:
        db.execute("ROLLBACK")
        raise

@app.get("/health/internal")
async def health(db: sqlite3.Connection = Depends(get_db)):
    db.execute("SELECT 1")
    return {"status": "healthy", "timestamp": datetime.now(timezone.utc).isoformat()}
