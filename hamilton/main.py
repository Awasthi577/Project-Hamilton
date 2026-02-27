import os
import json
import hmac
import time
import uuid
import sqlite3
import logging
import hashlib
from decimal import Decimal, ROUND_DOWN, InvalidOperation
from datetime import datetime, timezone
from typing import Optional

import redis.asyncio as aioredis
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request, HTTPException, Depends, Header
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field, field_validator
from nacl.signing import VerifyKey
from nacl.exceptions import BadSignatureError


DB_PATH  = os.getenv("DB_PATH", "ledger.db")
REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")


_bridge_secret = os.getenv("CLIENT_SECRET_BRIDGE")
_wallet_secret = os.getenv("CLIENT_SECRET_WALLET")
if not _bridge_secret or not _wallet_secret:
    raise RuntimeError("CLIENT_SECRET_BRIDGE and CLIENT_SECRET_WALLET must be set")

ALLOWED_ORIGINS = os.getenv(
    "ALLOWED_ORIGINS", "https://wallet.hamilton.finance"
).split(",")

MAX_BODY   = 512_000
RL_LIMIT   = 120          
TS_WINDOW  = 30           

SIG_PREFIX_TX   = b"HAMILTON_CORE_TX_V1:"
SIG_PREFIX_BURN = b"HAMILTON_CORE_BURN_V1:"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s [%(name)s] %(message)s",
)
log = logging.getLogger("hamilton")


def _get_conn() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, isolation_level=None, timeout=10.0)
    conn.row_factory = sqlite3.Row
    return conn


def get_db():
    conn = _get_conn()
    try:
        yield conn
    finally:
        conn.close()


def init_db():
    conn = _get_conn()
    try:
        conn.executescript("""
            PRAGMA journal_mode=WAL;

            CREATE TABLE IF NOT EXISTS clients (
                client_id   TEXT PRIMARY KEY,
                secret_hash TEXT NOT NULL,
                role        TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS utxos (
                token_id         TEXT PRIMARY KEY,
                amount           TEXT NOT NULL,
                currency         TEXT NOT NULL,
                owner_public_key TEXT NOT NULL,
                status           TEXT NOT NULL DEFAULT 'UNSPENT',
                created_at       DATETIME DEFAULT CURRENT_TIMESTAMP
            );

            -- append-only audit trail, never update rows here
            CREATE TABLE IF NOT EXISTS ledger_audit (
                seq        INTEGER PRIMARY KEY AUTOINCREMENT,
                tx_id      TEXT NOT NULL,
                action     TEXT NOT NULL,
                payload    TEXT NOT NULL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            );

            CREATE TABLE IF NOT EXISTS idempotency_cache (
                client_id   TEXT NOT NULL,
                idem_key    TEXT NOT NULL,
                status_code INTEGER NOT NULL,
                response    TEXT NOT NULL,
                created_at  DATETIME DEFAULT CURRENT_TIMESTAMP,
                PRIMARY KEY (client_id, idem_key)
            );
        """)

        for cid, secret, role in [
            ("liquidity-bridge", _bridge_secret, "ISSUER"),
            ("wallet-service",   _wallet_secret, "PROCESSOR"),
        ]:
            h = _hash_secret(secret)
            conn.execute(
                "INSERT OR IGNORE INTO clients (client_id, secret_hash, role) VALUES (?,?,?)",
                (cid, h, role),
            )
    finally:
        conn.close()


def _hash_secret(s: str) -> str:
    return hashlib.sha256(s.encode()).hexdigest()

def _to_decimal(v) -> Decimal:
    """coerce to Decimal and truncate to 2dp, raise ValueError on garbage"""
    try:
        d = Decimal(str(v))
    except InvalidOperation:
        raise ValueError(f"invalid amount: {v!r}")
    if d <= 0:
        raise ValueError("amount must be positive")
    return d.quantize(Decimal("0.01"), rounding=ROUND_DOWN)


class TxOut(BaseModel):
    token_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    amount: Decimal
    receiver_public_key: str

    @field_validator("amount", mode="before")
    @classmethod
    def coerce_amount(cls, v):
        return _to_decimal(v)

    @field_validator("receiver_public_key")
    @classmethod
    def check_pubkey(cls, v):
        _validate_hex(v, 64, "receiver_public_key")  # 32-byte ed25519
        return v


class TxRequest(BaseModel):
    transaction_id: str
    currency: str
    inputs: list[str] = Field(..., min_length=1)
    outputs: list[TxOut] = Field(..., min_length=1)
    signer_public_key: str
    signature: str

    @field_validator("signer_public_key")
    @classmethod
    def check_signer(cls, v):
        _validate_hex(v, 64, "signer_public_key")
        return v

    @field_validator("signature")
    @classmethod
    def check_sig_fmt(cls, v):
        _validate_hex(v, 128, "signature")  # 64-byte ed25519 sig
        return v


class MintReq(BaseModel):
    amount: Decimal
    currency: str
    public_key: str

    @field_validator("amount", mode="before")
    @classmethod
    def coerce_amount(cls, v):
        return _to_decimal(v)

    @field_validator("public_key")
    @classmethod
    def check_pk(cls, v):
        _validate_hex(v, 64, "public_key")
        return v


class BurnReq(BaseModel):
    token_ids: list[str] = Field(..., min_length=1)
    owner_public_key: str
    signature: str

    @field_validator("owner_public_key")
    @classmethod
    def check_pk(cls, v):
        _validate_hex(v, 64, "owner_public_key")
        return v

    @field_validator("signature")
    @classmethod
    def check_sig(cls, v):
        _validate_hex(v, 128, "signature")
        return v


def _validate_hex(val: str, expected_len: int, field: str):
    """explicit hex format + length check before we touch nacl"""
    if len(val) != expected_len:
        raise ValueError(f"{field}: expected {expected_len} hex chars, got {len(val)}")
    try:
        bytes.fromhex(val)
    except ValueError:
        raise ValueError(f"{field}: not valid hex")


def _verify_ed25519(pubkey_hex: str, msg: bytes, sig_hex: str, prefix: bytes):
    try:
        vk = VerifyKey(bytes.fromhex(pubkey_hex))
        vk.verify(prefix + msg, bytes.fromhex(sig_hex))
    except BadSignatureError:
        raise HTTPException(400, "signature verification failed")
    # ValueError/etc shouldn't happen here since we pre-validated hex above,
    # but just in case
    except Exception as exc:
        log.warning("unexpected error in sig verification: %s", exc)
        raise HTTPException(400, "signature verification failed")


def _canon(data: dict) -> bytes:
    """deterministic JSON serialisation for signing. sort_keys is load-bearing."""
    return json.dumps(data, sort_keys=True, separators=(",", ":")).encode()

async def _cache_body(request: Request, call_next):
    body = await request.body()
    request.state.raw_body = body
    return await call_next(request)


async def authenticate(
    request: Request,
    db: sqlite3.Connection = Depends(get_db),
    x_client_id: str = Header(...),
    x_timestamp: str = Header(...),
    x_signature: str = Header(...),
):
    # timestamp check first — cheap, no db hit
    try:
        ts = int(x_timestamp)
    except ValueError:
        raise HTTPException(400, "x-timestamp must be an integer unix epoch")

    age = abs(int(time.time()) - ts)
    if age > TS_WINDOW:
        raise HTTPException(401, f"request too old ({age}s > {TS_WINDOW}s window)")

    row = db.execute(
        "SELECT secret_hash, role FROM clients WHERE client_id=?", (x_client_id,)
    ).fetchone()
    if not row:
        raise HTTPException(401, "unknown client")

    body = getattr(request.state, "raw_body", b"")
    payload = (
        request.method.encode()
        + request.url.path.encode()
        + body
        + x_timestamp.encode()
    )
    expected = hmac.new(
        row["secret_hash"].encode(), payload, "sha256"
    ).hexdigest()

    if not hmac.compare_digest(expected, x_signature):
        raise HTTPException(401, "invalid signature")

    request.state.client_id   = x_client_id
    request.state.client_role = row["role"]


def require_role(role: str):
    """tiny dep factory — feels a bit java-y but it's the cleanest option here"""
    def _check(request: Request):
        if getattr(request.state, "client_role", None) != role:
            raise HTTPException(403, "forbidden")
    return _check


async def rate_limit(request: Request):
    r: aioredis.Redis = request.app.state.redis
    cid = getattr(request.state, "client_id", "anon")
    bucket = f"rl:{cid}:{int(time.time()) // 60}"
    count = await r.incr(bucket)
    if count == 1:
        await r.expire(bucket, 60)
    if count > RL_LIMIT:
        raise HTTPException(429, "rate limit exceeded, back off")

def _idem_get(db, client_id: str, key: str) -> Optional[JSONResponse]:
    row = db.execute(
        "SELECT status_code, response FROM idempotency_cache WHERE client_id=? AND idem_key=?",
        (client_id, key),
    ).fetchone()
    if row:
        return JSONResponse(status_code=row["status_code"], content=json.loads(row["response"]))
    return None


def _idem_set(db, client_id: str, key: str, status: int, body: dict):
    db.execute(
        "INSERT INTO idempotency_cache (client_id, idem_key, status_code, response) VALUES (?,?,?,?)",
        (client_id, key, status, json.dumps(body)),
    )

@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    r = aioredis.from_url(REDIS_URL, decode_responses=True)
    await r.ping()
    app.state.redis = r
    log.info("hamilton_core started, db=%s redis=%s", DB_PATH, REDIS_URL)
    yield
    await r.close()


app = FastAPI(title="hamilton-core", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_methods=["POST", "GET"],
    allow_headers=["*"],
)

@app.middleware("http")
async def body_size_guard(request: Request, call_next):
    cl = request.headers.get("content-length")
    if cl and int(cl) > MAX_BODY:
        return JSONResponse({"detail": "payload too large"}, status_code=413)
    return await call_next(request)

app.middleware("http")(_cache_body)


_auth_deps = [Depends(authenticate), Depends(rate_limit)]


@app.post("/transactions/process", dependencies=_auth_deps)
async def process_tx(
    request: Request,
    tx: TxRequest,
    db: sqlite3.Connection = Depends(get_db),
    x_idem: str = Header(...),
):
    cid = request.state.client_id

    if cached := _idem_get(db, cid, x_idem):
        return cached

    tx_data = tx.model_dump(mode="json", exclude={"signature"})
    _verify_ed25519(tx.signer_public_key, _canon(tx_data), tx.signature, SIG_PREFIX_TX)

    try:
        db.execute("BEGIN IMMEDIATE")

        in_total = Decimal("0.00")
        for tid in tx.inputs:
            row = db.execute(
                "SELECT amount, currency, status, owner_public_key FROM utxos WHERE token_id=?",
                (tid,),
            ).fetchone()

            if not row:
                raise ValueError(f"token not found: {tid}")
            if row["status"] != "UNSPENT":
                raise ValueError(f"token not available: {tid}")
            if row["currency"] != tx.currency:
                raise ValueError(f"currency mismatch on {tid}: got {row['currency']}")
            if row["owner_public_key"] != tx.signer_public_key:
                raise ValueError(f"signer does not own {tid}")

            in_total += Decimal(row["amount"])
            db.execute("UPDATE utxos SET status='SPENT' WHERE token_id=?", (tid,))

        out_total = sum(o.amount for o in tx.outputs)
        if in_total != out_total:
            raise ValueError(
                f"value conservation failed: inputs={in_total} outputs={out_total}"
            )

        for out in tx.outputs:
            db.execute(
                "INSERT INTO utxos (token_id, amount, currency, owner_public_key, status)"
                " VALUES (?,?,?,?,'UNSPENT')",
                (out.token_id, str(out.amount), tx.currency, out.receiver_public_key),
            )

        db.execute(
            "INSERT INTO ledger_audit (tx_id, action, payload) VALUES (?,?,?)",
            (tx.transaction_id, "TRANSFER", json.dumps(tx_data)),
        )

        result = {"status": "COMPLETED", "transaction_id": tx.transaction_id}
        _idem_set(db, cid, x_idem, 200, result)
        db.execute("COMMIT")
        log.info("tx COMPLETED id=%s inputs=%d outputs=%d", tx.transaction_id, len(tx.inputs), len(tx.outputs))
        return result

    except ValueError as exc:
        db.execute("ROLLBACK")
        raise HTTPException(400, str(exc))
    except Exception:
        db.execute("ROLLBACK")
        log.exception("unexpected error processing tx %s", tx.transaction_id)
        raise


@app.post(
    "/tokens/mint",
    dependencies=_auth_deps + [Depends(require_role("ISSUER"))],
)
async def mint(
    request: Request,
    body: MintReq,
    db: sqlite3.Connection = Depends(get_db),
    x_idem: str = Header(...),
):
    cid = request.state.client_id

    if cached := _idem_get(db, cid, x_idem):
        return cached

    tid = str(uuid.uuid4())
    try:
        db.execute("BEGIN IMMEDIATE")
        db.execute(
            "INSERT INTO utxos (token_id, amount, currency, owner_public_key, status)"
            " VALUES (?,?,?,?,'UNSPENT')",
            (tid, str(body.amount), body.currency, body.public_key),
        )
        db.execute(
            "INSERT INTO ledger_audit (tx_id, action, payload) VALUES (?,?,?)",
            (tid, "MINT", json.dumps(body.model_dump(mode="json"))),
        )
        result = {"status": "COMPLETED", "token_id": tid}
        _idem_set(db, cid, x_idem, 200, result)
        db.execute("COMMIT")
        log.info("MINT token=%s amount=%s currency=%s", tid, body.amount, body.currency)
        return result
    except Exception:
        db.execute("ROLLBACK")
        raise


@app.post("/tokens/burn", dependencies=_auth_deps)
async def burn(
    request: Request,
    body: BurnReq,
    db: sqlite3.Connection = Depends(get_db),
    x_idem: str = Header(...),
):
    cid = request.state.client_id

    if cached := _idem_get(db, cid, x_idem):
        return cached

    b_data = body.model_dump(mode="json", exclude={"signature"})
    _verify_ed25519(body.owner_public_key, _canon(b_data), body.signature, SIG_PREFIX_BURN)

    try:
        db.execute("BEGIN IMMEDIATE")

        for tid in body.token_ids:
            row = db.execute(
                "SELECT status, owner_public_key FROM utxos WHERE token_id=?", (tid,)
            ).fetchone()
            if not row or row["status"] != "UNSPENT":
                raise ValueError(f"token not available for burn: {tid}")
            if row["owner_public_key"] != body.owner_public_key:
                raise ValueError(f"caller does not own {tid}")
            db.execute("UPDATE utxos SET status='BURNED' WHERE token_id=?", (tid,))

        audit_id = str(uuid.uuid4())
        db.execute(
            "INSERT INTO ledger_audit (tx_id, action, payload) VALUES (?,?,?)",
            (audit_id, "BURN", json.dumps(b_data)),
        )

        result = {"status": "COMPLETED", "burned": len(body.token_ids)}
        _idem_set(db, cid, x_idem, 200, result)
        db.execute("COMMIT")
        log.info("BURN count=%d owner=%.16s...", len(body.token_ids), body.owner_public_key)
        return result

    except ValueError as exc:
        db.execute("ROLLBACK")
        raise HTTPException(400, str(exc))
    except Exception:
        db.execute("ROLLBACK")
        log.exception("unexpected error in burn")
        raise

@app.get("/health/internal")
async def health(db: sqlite3.Connection = Depends(get_db)):
    db.execute("SELECT 1")
    return {
        "status": "ok",
        "ts": datetime.now(timezone.utc).isoformat(),
    }
