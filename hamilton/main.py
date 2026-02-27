import os
import json
import hmac
import time
import uuid
import sqlite3
import logging
import hashlib
import secrets
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


DB_PATH = os.getenv("DB_PATH", "ledger.db")
REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")
NETWORK_ID = os.getenv("NETWORK_ID", "")

_bridge_secret = os.getenv("CLIENT_SECRET_BRIDGE", "")
_wallet_secret = os.getenv("CLIENT_SECRET_WALLET", "")
_health_token = os.getenv("HEALTH_TOKEN", "")

_MINIMUM_SECRET_BYTES = 32

def _check_secret_entropy(name: str, value: str):
    if not value:
        raise RuntimeError(f"{name} must be set")
    if len(value.encode()) < _MINIMUM_SECRET_BYTES:
        raise RuntimeError(f"{name} must be at least {_MINIMUM_SECRET_BYTES} bytes")

_check_secret_entropy("CLIENT_SECRET_BRIDGE", _bridge_secret)
_check_secret_entropy("CLIENT_SECRET_WALLET", _wallet_secret)
_check_secret_entropy("HEALTH_TOKEN", _health_token)

if not NETWORK_ID:
    raise RuntimeError("NETWORK_ID must be set")

ALLOWED_ORIGINS = os.getenv(
    "ALLOWED_ORIGINS", "https://wallet.hamilton.finance"
).split(",")

MAX_BODY = 512_000
RL_LIMIT_DEFAULT = 120
RL_LIMIT_TX = 30
RL_LIMIT_MINT = 20
TS_WINDOW_HMAC = 30
TS_WINDOW_SIG = 60
MAX_UTXO_LIST = 100
IDEM_KEY_MAX_LEN = 128
IDEM_STALE_SECS = TS_WINDOW_SIG * 2 + 10
ALLOWED_CURRENCIES = frozenset({"USD", "EUR", "GBP", "SGD", "JPY", "CHF"})

SIG_PREFIX_TX = b"HAMILTON_CORE_TX_V1:"
SIG_PREFIX_BURN = b"HAMILTON_CORE_BURN_V1:"

ALLOWED_HEADERS = [
    "content-type",
    "x-client-id",
    "x-timestamp",
    "x-signature",
    "x-idem",
    "x-health-token",
]

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


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _audit_chain_hash(prev_hash: str, payload: str) -> str:
    return _sha256_hex((prev_hash + payload).encode())


def _gc_stale_idem(conn: sqlite3.Connection):
    cutoff = int(time.time()) - IDEM_STALE_SECS
    conn.execute(
        "DELETE FROM idempotency_cache WHERE status='PENDING' AND created_ts < ?",
        (cutoff,),
    )


def init_db():
    conn = _get_conn()
    try:
        conn.executescript("""
            PRAGMA journal_mode=WAL;

            CREATE TABLE IF NOT EXISTS clients (
                client_id   TEXT PRIMARY KEY,
                hmac_key    TEXT NOT NULL,
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

            CREATE TABLE IF NOT EXISTS ledger_audit (
                seq        INTEGER PRIMARY KEY AUTOINCREMENT,
                tx_id      TEXT NOT NULL UNIQUE,
                action     TEXT NOT NULL,
                payload    TEXT NOT NULL,
                prev_hash  TEXT NOT NULL DEFAULT '',
                chain_hash TEXT NOT NULL DEFAULT '',
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            );

            CREATE TABLE IF NOT EXISTS idempotency_cache (
                client_id   TEXT NOT NULL,
                idem_key    TEXT NOT NULL,
                status      TEXT NOT NULL DEFAULT 'PENDING',
                status_code INTEGER,
                response    TEXT,
                created_ts  INTEGER NOT NULL,
                PRIMARY KEY (client_id, idem_key)
            );
        """)

        for cid, secret, role in [
            ("liquidity-bridge", _bridge_secret, "ISSUER"),
            ("wallet-service", _wallet_secret, "PROCESSOR"),
        ]:
            existing = conn.execute(
                "SELECT hmac_key FROM clients WHERE client_id=?", (cid,)
            ).fetchone()
            hk = existing["hmac_key"] if existing else secrets.token_hex(32)
            conn.execute(
                "INSERT OR REPLACE INTO clients (client_id, hmac_key, role) VALUES (?,?,?)",
                (cid, hk, role),
            )

        _gc_stale_idem(conn)
        log.info("hamilton_core db initialized network_id=%s", NETWORK_ID)
    finally:
        conn.close()


def _to_decimal(v) -> Decimal:
    try:
        d = Decimal(str(v))
    except InvalidOperation:
        raise ValueError(f"invalid amount: {v!r}")
    if d <= 0:
        raise ValueError("amount must be positive")
    return d.quantize(Decimal("0.01"), rounding=ROUND_DOWN)


def _validate_hex(val: str, expected_len: int, field: str):
    if len(val) != expected_len:
        raise ValueError(f"{field}: expected {expected_len} hex chars, got {len(val)}")
    try:
        bytes.fromhex(val)
    except ValueError:
        raise ValueError(f"{field}: not valid hex")


def _validate_currency(v: str) -> str:
    normed = v.strip().upper()
    if normed not in ALLOWED_CURRENCIES:
        raise ValueError(f"unsupported currency: {v!r}")
    return normed


def _validate_idem_key(v: str):
    if not v or len(v) > IDEM_KEY_MAX_LEN:
        raise HTTPException(400, "x-idem must be 1–128 characters")
    try:
        uuid.UUID(v)
    except ValueError:
        raise HTTPException(400, "x-idem must be a valid UUID")


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
        _validate_hex(v, 64, "receiver_public_key")
        return v


class TxRequest(BaseModel):
    transaction_id: str
    network_id: str
    currency: str
    inputs: list[str] = Field(..., min_length=1, max_length=MAX_UTXO_LIST)
    outputs: list[TxOut] = Field(..., min_length=1, max_length=MAX_UTXO_LIST)
    signer_public_key: str
    signed_at: int
    signature: str

    @field_validator("currency", mode="before")
    @classmethod
    def check_currency(cls, v):
        return _validate_currency(v)

    @field_validator("signer_public_key")
    @classmethod
    def check_signer(cls, v):
        _validate_hex(v, 64, "signer_public_key")
        return v

    @field_validator("signature")
    @classmethod
    def check_sig_fmt(cls, v):
        _validate_hex(v, 128, "signature")
        return v


class MintReq(BaseModel):
    amount: Decimal
    currency: str
    public_key: str

    @field_validator("amount", mode="before")
    @classmethod
    def coerce_amount(cls, v):
        return _to_decimal(v)

    @field_validator("currency", mode="before")
    @classmethod
    def check_currency(cls, v):
        return _validate_currency(v)

    @field_validator("public_key")
    @classmethod
    def check_pk(cls, v):
        _validate_hex(v, 64, "public_key")
        return v


class BurnReq(BaseModel):
    token_ids: list[str] = Field(..., min_length=1, max_length=MAX_UTXO_LIST)
    network_id: str
    owner_public_key: str
    signed_at: int
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


def _verify_ed25519(pubkey_hex: str, msg: bytes, sig_hex: str, prefix: bytes):
    try:
        vk = VerifyKey(bytes.fromhex(pubkey_hex))
        vk.verify(prefix + msg, bytes.fromhex(sig_hex))
    except BadSignatureError:
        raise HTTPException(400, "signature verification failed")
    except Exception:
        raise HTTPException(400, "signature verification failed")


def _verify_signed_at(signed_at: int):
    if abs(int(time.time()) - signed_at) > TS_WINDOW_SIG:
        raise HTTPException(400, "signed_at out of acceptable window")


def _verify_network(provided: str):
    if provided != NETWORK_ID:
        raise HTTPException(400, "network_id mismatch")


def _canon(data: dict) -> bytes:
    return json.dumps(data, sort_keys=True, separators=(",", ":")).encode()


def _audit_insert(conn: sqlite3.Connection, tx_id: str, action: str, payload_str: str):
    last = conn.execute(
        "SELECT chain_hash FROM ledger_audit ORDER BY seq DESC LIMIT 1"
    ).fetchone()
    prev_hash = last["chain_hash"] if last else ""
    chain_hash = _audit_chain_hash(prev_hash, payload_str)
    conn.execute(
        "INSERT INTO ledger_audit (tx_id, action, payload, prev_hash, chain_hash)"
        " VALUES (?,?,?,?,?)",
        (tx_id, action, payload_str, prev_hash, chain_hash),
    )


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    r = aioredis.from_url(REDIS_URL, decode_responses=True)
    try:
        await r.ping()
    except Exception as exc:
        raise RuntimeError(f"Redis unavailable at startup: {exc}") from exc
    app.state.redis = r
    log.info("hamilton_core started db=%s redis=%s network=%s", DB_PATH, REDIS_URL, NETWORK_ID)
    log.info("rate limiting is hard-enforced; Redis unavailability will return 503 by design")
    yield
    await r.close()


app = FastAPI(title="hamilton-core", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_methods=["POST", "GET"],
    allow_headers=ALLOWED_HEADERS,
)


@app.middleware("http")
async def body_size_guard(request: Request, call_next):
    cl = request.headers.get("content-length")
    if cl and int(cl) > MAX_BODY:
        return JSONResponse({"detail": "payload too large"}, status_code=413)
    return await call_next(request)


@app.middleware("http")
async def cache_body(request: Request, call_next):
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
    try:
        ts = int(x_timestamp)
    except ValueError:
        raise HTTPException(400, "x-timestamp must be an integer unix epoch")

    if abs(int(time.time()) - ts) > TS_WINDOW_HMAC:
        raise HTTPException(401, "request timestamp out of window")

    row = db.execute(
        "SELECT hmac_key, role FROM clients WHERE client_id=?", (x_client_id,)
    ).fetchone()
    if not row:
        raise HTTPException(401, "unauthorized")

    body = getattr(request.state, "raw_body", b"")
    payload = (
        request.method.encode()
        + request.url.path.encode()
        + body
        + x_timestamp.encode()
    )
    expected = hmac.new(
        bytes.fromhex(row["hmac_key"]), payload, hashlib.sha256
    ).hexdigest()

    if not hmac.compare_digest(expected, x_signature):
        raise HTTPException(401, "unauthorized")

    request.state.client_id = x_client_id
    request.state.client_role = row["role"]


def require_role(role: str):
    def _check(request: Request):
        if getattr(request.state, "client_role", None) != role:
            raise HTTPException(403, "forbidden")
    return _check


async def _rate_limit(request: Request, endpoint_key: str, limit: int):
    try:
        r: aioredis.Redis = request.app.state.redis
        cid = getattr(request.state, "client_id", "anon")
        bucket = f"rl:{endpoint_key}:{cid}:{int(time.time()) // 60}"
        count = await r.incr(bucket)
        if count == 1:
            await r.expire(bucket, 60)
        if count > limit:
            raise HTTPException(429, "rate limit exceeded")
    except HTTPException:
        raise
    except Exception as exc:
        log.warning(
            "redis unavailable for rate limiting cid=%s reason=%s",
            getattr(request.state, "client_id", "anon"),
            type(exc).__name__,
        )
        raise HTTPException(503, "service temporarily unavailable: rate limiter offline")


async def rate_limit_tx(request: Request):
    await _rate_limit(request, "tx", RL_LIMIT_TX)


async def rate_limit_default(request: Request):
    await _rate_limit(request, "default", RL_LIMIT_DEFAULT)


async def rate_limit_mint(request: Request):
    await _rate_limit(request, "mint", RL_LIMIT_MINT)


def _idem_acquire(conn: sqlite3.Connection, client_id: str, key: str) -> Optional[dict]:
    existing = conn.execute(
        "SELECT status, status_code, response FROM idempotency_cache"
        " WHERE client_id=? AND idem_key=?",
        (client_id, key),
    ).fetchone()

    if existing:
        if existing["status"] == "COMPLETE":
            return {
                "status_code": existing["status_code"],
                "body": json.loads(existing["response"]),
            }
        raise HTTPException(409, "concurrent request with same idempotency key in flight")

    conn.execute(
        "INSERT INTO idempotency_cache (client_id, idem_key, status, created_ts)"
        " VALUES (?,?,?,?)",
        (client_id, key, "PENDING", int(time.time())),
    )
    return None


def _idem_complete(conn: sqlite3.Connection, client_id: str, key: str, status: int, body: dict):
    rows = conn.execute(
        "UPDATE idempotency_cache SET status='COMPLETE', status_code=?, response=?"
        " WHERE client_id=? AND idem_key=? AND status='PENDING'",
        (status, json.dumps(body), client_id, key),
    ).rowcount
    if rows != 1:
        raise RuntimeError("idempotency record missing or already completed")


_auth_deps = [Depends(authenticate)]


@app.post(
    "/transactions/process",
    dependencies=_auth_deps + [Depends(rate_limit_tx), Depends(require_role("PROCESSOR"))],
)
async def process_tx(
    request: Request,
    tx: TxRequest,
    db: sqlite3.Connection = Depends(get_db),
    x_idem: str = Header(...),
):
    _validate_idem_key(x_idem)
    _verify_network(tx.network_id)
    _verify_signed_at(tx.signed_at)

    if len(tx.inputs) != len(set(tx.inputs)):
        raise HTTPException(400, "duplicate inputs")

    output_ids = [o.token_id for o in tx.outputs]
    if len(output_ids) != len(set(output_ids)):
        raise HTTPException(400, "duplicate output token_ids")

    signing_data = {
        "transaction_id": tx.transaction_id,
        "network_id": tx.network_id,
        "currency": tx.currency,
        "inputs": tx.inputs,
        "outputs": [
            {
                "token_id": o.token_id,
                "amount": str(o.amount),
                "receiver_public_key": o.receiver_public_key,
            }
            for o in tx.outputs
        ],
        "signer_public_key": tx.signer_public_key,
        "signed_at": tx.signed_at,
    }
    _verify_ed25519(tx.signer_public_key, _canon(signing_data), tx.signature, SIG_PREFIX_TX)

    cid = request.state.client_id

    try:
        db.execute("BEGIN IMMEDIATE")

        cached = _idem_acquire(db, cid, x_idem)
        if cached:
            db.execute("COMMIT")
            return JSONResponse(status_code=cached["status_code"], content=cached["body"])

        in_total = Decimal("0.00")
        for tid in tx.inputs:
            row = db.execute(
                "SELECT amount, currency, status, owner_public_key FROM utxos WHERE token_id=?",
                (tid,),
            ).fetchone()
            if not row or row["status"] != "UNSPENT":
                raise ValueError("UTXO_NOT_AVAILABLE")
            if row["currency"] != tx.currency:
                raise ValueError("CURRENCY_MISMATCH")
            if row["owner_public_key"] != tx.signer_public_key:
                raise ValueError("OWNERSHIP_ERROR")
            in_total += Decimal(row["amount"])
            db.execute("UPDATE utxos SET status='SPENT' WHERE token_id=?", (tid,))

        out_total = sum(o.amount for o in tx.outputs)
        if in_total != out_total:
            raise ValueError("VALUE_CONSERVATION_FAILED")

        for out in tx.outputs:
            db.execute(
                "INSERT INTO utxos (token_id, amount, currency, owner_public_key, status)"
                " VALUES (?,?,?,?,'UNSPENT')",
                (out.token_id, str(out.amount), tx.currency, out.receiver_public_key),
            )

        _audit_insert(db, tx.transaction_id, "TRANSFER", json.dumps(signing_data))

        result = {"status": "COMPLETED", "transaction_id": tx.transaction_id}
        _idem_complete(db, cid, x_idem, 200, result)
        db.execute("COMMIT")

        log.info("tx COMPLETED id=%s inputs=%d outputs=%d", tx.transaction_id, len(tx.inputs), len(tx.outputs))
        return result

    except HTTPException:
        db.execute("ROLLBACK")
        raise
    except ValueError as exc:
        db.execute("ROLLBACK")
        raise HTTPException(400, str(exc))
    except Exception:
        db.execute("ROLLBACK")
        log.error("unexpected error processing tx id=%s", tx.transaction_id)
        raise


@app.post(
    "/tokens/mint",
    dependencies=_auth_deps + [Depends(rate_limit_mint), Depends(require_role("ISSUER"))],
)
async def mint(
    request: Request,
    body: MintReq,
    db: sqlite3.Connection = Depends(get_db),
    x_idem: str = Header(...),
):
    _validate_idem_key(x_idem)
    cid = request.state.client_id
    mint_payload = body.model_dump(mode="json")

    try:
        db.execute("BEGIN IMMEDIATE")

        cached = _idem_acquire(db, cid, x_idem)
        if cached:
            db.execute("COMMIT")
            return JSONResponse(status_code=cached["status_code"], content=cached["body"])

        tid = str(uuid.uuid4())

        db.execute(
            "INSERT INTO utxos (token_id, amount, currency, owner_public_key, status)"
            " VALUES (?,?,?,?,'UNSPENT')",
            (tid, str(body.amount), body.currency, body.public_key),
        )
        _audit_insert(db, tid, "MINT", json.dumps(mint_payload))

        result = {"status": "COMPLETED", "token_id": tid}
        _idem_complete(db, cid, x_idem, 200, result)
        db.execute("COMMIT")

        log.info("MINT token=%s amount=%s currency=%s", tid, body.amount, body.currency)
        return result

    except HTTPException:
        db.execute("ROLLBACK")
        raise
    except Exception:
        db.execute("ROLLBACK")
        log.error("unexpected error in mint")
        raise


@app.post("/tokens/burn", dependencies=_auth_deps + [Depends(rate_limit_default)])
async def burn(
    request: Request,
    body: BurnReq,
    db: sqlite3.Connection = Depends(get_db),
    x_idem: str = Header(...),
):
    _validate_idem_key(x_idem)
    _verify_network(body.network_id)
    _verify_signed_at(body.signed_at)

    if len(body.token_ids) != len(set(body.token_ids)):
        raise HTTPException(400, "duplicate token_ids in burn request")

    signing_data = {
        "token_ids": body.token_ids,
        "network_id": body.network_id,
        "owner_public_key": body.owner_public_key,
        "signed_at": body.signed_at,
    }
    _verify_ed25519(body.owner_public_key, _canon(signing_data), body.signature, SIG_PREFIX_BURN)

    cid = request.state.client_id

    try:
        db.execute("BEGIN IMMEDIATE")

        cached = _idem_acquire(db, cid, x_idem)
        if cached:
            db.execute("COMMIT")
            return JSONResponse(status_code=cached["status_code"], content=cached["body"])

        for tid in body.token_ids:
            row = db.execute(
                "SELECT status, owner_public_key FROM utxos WHERE token_id=?", (tid,)
            ).fetchone()
            if not row or row["status"] != "UNSPENT":
                raise ValueError("UTXO_NOT_AVAILABLE")
            if row["owner_public_key"] != body.owner_public_key:
                raise ValueError("OWNERSHIP_ERROR")
            db.execute("UPDATE utxos SET status='BURNED' WHERE token_id=?", (tid,))

        audit_id = str(uuid.uuid4())
        _audit_insert(db, audit_id, "BURN", json.dumps(signing_data))

        result = {"status": "COMPLETED", "burned": len(body.token_ids)}
        _idem_complete(db, cid, x_idem, 200, result)
        db.execute("COMMIT")

        log.info("BURN count=%d owner=%s", len(body.token_ids), body.owner_public_key)
        return result

    except HTTPException:
        db.execute("ROLLBACK")
        raise
    except ValueError as exc:
        db.execute("ROLLBACK")
        raise HTTPException(400, str(exc))
    except Exception:
        db.execute("ROLLBACK")
        log.error("unexpected error in burn")
        raise


@app.get("/health/internal")
async def health(
    db: sqlite3.Connection = Depends(get_db),
    x_health_token: str = Header(...),
):
    if not secrets.compare_digest(_health_token, x_health_token):
        raise HTTPException(403, "forbidden")
    db.execute("SELECT 1")
    return {"status": "ok", "ts": datetime.now(timezone.utc).isoformat()}
