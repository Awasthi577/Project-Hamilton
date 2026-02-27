import json
import uuid
import hashlib
import logging
from decimal import Decimal
from datetime import datetime, timezone
from typing import Optional, List, Dict, Any

import redis

from core.models import UTXO, Transaction
from core.crypto import CryptoUtils

logger = logging.getLogger(__name__)

SIGNATURE_DOMAIN = b"HAMILTON_MAINNET_V1"
MAX_TX_INPUTS = 100
MAX_TX_OUTPUTS = 100
SCHEMA_VERSION = "1.0"


class LedgerError(Exception):
    pass

class TxValidationError(LedgerError):
    pass

class DoubleSpendError(LedgerError):
    pass


class UTXOStore:
    def __init__(
        self,
        fee_collector_pubkey: str,
        host: str = "localhost",
        port: int = 6379,
        db: int = 0,
        max_connections: int = 64,
    ) -> None:
        if not fee_collector_pubkey:
            raise ValueError("fee_collector_pubkey is required to initialize ledger")
            
        self.fee_collector = fee_collector_pubkey
        
        self._pool = redis.ConnectionPool(
            host=host,
            port=port,
            db=db,
            decode_responses=True,
            socket_timeout=5,
            retry_on_timeout=True,
            health_check_interval=30,
            max_connections=max_connections,
        )
        self._redis = redis.Redis(connection_pool=self._pool)

        self._utxo_prefix = "utxo:"
        self._owner_prefix = "owner:"
        self._tx_prefix = "tx:"
        self._audit_stream_key = "ledger:audit_log"

    def close(self) -> None:
        try:
            self._redis.close()
        finally:
            self._pool.disconnect()

    def _utxo_key(self, token_id: str) -> str:
        return f"{self._utxo_prefix}{token_id}"

    def _owner_key(self, public_key: str) -> str:
        return f"{self._owner_prefix}{public_key}"

    def _tx_key(self, tx_hash: str) -> str:
        return f"{self._tx_prefix}{tx_hash}"

    def _compute_tx_hash(self, tx: Transaction) -> str:
        payload = json.dumps({
            "inputs": [{"token_id": i.token_id} for i in tx.inputs],
            "outputs": [
                {"amount": str(o.amount), "currency": o.currency, "owner": o.owner_public_key} 
                for o in tx.outputs
            ],
            "fee": str(tx.fee)
        }, separators=(",", ":"), sort_keys=True).encode("utf-8")
        
        return hashlib.sha256(payload).hexdigest()

    def _parse_utxo(self, raw_data: str) -> UTXO:
        data = json.loads(raw_data)
        if data.get("created_at"):
            data["created_at"] = datetime.fromisoformat(data["created_at"])
        if data.get("expires_at"):
            data["expires_at"] = datetime.fromisoformat(data["expires_at"])
        if data.get("amount") is not None:
            data["amount"] = Decimal(str(data["amount"]))
        return UTXO(**data)

    def add_utxo(self, utxo: UTXO) -> str:
        data = utxo.model_dump()
        for k, v in data.items():
            if isinstance(v, datetime):
                data[k] = v.isoformat()
            elif isinstance(v, Decimal):
                data[k] = str(v)

        pipe = self._redis.pipeline(transaction=True)
        pipe.set(self._utxo_key(utxo.token_id), json.dumps(data, separators=(",", ":")))
        pipe.sadd(self._owner_key(utxo.owner_public_key), utxo.token_id)
        pipe.execute()

        return utxo.token_id

    def get_utxo(self, token_id: str) -> Optional[UTXO]:
        raw = self._redis.get(self._utxo_key(token_id))
        return self._parse_utxo(raw) if raw else None

    def get_balance(self, public_key: str, currency: str = "INR") -> Decimal:
        owner_key = self._owner_key(public_key)
        total = Decimal("0")
        now = datetime.now(timezone.utc)
        
        cursor = '0'
        while cursor != 0:
            cursor, token_ids = self._redis.sscan(owner_key, cursor=cursor, count=200)
            if not token_ids:
                continue

            keys = [self._utxo_key(t) for t in token_ids]
            raw_utxos = self._redis.mget(keys)

            cleanup = self._redis.pipeline(transaction=False)
            for token_id, raw in zip(token_ids, raw_utxos):
                if raw:
                    u = self._parse_utxo(raw)
                    if u.currency == currency and (not u.expires_at or u.expires_at > now):
                        total += u.amount
                else:
                    # Self-healing: remove orphaned tokens from owner index
                    cleanup.srem(owner_key, token_id)

            if cleanup.command_stack:
                cleanup.execute()

        return total
        
    def _validate_tx_intent(self, tx: Transaction, inputs: List[UTXO], tx_hash: str) -> None:
        now = datetime.now(timezone.utc)
        target_currency = inputs[0].currency
        total_in = Decimal("0")

        # Eliminates cross-node ordering divergence issues
        utxo_map = {u.token_id: u for u in inputs}

        for tx_inp in tx.inputs:
            underlying_utxo = utxo_map.get(tx_inp.token_id)
            if not underlying_utxo:
                raise TxValidationError(f"Missing UTXO mapping for input {tx_inp.token_id}")

            if underlying_utxo.currency != target_currency:
                raise TxValidationError(f"Mixed currency in inputs: {underlying_utxo.token_id}")

            if underlying_utxo.expires_at and underlying_utxo.expires_at < now:
                raise TxValidationError(f"UTXO expired: {underlying_utxo.token_id}")

            total_in += underlying_utxo.amount

            # Bind signature to tx intent + domain, not just the token
            sig_payload = SIGNATURE_DOMAIN + f"|{tx_hash}|{underlying_utxo.token_id}".encode("utf-8")
            
            try:
                pub_key = CryptoUtils.deserialize_public_key(underlying_utxo.owner_public_key)
                if not CryptoUtils.verify_signature(pub_key, sig_payload, tx_inp.signature):
                    raise TxValidationError(f"Invalid signature for input {underlying_utxo.token_id}")
            except Exception as e:
                raise TxValidationError(f"Cryptographic verification failed: {str(e)}")

        total_out = Decimal("0")
        for out in tx.outputs:
            if out.currency != target_currency:
                raise TxValidationError("Output currency does not match input currency")
            if out.amount <= 0:
                raise TxValidationError(f"Invalid output amount: {out.amount}")
            total_out += out.amount

        if tx.fee < 0:
            raise TxValidationError("Negative fees are not permitted")

        if total_in != (total_out + tx.fee):
            raise TxValidationError(f"Ledger imbalance: in={total_in}, out={total_out}, fee={tx.fee}")

    def process_transaction(self, tx: Transaction) -> str:
        if not tx.inputs or not tx.outputs:
            raise TxValidationError("Transaction must contain inputs and outputs")

        if len(tx.inputs) > MAX_TX_INPUTS or len(tx.outputs) > MAX_TX_OUTPUTS:
            raise TxValidationError("Transaction exceeds maximum bounds")

        input_ids = [inp.token_id for inp in tx.inputs]
        if len(set(input_ids)) != len(tx.inputs):
            raise TxValidationError("Duplicate inputs detected in transaction")

        derived_tx_id = self._compute_tx_hash(tx)
        if getattr(tx, "transaction_id", None) and tx.transaction_id != derived_tx_id:
            raise TxValidationError("Provided transaction_id does not match canonical hash")
        tx.transaction_id = derived_tx_id

        input_keys = [self._utxo_key(tid) for tid in input_ids]
        tx_key = self._tx_key(derived_tx_id)
        
        watch_keys = input_keys + [tx_key]
        pipe = self._redis.pipeline(transaction=True)

        try:
            pipe.watch(*watch_keys)

            if pipe.exists(tx_key):
                raise TxValidationError("Transaction already processed")

            raw_inputs = pipe.mget(input_keys)
            if not all(raw_inputs):
                raise DoubleSpendError("One or more inputs are missing or already spent")

            utxos = [self._parse_utxo(raw) for raw in raw_inputs]

            self._validate_tx_intent(tx, utxos, derived_tx_id)

            pipe.multi()

            # Record tx id for replay protection (keep for 7 days)
            pipe.set(tx_key, "1", ex=86400 * 7)

            for utxo in utxos:
                pipe.delete(self._utxo_key(utxo.token_id))
                pipe.srem(self._owner_key(utxo.owner_public_key), utxo.token_id)

            for out in tx.outputs:
                new_id = str(uuid.uuid4())
                pipe.set(
                    self._utxo_key(new_id),
                    json.dumps({
                        "token_id": new_id,
                        "amount": str(out.amount),
                        "currency": out.currency,
                        "owner_public_key": out.owner_public_key,
                        "lock_script": out.lock_script
                    }, separators=(",", ":"))
                )
                pipe.sadd(self._owner_key(out.owner_public_key), new_id)

            if tx.fee > 0:
                fee_id = str(uuid.uuid4())
                pipe.set(
                    self._utxo_key(fee_id),
                    json.dumps({
                        "token_id": fee_id,
                        "amount": str(tx.fee),
                        "currency": utxos[0].currency,
                        "owner_public_key": self.fee_collector,
                        "lock_script": ""
                    }, separators=(",", ":"))
                )
                pipe.sadd(self._owner_key(self.fee_collector), fee_id)

            # Append-only audit trail for durability and forensics
            pipe.xadd(self._audit_stream_key, {
                "tx_id": derived_tx_id,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "inputs": json.dumps(input_ids),
                "outputs": json.dumps([out.model_dump() for out in tx.outputs], default=str),
                "fee": str(tx.fee)
            })

            pipe.execute()
            return derived_tx_id

        except redis.WatchError:
            raise DoubleSpendError("Concurrent transaction conflict")
        finally:
            pipe.reset()

    def snapshot(self) -> Dict[str, Any]:
        result: Dict[str, Any] = {"version": SCHEMA_VERSION, "utxos": {}}

        for key in self._redis.scan_iter(match=f"{self._utxo_prefix}*"):
            raw = self._redis.get(key)
            if raw:
                token_id = key[len(self._utxo_prefix):]
                result["utxos"][token_id] = json.loads(raw)

        return result

    def restore(self, snapshot: Dict[str, Any]) -> bool:
        if snapshot.get("version") != SCHEMA_VERSION:
            raise ValueError(f"Unsupported snapshot version. Expected {SCHEMA_VERSION}")

        pipe = self._redis.pipeline(transaction=True)

        for key in self._redis.scan_iter(match=f"{self._utxo_prefix}*"):
            pipe.delete(key)
        for key in self._redis.scan_iter(match=f"{self._owner_prefix}*"):
            pipe.delete(key)
        for key in self._redis.scan_iter(match=f"{self._tx_prefix}*"):
            pipe.delete(key)

        for token_id, data in snapshot.get("utxos", {}).items():
            if "amount" in data:
                data["amount"] = str(data["amount"])

            pipe.set(self._utxo_key(token_id), json.dumps(data, separators=(",", ":")))
            pipe.sadd(self._owner_key(data["owner_public_key"]), token_id)

        pipe.execute()
        return True
