from __future__ import annotations

import json
import uuid
import logging
from decimal import Decimal
from datetime import datetime
from typing import Optional, List, Dict, Any

import redis

from core.models import UTXO, Transaction
from core.crypto import CryptoUtils

logger = logging.getLogger(__name__)


class UTXOStore:
    def __init__(
        self,
        host: str = "localhost",
        port: int = 6379,
        db: int = 0,
        max_connections: int = 64,
    ) -> None:
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

    def close(self) -> None:
        try:
            self._redis.close()
        finally:
            self._pool.disconnect()

    def _utxo_key(self, token_id: str) -> str:
        return f"{self._utxo_prefix}{token_id}"

    def _owner_key(self, public_key: str) -> str:
        return f"{self._owner_prefix}{public_key}"

    @staticmethod
    def _encode(utxo: UTXO) -> str:
        data = utxo.model_dump()

        for k, v in data.items():
            if isinstance(v, datetime):
                data[k] = v.isoformat()
            elif isinstance(v, Decimal):
                data[k] = str(v)

        return json.dumps(data, separators=(",", ":"))

    @staticmethod
    def _decode(raw: str) -> UTXO:
        data = json.loads(raw)

        if data.get("created_at"):
            data["created_at"] = datetime.fromisoformat(data["created_at"])

        if data.get("expires_at"):
            data["expires_at"] = datetime.fromisoformat(data["expires_at"])

        if data.get("amount") is not None:
            data["amount"] = Decimal(data["amount"])

        return UTXO(**data)

    def add_utxo(self, utxo: UTXO) -> bool:
        key = self._utxo_key(utxo.token_id)
        owner_key = self._owner_key(utxo.owner_public_key)

        pipe = self._redis.pipeline(transaction=True)
        pipe.set(key, self._encode(utxo))
        pipe.sadd(owner_key, utxo.token_id)
        pipe.execute()

        return True

    def get_utxo(self, token_id: str) -> Optional[UTXO]:
        raw = self._redis.get(self._utxo_key(token_id))
        return self._decode(raw) if raw else None

    def get_utxos_by_owner(self, public_key: str) -> List[UTXO]:
        owner_key = self._owner_key(public_key)
        token_ids = list(self._redis.smembers(owner_key))

        if not token_ids:
            return []

        keys = [self._utxo_key(t) for t in token_ids]
        values = self._redis.mget(keys)

        utxos: List[UTXO] = []
        cleanup = self._redis.pipeline()

        for token_id, raw in zip(token_ids, values):
            if raw:
                utxos.append(self._decode(raw))
            else:
                cleanup.srem(owner_key, token_id)

        if cleanup.command_stack:
            cleanup.execute()

        return utxos
        
    def process_transaction(self, tx: Transaction) -> bool:
        if not tx.is_valid():
            return False

        input_keys = [self._utxo_key(i.token_id) for i in tx.inputs]
        pipe = self._redis.pipeline()

        try:
            pipe.watch(*input_keys)

            raw_inputs = pipe.mget(input_keys)
            if not all(raw_inputs):
                pipe.unwatch()
                return False

            utxos = [self._decode(raw) for raw in raw_inputs]

            currency = utxos[0].currency
            total_in = Decimal("0")

            for utxo, inp in zip(utxos, tx.inputs):
                if utxo.currency != currency:
                    pipe.unwatch()
                    return False

                payload = CryptoUtils.create_token_payload(
                    {
                        "token_id": utxo.token_id,
                        "amount": utxo.amount,
                        "currency": utxo.currency,
                        "owner_public_key": utxo.owner_public_key,
                    }
                )

                pub = CryptoUtils.deserialize_public_key(
                    utxo.owner_public_key
                )

                if not CryptoUtils.verify_signature(
                    pub, payload, inp.signature
                ):
                    pipe.unwatch()
                    return False

                total_in += utxo.amount

            total_out = sum(
                (Decimal(str(o.amount)) for o in tx.outputs),
                Decimal("0"),
            )

            if total_in != total_out + tx.fee:
                pipe.unwatch()
                return False

            pipe.multi()

            for utxo in utxos:
                pipe.delete(self._utxo_key(utxo.token_id))
                pipe.srem(
                    self._owner_key(utxo.owner_public_key),
                    utxo.token_id,
                )

            for output in tx.outputs:
                new_id = str(uuid.uuid4())

                new_utxo = UTXO(
                    token_id=new_id,
                    amount=output.amount,
                    currency=output.currency,
                    owner_public_key=output.owner_public_key,
                    lock_script=output.lock_script,
                )

                pipe.set(
                    self._utxo_key(new_id),
                    self._encode(new_utxo),
                )
                pipe.sadd(
                    self._owner_key(output.owner_public_key),
                    new_id,
                )

            if tx.fee > 0:
                fee_utxo = UTXO(
                    token_id=str(uuid.uuid4()),
                    amount=tx.fee,
                    currency=currency,
                    owner_public_key="system_fee_address",
                    lock_script="",
                )

                pipe.set(
                    self._utxo_key(fee_utxo.token_id),
                    self._encode(fee_utxo),
                )
                pipe.sadd(
                    self._owner_key(fee_utxo.owner_public_key),
                    fee_utxo.token_id,
                )

            pipe.execute()
            return True

        except redis.WatchError:
            return False

        finally:
            pipe.reset()
            
    def get_balance(
        self,
        public_key: str,
        currency: str = "INR",
    ) -> Decimal:
        utxos = self.get_utxos_by_owner(public_key)

        total = Decimal("0")
        for u in utxos:
            if u.currency == currency:
                total += u.amount

        return total

    def snapshot(self) -> Dict[str, Any]:
        result: Dict[str, Any] = {}

        for key in self._redis.scan_iter(match=f"{self._utxo_prefix}*"):
            raw = self._redis.get(key)
            if raw:
                token_id = key[len(self._utxo_prefix):]
                result[token_id] = json.loads(raw)

        return result

    def restore(self, snapshot: Dict[str, Any]) -> bool:
        pipe = self._redis.pipeline()

        for key in self._redis.scan_iter(match=f"{self._utxo_prefix}*"):
            pipe.delete(key)

        for key in self._redis.scan_iter(match=f"{self._owner_prefix}*"):
            pipe.delete(key)

        for token_id, data in snapshot.items():
            utxo_key = self._utxo_key(token_id)
            owner_key = self._owner_key(data["owner_public_key"])

            if "amount" in data:
                data["amount"] = str(data["amount"])

            pipe.set(utxo_key, json.dumps(data))
            pipe.sadd(owner_key, token_id)

        pipe.execute()
        return True
