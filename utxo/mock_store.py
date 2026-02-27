from __future__ import annotations

import uuid
import threading
from decimal import Decimal
from datetime import datetime
from typing import Dict, List, Optional, Any

from core.models import UTXO, Transaction
from core.crypto import CryptoUtils


class MockUTXOStore:
    def __init__(self) -> None:
        self._utxos: Dict[str, UTXO] = {}
        self._owners: Dict[str, set[str]] = {}
        self._lock = threading.RLock()
        self._closed = False

    def close(self) -> None:
        with self._lock:
            self._utxos.clear()
            self._owners.clear()
            self._closed = True

    def _ensure_open(self) -> None:
        if self._closed:
            raise RuntimeError("store is closed")

    def _index_add(self, owner: str, token_id: str) -> None:
        bucket = self._owners.get(owner)
        if bucket is None:
            bucket = set()
            self._owners[owner] = bucket
        bucket.add(token_id)

    def _index_remove(self, owner: str, token_id: str) -> None:
        bucket = self._owners.get(owner)
        if not bucket:
            return

        bucket.discard(token_id)
        if not bucket:
            del self._owners[owner]

    @staticmethod
    def _serialize(utxo: UTXO) -> Dict[str, Any]:
        data = utxo.model_dump()

        if isinstance(data.get("amount"), Decimal):
            data["amount"] = str(data["amount"])

        for field in ("created_at", "expires_at"):
            value = data.get(field)
            if isinstance(value, datetime):
                data[field] = value.isoformat()

        return data

    @staticmethod
    def _deserialize(data: Dict[str, Any]) -> UTXO:
        if "amount" in data:
            data["amount"] = Decimal(str(data["amount"]))

        for field in ("created_at", "expires_at"):
            value = data.get(field)
            if isinstance(value, str):
                data[field] = datetime.fromisoformat(value)

        return UTXO(**data)

    def add_utxo(self, utxo: UTXO) -> bool:
        with self._lock:
            self._ensure_open()

            self._utxos[utxo.token_id] = utxo
            self._index_add(utxo.owner_public_key, utxo.token_id)
            return True

    def get_utxo(self, token_id: str) -> Optional[UTXO]:
        with self._lock:
            self._ensure_open()
            return self._utxos.get(token_id)

    def _remove_utxo(self, token_id: str) -> bool:
        utxo = self._utxos.pop(token_id, None)
        if not utxo:
            return False

        self._index_remove(utxo.owner_public_key, token_id)
        return True

    def get_utxos_by_owner(self, public_key: str) -> List[UTXO]:
        with self._lock:
            self._ensure_open()

            ids = self._owners.get(public_key)
            if not ids:
                return []

            return [self._utxos[i] for i in ids if i in self._utxos]

    def process_transaction(self, tx: Transaction) -> bool:
        if not tx.is_valid():
            return False

        with self._lock:
            self._ensure_open()

            inputs: List[UTXO] = []

            for tx_input in tx.inputs:
                utxo = self._utxos.get(tx_input.token_id)
                if utxo is None:
                    return False

                payload = CryptoUtils.create_token_payload(
                    {
                        "token_id": utxo.token_id,
                        "amount": utxo.amount,
                        "currency": utxo.currency,
                        "owner_public_key": utxo.owner_public_key,
                    }
                )

                try:
                    pub = CryptoUtils.deserialize_public_key(
                        utxo.owner_public_key
                    )
                    if not CryptoUtils.verify_signature(
                        pub, payload, tx_input.signature
                    ):
                        return False
                except Exception:
                    return False

                inputs.append(utxo)

            if not inputs:
                return False

            currency = inputs[0].currency
            total_in = Decimal("0")

            for utxo in inputs:
                if utxo.currency != currency:
                    return False
                total_in += Decimal(str(utxo.amount))

            total_out = sum(
                (Decimal(str(o.amount)) for o in tx.outputs),
                Decimal("0"),
            )

            if total_in != total_out + tx.fee:
                return False

            for utxo in inputs:
                self._remove_utxo(utxo.token_id)

            for output in tx.outputs:
                new_utxo = UTXO(
                    token_id=str(uuid.uuid4()),
                    amount=output.amount,
                    currency=output.currency,
                    owner_public_key=output.owner_public_key,
                    lock_script=output.lock_script,
                )
                self._utxos[new_utxo.token_id] = new_utxo
                self._index_add(
                    new_utxo.owner_public_key,
                    new_utxo.token_id,
                )

            if tx.fee > 0:
                fee_utxo = UTXO(
                    token_id=str(uuid.uuid4()),
                    amount=tx.fee,
                    currency=currency,
                    owner_public_key="system_fee_address",
                    lock_script="",
                )
                self._utxos[fee_utxo.token_id] = fee_utxo
                self._index_add(
                    fee_utxo.owner_public_key,
                    fee_utxo.token_id,
                )

            return True

    def get_balance(
        self,
        public_key: str,
        currency: str = "INR",
    ) -> Decimal:
        with self._lock:
            self._ensure_open()

            total = Decimal("0")
            for utxo in self.get_utxos_by_owner(public_key):
                if utxo.currency == currency:
                    total += Decimal(str(utxo.amount))

            return total

    def snapshot(self) -> Dict[str, Any]:
        with self._lock:
            self._ensure_open()

            return {
                "utxos": {
                    tid: self._serialize(u)
                    for tid, u in self._utxos.items()
                },
                "owners": {
                    owner: list(tokens)
                    for owner, tokens in self._owners.items()
                },
            }

    def restore(self, snapshot: Dict[str, Any]) -> bool:
        new_utxos: Dict[str, UTXO] = {}
        new_index: Dict[str, set[str]] = {}

        try:
            for token_id, data in snapshot["utxos"].items():
                utxo = self._deserialize(dict(data))
                new_utxos[token_id] = utxo

                bucket = new_index.setdefault(
                    utxo.owner_public_key, set()
                )
                bucket.add(token_id)

        except Exception:
            return False

        with self._lock:
            self._ensure_open()
            self._utxos = new_utxos
            self._owners = new_index

        return True
