import json
import uuid
import hashlib
import threading
from decimal import Decimal
from datetime import datetime, timezone
from typing import Dict, List, Optional

from core.models import UTXO, Transaction
from core.crypto import CryptoUtils

SIGNATURE_DOMAIN = b"HAMILTON_MAINNET_V1"

MAX_TX_INPUTS = 100
MAX_TX_OUTPUTS = 100
MAX_HISTORY_SIZE = 100_000


class LedgerError(Exception):
    pass

class TxValidationError(LedgerError):
    pass

class DoubleSpendError(LedgerError):
    pass


class MemoryUTXOLedger:
    def __init__(self, fee_collector_pubkey: str):
        if not fee_collector_pubkey:
            raise ValueError("fee_collector_pubkey is required to initialize ledger")

        self.fee_collector = fee_collector_pubkey
        self.utxos: Dict[str, UTXO] = {}
        self.owner_index: Dict[str, set[str]] = {}
        
        # Bounded dict to prevent memory leaks in long-running nodes
        self.processed_txs: Dict[str, bool] = {}
        self.lock = threading.Lock()

    def get_utxo(self, token_id: str) -> Optional[UTXO]:
        with self.lock:
            return self.utxos.get(token_id)

    def get_balance(self, public_key: str, currency: str = "INR") -> Decimal:
        with self.lock:
            token_ids = self.owner_index.get(public_key, set())
            if not token_ids:
                return Decimal("0")

            now = datetime.now(timezone.utc)
            total = Decimal("0")
            
            for tid in token_ids:
                utxo = self.utxos.get(tid)
                if utxo and utxo.currency == currency:
                    if not utxo.expires_at or utxo.expires_at > now:
                        total += utxo.amount

            return total

    def _compute_tx_hash(self, tx: Transaction) -> str:
        # Canonicalization boundary: ensures all nodes agree on the exact bytes
        payload = json.dumps({
            "inputs": [{"token_id": i.token_id} for i in tx.inputs],
            "outputs": [
                {"amount": str(o.amount), "currency": o.currency, "owner": o.owner_public_key} 
                for o in tx.outputs
            ],
            "fee": str(tx.fee)
        }, separators=(",", ":"), sort_keys=True).encode("utf-8")
        
        return hashlib.sha256(payload).hexdigest()

    def apply_transaction(self, tx: Transaction) -> str:
        if not tx.inputs or not tx.outputs:
            raise TxValidationError("transaction must contain inputs and outputs")

        if len(tx.inputs) > MAX_TX_INPUTS or len(tx.outputs) > MAX_TX_OUTPUTS:
            raise TxValidationError("transaction exceeds maximum bounds")

        if tx.fee < 0:
            raise TxValidationError("negative fees are not permitted")

        for out in tx.outputs:
            if out.amount <= 0:
                raise TxValidationError(f"invalid output amount: {out.amount}")

        # The ledger dictates the transaction ID via canonical hashing
        derived_tx_id = self._compute_tx_hash(tx)
        if getattr(tx, "transaction_id", None) and tx.transaction_id != derived_tx_id:
            raise TxValidationError("provided transaction_id does not match canonical hash")
        tx.transaction_id = derived_tx_id

        input_ids = [inp.token_id for inp in tx.inputs]
        if len(set(input_ids)) != len(tx.inputs):
            raise TxValidationError("duplicate inputs detected in transaction")

        with self.lock:
            if tx.transaction_id in self.processed_txs:
                raise TxValidationError("transaction already processed")

            fetched_inputs = []
            for tid in input_ids:
                utxo = self.utxos.get(tid)
                if not utxo:
                    raise DoubleSpendError(f"input utxo missing or spent: {tid}")
                fetched_inputs.append(utxo)

        self._validate_tx_intent(tx, fetched_inputs, derived_tx_id)

        with self.lock:
            if tx.transaction_id in self.processed_txs:
                raise DoubleSpendError("transaction processed concurrently")

            for tid in input_ids:
                if tid not in self.utxos:
                    raise DoubleSpendError(f"input utxo spent concurrently: {tid}")

            for tid in input_ids:
                spent_utxo = self.utxos.pop(tid)
                owner_bucket = self.owner_index.get(spent_utxo.owner_public_key)
                if owner_bucket:
                    owner_bucket.discard(tid)
                    if not owner_bucket:
                        del self.owner_index[spent_utxo.owner_public_key]

            for out in tx.outputs:
                new_token_id = str(uuid.uuid4())
                self.utxos[new_token_id] = UTXO(
                    token_id=new_token_id,
                    amount=out.amount,
                    currency=out.currency,
                    owner_public_key=out.owner_public_key,
                    lock_script=out.lock_script,
                )
                self.owner_index.setdefault(out.owner_public_key, set()).add(new_token_id)

            if tx.fee > 0:
                fee_token_id = str(uuid.uuid4())
                self.utxos[fee_token_id] = UTXO(
                    token_id=fee_token_id,
                    amount=tx.fee,
                    currency=fetched_inputs[0].currency,
                    owner_public_key=self.fee_collector,
                    lock_script="",
                )
                self.owner_index.setdefault(self.fee_collector, set()).add(fee_token_id)

            self.processed_txs[tx.transaction_id] = True
            if len(self.processed_txs) > MAX_HISTORY_SIZE:
                oldest_tx = next(iter(self.processed_txs))
                del self.processed_txs[oldest_tx]

        return tx.transaction_id

    def _validate_tx_intent(self, tx: Transaction, inputs: List[UTXO], tx_hash: str) -> None:
        now = datetime.now(timezone.utc)
        target_currency = inputs[0].currency
        total_in = Decimal("0")

        utxo_map = {u.token_id: u for u in inputs}

        for tx_inp in tx.inputs:
            underlying_utxo = utxo_map.get(tx_inp.token_id)
            if not underlying_utxo:
                raise TxValidationError(f"missing utxo mapping for {tx_inp.token_id}")

            if underlying_utxo.currency != target_currency:
                raise TxValidationError(f"mixed currency in inputs: {underlying_utxo.token_id}")

            if underlying_utxo.expires_at and underlying_utxo.expires_at < now:
                raise TxValidationError(f"utxo expired: {underlying_utxo.token_id}")

            if underlying_utxo.lock_script:
                raise TxValidationError(f"lock scripts not supported in v1 consensus: {underlying_utxo.token_id}")

            total_in += underlying_utxo.amount

            sig_payload = SIGNATURE_DOMAIN + f"|{tx_hash}|{underlying_utxo.token_id}".encode("utf-8")
            
            try:
                pub_key = CryptoUtils.deserialize_public_key(underlying_utxo.owner_public_key)
                if not CryptoUtils.verify_signature(pub_key, sig_payload, tx_inp.signature):
                    raise TxValidationError(f"invalid signature for input {underlying_utxo.token_id}")
            except Exception as e:
                raise TxValidationError(f"cryptographic verification failed: {str(e)}")

        total_out = Decimal("0")
        for out in tx.outputs:
            if out.currency != target_currency:
                raise TxValidationError("output currency does not match input currency")
            total_out += out.amount

        if total_in != (total_out + tx.fee):
            raise TxValidationError(
                f"ledger imbalance: in={total_in}, out={total_out}, fee={tx.fee}"
            )
