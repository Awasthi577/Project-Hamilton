"""
Mock UTXO Store for testing - Thread-Safe, Atomic, Strict Implementation
"""
import sys
import os
import uuid
import threading
from typing import Optional, List, Dict, Any
from decimal import Decimal
from datetime import datetime

from core.models import UTXO, Transaction, TransactionInput, TransactionOutput
from core.crypto import CryptoUtils

class MockUTXOStore:
    """Mock UTXO Store for testing - Thread-safe, strict implementation"""
    
    def __init__(self):
        """Initialize in-memory store with thread locks"""
        self.utxos: Dict[str, UTXO] = {}  # token_id -> UTXO
        self.owner_index: Dict[str, set] = {}  # public_key -> set(token_ids)
        self._lock = threading.RLock() # Reentrant lock for thread safety
    
    def add_utxo(self, utxo: UTXO) -> bool:
        """Add a new UTXO to the store atomically"""
        with self._lock:
            self.utxos[utxo.token_id] = utxo
            
            # Add to owner's index
            if utxo.owner_public_key not in self.owner_index:
                self.owner_index[utxo.owner_public_key] = set()
            self.owner_index[utxo.owner_public_key].add(utxo.token_id)
            
            return True
    
    def get_utxo(self, token_id: str) -> Optional[UTXO]:
        """Get UTXO by token ID"""
        with self._lock:
            return self.utxos.get(token_id)
    
    def spend_utxo(self, token_id: str) -> bool:
        """Mark UTXO as spent (remove from store)"""
        with self._lock:
            utxo = self.get_utxo(token_id)
            if utxo:
                del self.utxos[token_id]
                
                # Remove from owner's index
                if utxo.owner_public_key in self.owner_index:
                    self.owner_index[utxo.owner_public_key].discard(token_id)
                    # Cleanup empty sets
                    if not self.owner_index[utxo.owner_public_key]:
                        del self.owner_index[utxo.owner_public_key]
                
                return True
            
            return False
    
    def get_utxos_by_owner(self, public_key: str) -> List[UTXO]:
        """Get all UTXOs owned by a public key"""
        with self._lock:
            token_ids = self.owner_index.get(public_key, set())
            return [self.utxos[token_id] for token_id in token_ids if token_id in self.utxos]
    
    def process_transaction(self, transaction: Transaction) -> bool:
        """Process a transaction - validate and update UTXO set"""
        # Validate transaction
        if not transaction.is_valid():
            return False
        
        with self._lock:
            # 1. Verification Phase (Read-only)
            for input_item in transaction.inputs:
                utxo = self.get_utxo(input_item.token_id)
                if not utxo:
                    return False  # UTXO doesn't exist or already spent
                
                # STRICT CRYPTO ENFORCEMENT: No '_original_payload' backdoor allowed.
                # The mock MUST test the exact same payload reconstruction as production.
                payload = CryptoUtils.create_token_payload({
                    "token_id": utxo.token_id,
                    "amount": utxo.amount,
                    "currency": utxo.currency,
                    "owner_public_key": utxo.owner_public_key
                })
                
                # Deserialize public key
                try:
                    public_key = CryptoUtils.deserialize_public_key(utxo.owner_public_key)
                    if not CryptoUtils.verify_signature(public_key, payload, input_item.signature):
                        return False  # Invalid signature
                except Exception:
                    return False  # Invalid public key or signature format
            
            # 2. Execution Phase (Write - Guaranteed to finish if we reach here)
            # Spend inputs
            for input_item in transaction.inputs:
                self.spend_utxo(input_item.token_id)
            
            # Create new UTXOs for outputs
            for output in transaction.outputs:
                new_utxo = UTXO(
                    token_id=str(uuid.uuid4()),
                    amount=output.amount,
                    currency=output.currency,
                    owner_public_key=output.owner_public_key,
                    lock_script=output.lock_script
                )
                self.add_utxo(new_utxo)
            
            return True
    
    def get_balance(self, public_key: str, currency: str = "INR") -> Decimal:
        """Get total balance for a public key in specific currency"""
        with self._lock:
            utxos = self.get_utxos_by_owner(public_key)
            # Use Decimal strictly to match production behavior
            balance = sum(
                (Decimal(str(utxo.amount)) for utxo in utxos if utxo.currency == currency),
                Decimal("0.00")
            )
            return balance
    
    def snapshot(self) -> Dict[str, Any]:
        """Get snapshot of current UTXO state securely handling Decimal/Datetime"""
        with self._lock:
            serialized_utxos = {}
            for k, v in self.utxos.items():
                data = v.model_dump()
                # Ensure Decimal and Datetime are serializable
                if 'amount' in data:
                    data['amount'] = str(data['amount'])
                if data.get('created_at') and isinstance(data['created_at'], datetime):
                    data['created_at'] = data['created_at'].isoformat()
                if data.get('expires_at') and isinstance(data['expires_at'], datetime):
                    data['expires_at'] = data['expires_at'].isoformat()
                    
                serialized_utxos[k] = data

            return {
                "utxos": serialized_utxos,
                "owner_index": {k: list(v) for k, v in self.owner_index.items()}
            }
    
    def restore(self, snapshot: Dict[str, Any]) -> bool:
        """Restore UTXO state from snapshot ATOMICALLY"""
        temp_utxos = {}
        temp_owner_index = {}
        
        try:
            # 1. Build temporary state (Validates data before destruction)
            for token_id, utxo_data in snapshot["utxos"].items():
                # Reconstruct types correctly
                if 'amount' in utxo_data:
                    utxo_data['amount'] = Decimal(str(utxo_data['amount']))
                if utxo_data.get('created_at') and isinstance(utxo_data['created_at'], str):
                    utxo_data['created_at'] = datetime.fromisoformat(utxo_data['created_at'])
                if utxo_data.get('expires_at') and isinstance(utxo_data['expires_at'], str):
                    utxo_data['expires_at'] = datetime.fromisoformat(utxo_data['expires_at'])
                
                utxo = UTXO(**utxo_data)
                temp_utxos[utxo.token_id] = utxo
                
                if utxo.owner_public_key not in temp_owner_index:
                    temp_owner_index[utxo.owner_public_key] = set()
                temp_owner_index[utxo.owner_public_key].add(utxo.token_id)
            
            # 2. Swap states atomically
            with self._lock:
                self.utxos = temp_utxos
                self.owner_index = temp_owner_index
                
            return True
            
        except Exception as e:
            # If parsing fails, the original state is preserved!
            print(f"Failed to restore state: {e}")
            return False