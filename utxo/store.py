"""
UTXO State Store using Redis - Secure, Atomic, and High-Performance
"""
import redis
import json
import uuid
import logging
from typing import Optional, List, Dict, Any
from datetime import datetime, timezone
from decimal import Decimal

# Assuming these are imported from your models
from core.models import UTXO, Transaction, TransactionInput, TransactionOutput
from core.crypto import CryptoUtils

logger = logging.getLogger(__name__)

class UTXOStore:
    """Production-Ready UTXO State Store using Redis"""
    
    def __init__(self, host: str = 'localhost', port: int = 6379, db: int = 0):
        """Initialize Redis connection pool for high concurrency and resilience"""
        # Connection pool prevents TCP port exhaustion under heavy load
        self.pool = redis.ConnectionPool(
            host=host, 
            port=port, 
            db=db, 
            decode_responses=True, # Automatically decodes utf-8
            max_connections=100,
            socket_timeout=5.0,    # Production safety: Prevent indefinite hangs
            retry_on_timeout=True  # Production safety: Handle transient network blips
        )
        self.redis = redis.Redis(connection_pool=self.pool)
        self._prefix = "utxo:"
        self._owner_prefix = "owner:"

    def _get_key(self, token_id: str) -> str:
        return f"{self._prefix}{token_id}"

    def _get_owner_key(self, public_key: str) -> str:
        return f"{self._owner_prefix}{public_key}"

    def add_utxo(self, utxo: UTXO) -> bool:
        """Add a new UTXO atomically"""
        utxo_key = self._get_key(utxo.token_id)
        owner_key = self._get_owner_key(utxo.owner_public_key)
        
        utxo_data = utxo.model_dump()
        
        # Serialize datetime and Decimal
        for key, value in utxo_data.items():
            if isinstance(value, datetime):
                utxo_data[key] = value.isoformat()
            elif isinstance(value, Decimal):
                utxo_data[key] = str(value)
                
        # Use pipeline to ensure both operations succeed or fail together
        pipe = self.redis.pipeline()
        pipe.set(utxo_key, json.dumps(utxo_data))
        pipe.sadd(owner_key, utxo.token_id)
        pipe.execute()
        
        return True

    def get_utxo(self, token_id: str) -> Optional[UTXO]:
        """Get a single UTXO by ID"""
        data = self.redis.get(self._get_key(token_id))
        if not data:
            return None
            
        return self._parse_utxo(data)

    def _parse_utxo(self, raw_json: str) -> UTXO:
        """Helper to parse JSON back to strict types"""
        utxo_data = json.loads(raw_json)
        
        if utxo_data.get('created_at'):
            utxo_data['created_at'] = datetime.fromisoformat(utxo_data['created_at'])
        if utxo_data.get('expires_at'):
            utxo_data['expires_at'] = datetime.fromisoformat(utxo_data['expires_at'])
        if utxo_data.get('amount'):
            utxo_data['amount'] = Decimal(str(utxo_data['amount']))
            
        return UTXO(**utxo_data)

    def get_utxos_by_owner(self, public_key: str) -> List[UTXO]:
        """Get all UTXOs owned by a public key (O(1) network roundtrip)"""
        owner_key = self._get_owner_key(public_key)
        token_ids = self.redis.smembers(owner_key)
        
        if not token_ids:
            return []
            
        # N+1 Query Fix: Use MGET to fetch all UTXOs in ONE network request
        keys = [self._get_key(tid) for tid in token_ids]
        raw_utxos = self.redis.mget(keys)
        
        utxos = []
        # Cleanup orphaned index entries if data is missing
        pipe = self.redis.pipeline()
        for i, raw_data in enumerate(raw_utxos):
            if raw_data:
                utxos.append(self._parse_utxo(raw_data))
            else:
                # Self-healing: Remove stale pointer from owner set
                pipe.srem(owner_key, list(token_ids)[i])
        
        if len(pipe.command_stack) > 0:
            pipe.execute()
            
        return utxos

    def process_transaction(self, transaction: Transaction) -> bool:
        """
        Process a transaction ATOMICALLY with optimistic locking.
        Prevents double-spending and partial state corruption.
        """
        if not transaction.is_valid():
            return False

        input_keys = [self._get_key(inp.token_id) for inp in transaction.inputs]
        
        # We must use a transaction pipeline to guarantee atomicity
        pipe = self.redis.pipeline()
        
        try:
            # WATCH monitors keys for changes. If another process modifies these UTXOs
            # before we call pipe.execute(), the transaction will safely abort (WatchError).
            pipe.watch(*input_keys)
            
            # 1. Fetch current state of inputs
            raw_inputs = pipe.mget(input_keys)
            if not all(raw_inputs):
                pipe.unwatch()
                return False # One or more UTXOs do not exist (already spent)
                
            utxos = [self._parse_utxo(raw) for raw in raw_inputs]
            
            # 2. Cryptographic Validation & Conservation of Mass (Infinite Money Check)
            total_in = Decimal("0.00")
            input_currency = utxos[0].currency if utxos else None
            
            for idx, utxo in enumerate(utxos):
                # Ensure no mixed currencies in inputs
                if utxo.currency != input_currency:
                    pipe.unwatch()
                    return False
                    
                # Reject transactions with unsupported lock scripts
                if utxo.lock_script and utxo.lock_script != "":
                    pipe.unwatch()
                    return False
                    
                total_in += Decimal(str(utxo.amount))
                
                inp = transaction.inputs[idx]
                payload = CryptoUtils.create_token_payload({
                    "token_id": utxo.token_id,
                    "amount": utxo.amount,
                    "currency": utxo.currency,
                    "owner_public_key": utxo.owner_public_key
                })
                
                try:
                    public_key = CryptoUtils.deserialize_public_key(utxo.owner_public_key)
                    if not CryptoUtils.verify_signature(public_key, payload, inp.signature):
                        pipe.unwatch()
                        return False 
                except Exception:
                    pipe.unwatch()
                    return False
            
            # Verify outputs match inputs exactly
            total_out = Decimal("0.00")
            for output in transaction.outputs:
                if output.currency != input_currency:
                    pipe.unwatch()
                    return False
                total_out += Decimal(str(output.amount))
                
            if total_in != (total_out + transaction.fee):
                logger.error(f"Value mismatch detected: IN {total_in} != OUT {total_out} + FEE {transaction.fee}")
                pipe.unwatch()
                return False
            
            # Create system UTXO for transaction fee to prevent deflationary fee destruction
            system_fee_utxo = UTXO(
                token_id=str(uuid.uuid4()),
                amount=transaction.fee,
                currency=input_currency,
                owner_public_key="system_fee_address",
                lock_script=""
            )
            
            # 3. Enter MULTI mode (all commands from here are queued and run atomically)
            pipe.multi()
            
            # Delete Inputs
            for utxo in utxos:
                pipe.delete(self._get_key(utxo.token_id))
                pipe.srem(self._get_owner_key(utxo.owner_public_key), utxo.token_id)
                
            # Create Outputs
            for output in transaction.outputs:
                new_id = str(uuid.uuid4())
                new_utxo = UTXO(
                    token_id=new_id,
                    amount=output.amount,
                    currency=output.currency,
                    owner_public_key=output.owner_public_key,
                    lock_script=output.lock_script
                )
                utxo_data = new_utxo.model_dump()
                utxo_data['amount'] = str(utxo_data['amount'])
                
                pipe.set(self._get_key(new_id), json.dumps(utxo_data))
                pipe.sadd(self._get_owner_key(output.owner_public_key), new_id)
            
            # Add system fee UTXO
            fee_utxo_data = system_fee_utxo.model_dump()
            fee_utxo_data['amount'] = str(fee_utxo_data['amount'])
            pipe.set(self._get_key(system_fee_utxo.token_id), json.dumps(fee_utxo_data))
            pipe.sadd(self._get_owner_key(system_fee_utxo.owner_public_key), system_fee_utxo.token_id)
                
            # EXECUTE! (Will throw WatchError if another thread touched the inputs)
            pipe.execute()
            return True
            
        except redis.WatchError:
            # Race condition detected: another process spent this UTXO first.
            return False
        finally:
            # Ensure connection is cleaned up
            pipe.reset()

    def get_balance(self, public_key: str, currency: str = "INR") -> Decimal:
        """Get total balance (Using strict Decimals)"""
        utxos = self.get_utxos_by_owner(public_key)
        balance = sum(
            (Decimal(str(utxo.amount)) for utxo in utxos if utxo.currency == currency),
            Decimal("0.00")
        )
        return balance

    def snapshot(self) -> Dict[str, Any]:
        """
        Get snapshot safely without blocking the Redis event loop.
        Uses SCAN instead of KEYS.
        WARNING: Application-level snapshots are not recommended for production backups.
        Use Redis native RDB/AOF persistence instead.
        """
        logger.warning("snapshot() called. Use Redis RDB/AOF for production backups.")
        snapshot = {}
        # scan_iter acts as a Python generator, fetching keys in small batches
        for key in self.redis.scan_iter(match=f"{self._prefix}*"):
            token_id = key.replace(self._prefix, '')
            raw_data = self.redis.get(key)
            if raw_data:
                snapshot[token_id] = json.loads(raw_data)
                
        return snapshot

    def restore(self, snapshot: Dict[str, Any]) -> bool:
        """
        Restore state safely using pipelines, targeting ONLY utxo keys.
        NO FLUSHDB allowed.
        WARNING: This is a destructive operation. Avoid in live production systems.
        """
        logger.warning("restore() called. This is destructive and can drop active requests.")
        pipe = self.redis.pipeline()
        
        # 1. Safely clear ONLY existing UTXO indices and data
        for key in self.redis.scan_iter(match=f"{self._prefix}*"):
            pipe.delete(key)
        for key in self.redis.scan_iter(match=f"{self._owner_prefix}*"):
            pipe.delete(key)
            
        # 2. Rebuild state
        for token_id, utxo_data in snapshot.items():
            # Standardize Decimal back from snapshot string if needed
            if 'amount' in utxo_data:
                utxo_data['amount'] = str(utxo_data['amount'])
                
            utxo_key = self._get_key(token_id)
            owner_key = self._get_owner_key(utxo_data['owner_public_key'])
            
            pipe.set(utxo_key, json.dumps(utxo_data))
            pipe.sadd(owner_key, token_id)
            
        pipe.execute()
        return True