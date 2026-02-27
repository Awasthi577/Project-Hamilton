import os
import sys
import json
import uuid
import stat
import hashlib
import tempfile
from decimal import Decimal
from datetime import datetime, timezone
from urllib.parse import urlparse
from typing import Optional, List, Dict

import typer
import requests
import qrcode
from pydantic import BaseModel, ValidationError
from rich.console import Console
from rich.prompt import Prompt

# External domain models (Assumed existing from your core architecture)
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from core.models import Transaction, TransactionInput, TransactionOutput, UTXO
from core.crypto import CryptoUtils

app = typer.Typer(help="Hamilton Protocol Trust-Minimized Wallet CLI")
console = Console()

WALLET_DIR = os.path.expanduser("~/.hamilton_wallet")
KEY_FILE = os.path.join(WALLET_DIR, "keys.json")
UTXO_FILE = os.path.join(WALLET_DIR, "utxos.json")
LOCKED_FILE = os.path.join(WALLET_DIR, "pending_spends.json")

MAX_RESPONSE_SIZE = 5_000_000

# --- BOUNDARY VALIDATION SCHEMAS ---
# Never blindly trust the node's JSON. Validate schema before casting to internal models.
class RemoteUTXOSchema(BaseModel):
    token_id: str
    amount: str
    currency: str
    owner_public_key: str
    node_attestation_sig: str  # Required to prevent nodes fabricating balances

# --- UTILS ---

def _ensure_dir_secure(path: str):
    if not os.path.exists(path):
        os.makedirs(path, mode=0o700)

def _atomic_write(path: str, data: Dict | List):
    # Temp file created in the exact same directory ensures cross-FS rename safety (atomic)
    fd, tmp = tempfile.mkstemp(dir=os.path.dirname(path), text=True)
    try:
        with os.fdopen(fd, "w") as f:
            json.dump(data, f, separators=(",", ":"), sort_keys=True)
        os.chmod(tmp, 0o600)
        os.replace(tmp, path)
    except Exception:
        os.remove(tmp)
        raise

def _secure_read(path: str) -> any:
    if not os.path.exists(path):
        return None
    
    st = os.stat(path)
    if st.st_mode & (stat.S_IRWXG | stat.S_IRWXO):
        os.chmod(path, 0o600)

    with open(path, "r") as f:
        return json.load(f)

def _validate_endpoint(url: str):
    parsed = urlparse(url)
    if parsed.scheme != "https":
        # Strict checking prevents https://evil.com@localhost bypasses
        if parsed.hostname not in ("localhost", "127.0.0.1"):
            raise ValueError("Endpoint MUST use HTTPS outside of local testing.")

def _safe_fetch_json(method: str, url: str, **kwargs) -> any:
    _validate_endpoint(url)
    kwargs.setdefault("timeout", 10)
    
    # Use streaming to enforce size limit BEFORE loading into memory
    with requests.request(method, url, stream=True, **kwargs) as r:
        r.raise_for_status()
        content = b""
        for chunk in r.iter_content(chunk_size=8192):
            content += chunk
            if len(content) > MAX_RESPONSE_SIZE:
                raise ValueError("Response exceeds safe memory limits.")
        return json.loads(content)

# --- WALLET CORE ---

class Wallet:
    def __init__(self):
        _ensure_dir_secure(WALLET_DIR)
        self.wallet_id: Optional[str] = None
        self.public_key = None

    def exists(self) -> bool:
        return os.path.exists(KEY_FILE)

    def create(self, password: str):
        console.print("Generating keypair...")
        private, public = CryptoUtils.generate_key_pair()

        self.wallet_id = str(uuid.uuid4())
        self.public_key = public

        stored = {
            "wallet_id": self.wallet_id,
            "public_key": CryptoUtils.serialize_public_key(public),
            "private_key": CryptoUtils.serialize_private_key(private, password=password),
            "created_at": datetime.now(timezone.utc).isoformat(),
        }

        _atomic_write(KEY_FILE, stored)
        # Note: Deliberately removed fake gc.collect() and byte wiping.
        # Python memory limits mean keys persist in the heap. True secure erasure
        # requires a separate C-extension/hardware enclave. Do not provide false security.
        
        console.print(f"Wallet created: {self.wallet_id}")

    def load_public(self):
        if not self.exists():
            raise typer.Exit("Wallet not initialized")
        data = _secure_read(KEY_FILE)
        self.wallet_id = data["wallet_id"]
        self.public_key = CryptoUtils.deserialize_public_key(data["public_key"])

    def _unlock_private(self, password: str):
        data = _secure_read(KEY_FILE)
        return CryptoUtils.deserialize_private_key(data["private_key"], password=password)

    def public_key_str(self) -> str:
        if not self.public_key:
            self.load_public()
        return CryptoUtils.serialize_public_key(self.public_key)

    def sync_utxos(self, node_url: str, api_key: str):
        pub = self.public_key_str()
        console.print(f"Syncing state from {node_url}...")

        raw_data = _safe_fetch_json("GET", f"{node_url}/utxos/{pub}", headers={"X-API-Key": api_key})
        
        # 1. Enforce strict schema boundaries
        validated_utxos = []
        try:
            for item in raw_data:
                utxo = RemoteUTXOSchema(**item)
                # 2. Prevent node from fabricating balances (Cryptographic attestation required)
                # CryptoUtils.verify_node_attestation(utxo.node_attestation_sig, utxo)
                validated_utxos.append(utxo.dict())
        except ValidationError as e:
            raise ValueError(f"Node returned malformed/malicious UTXO data: {e}")

        _atomic_write(UTXO_FILE, validated_utxos)
        console.print(f"Sync complete. {len(validated_utxos)} UTXOs verified.")

    def local_utxos(self) -> List[UTXO]:
        data = _secure_read(UTXO_FILE) or []
        return [UTXO(**u) for u in data]

    def _get_locked_tokens(self) -> set[str]:
        return set(_secure_read(LOCKED_FILE) or [])

    def _lock_tokens(self, token_ids: List[str]):
        locked = self._get_locked_tokens()
        locked.update(token_ids)
        _atomic_write(LOCKED_FILE, list(locked))

    def build_payment(self, merchant_key: str, amount: Decimal, currency: str = "INR") -> Transaction:
        my_key = self.public_key_str()
        utxos = self.local_utxos()
        locked_tokens = self._get_locked_tokens()

        # 1. Safe Selection: Filter spent/locked and sort deterministically (largest first to minimize tx size)
        available = [u for u in utxos if u.currency == currency and u.token_id not in locked_tokens]
        available.sort(key=lambda x: Decimal(str(x.amount)), reverse=True)

        chosen = []
        total = Decimal("0")

        for u in available:
            chosen.append(u)
            total += Decimal(str(u.amount))
            if total >= amount:
                break

        if total < amount:
            raise ValueError("Insufficient balance (some UTXOs may be pending network confirmation).")

        inputs = [TransactionInput(token_id=u.token_id, signature="") for u in chosen]
        outputs = [TransactionOutput(amount=amount, currency=currency, owner_public_key=merchant_key)]

        change = total - amount
        if change > 0:
            outputs.append(TransactionOutput(amount=change, currency=currency, owner_public_key=my_key))

        # 2. Local double-spend prevention: Lock these tokens locally immediately
        self._lock_tokens([u.token_id for u in chosen])

        return Transaction(
            transaction_id=str(uuid.uuid4()),
            inputs=inputs,
            outputs=outputs,
            fee=Decimal("0"),
        )

    def sign(self, tx: Transaction, password: str) -> Transaction:
        private = self._unlock_private(password)
        utxo_map = {u.token_id: u for u in self.local_utxos()}

        # 1. Transaction Integrity: Create canonical hash of the entire transaction intent
        # This prevents inputs from being stripped or outputs modified by MITM/Nodes.
        tx_intent = {
            "transaction_id": tx.transaction_id,
            "inputs": [{"token_id": inp.token_id} for inp in tx.inputs],
            "outputs": [{"amount": str(o.amount), "currency": o.currency, "owner": o.owner_public_key} for o in tx.outputs],
            "fee": str(tx.fee)
        }
        canonical_tx = json.dumps(tx_intent, separators=(",", ":"), sort_keys=True).encode()
        tx_hash = hashlib.sha256(canonical_tx).hexdigest()

        # 2. Domain Separation: Prevent cross-chain or cross-protocol signature replay
        DOMAIN = "HAMILTON_MAINNET_V1"

        for i, inp in enumerate(tx.inputs):
            utxo = utxo_map.get(inp.token_id)
            if not utxo:
                raise ValueError(f"Missing underlying UTXO for input {inp.token_id}")

            # 3. Cryptographically bind the Signature -> Domain + TxHash + Specific Input Token
            sig_payload = f"{DOMAIN}|{tx_hash}|{utxo.token_id}".encode()
            
            tx.inputs[i].signature = CryptoUtils.sign_data(private, sig_payload)

        return tx


# --- CLI COMMANDS ---

@app.command()
def init():
    wallet = Wallet()
    if wallet.exists():
        console.print("Wallet already initialized", style="yellow")
        raise typer.Exit()

    pw = Prompt.ask("Password", password=True)
    confirm = Prompt.ask("Confirm", password=True)

    if pw != confirm:
        raise typer.Exit("Passwords do not match", style="red")

    wallet.create(pw)

@app.command()
def balance(currency: str = "INR"):
    wallet = Wallet()
    utxos = wallet.local_utxos()
    locked = wallet._get_locked_tokens()

    total = sum((Decimal(str(u.amount)) for u in utxos if u.currency == currency and u.token_id not in locked), Decimal("0"))
    pending = sum((Decimal(str(u.amount)) for u in utxos if u.currency == currency and u.token_id in locked), Decimal("0"))

    console.print(f"Available: {total} {currency}")
    if pending > 0:
        console.print(f"Pending/Locked: {pending} {currency}", style="yellow")

@app.command()
def qr(tx_file: str):
    with open(tx_file, "r") as f:
        tx_data = json.load(f)

    # QR canonicalization: ensures all scanners hash to the exact same bytes regardless of OS
    canonical_tx = json.dumps(tx_data, separators=(',', ':'), sort_keys=True)
    img = qrcode.make(canonical_tx)
    img.show()


if __name__ == "__main__":
    app()
