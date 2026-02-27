"""
Edge Wallet CLI - Secure, Production-Ready Offline Payment Wallet
SECURITY HARDENED (Backward Compatible)
"""

import os
import sys
import json
import uuid
import stat
import tempfile
import requests
import gc
from decimal import Decimal
from datetime import datetime, timezone
from typing import Optional, List

import typer
from rich.console import Console
from rich.prompt import Prompt
import qrcode

# Setup path for local imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.models import Transaction, TransactionInput, TransactionOutput, UTXO
from core.crypto import CryptoUtils

app = typer.Typer(help="Hamilton Edge Wallet - Secure Offline Transactions")
console = Console()

WALLET_DIR = os.path.expanduser("~/.hamilton_wallet")
KEY_STORAGE = os.path.join(WALLET_DIR, "keys.json")
UTXO_CACHE = os.path.join(WALLET_DIR, "utxos.json")

# =====================================================
# SECURITY HELPERS (ADDED — NON BREAKING)
# =====================================================

MAX_RESPONSE_SIZE = 5_000_000  # 5MB safety limit


def _secure_delete(var):
    """Best-effort memory cleanup (Python limitation acknowledged)."""
    try:
        if isinstance(var, bytearray):
            for i in range(len(var)):
                var[i] = 0
    finally:
        var = None
        gc.collect()


def _validate_endpoint(url: str):
    """Prevent MITM except localhost."""
    if not url.startswith("https://") and "localhost" not in url:
        raise ValueError("Only HTTPS endpoints allowed (except localhost).")


def _safe_request(method: str, url: str, **kwargs):
    """Network safety wrapper."""
    kwargs.setdefault("timeout", 10)

    r = requests.request(method, url, **kwargs)

    if len(r.content) > MAX_RESPONSE_SIZE:
        raise ValueError("Server response too large")

    return r


def _secure_json_load(path: str):
    """Safe JSON loader with permission audit."""
    st = os.stat(path)
    if bool(st.st_mode & (stat.S_IRWXG | stat.S_IRWXO)):
        console.print("[yellow]Fixing insecure file permissions...[/yellow]")
        os.chmod(path, 0o600)

    with open(path, "r") as f:
        return json.load(f)


def _secure_write_json(path: str, data: dict):
    """Atomic + permission-safe write."""
    fd, temp_path = tempfile.mkstemp(dir=WALLET_DIR, text=True)
    try:
        with os.fdopen(fd, "w") as f:
            json.dump(data, f, indent=2)
        os.chmod(temp_path, 0o600)
        os.replace(temp_path, path)
    except Exception:
        os.remove(temp_path)
        raise


# =====================================================
# WALLET
# =====================================================

class SecureWallet:

    def __init__(self):
        self._ensure_secure_environment()
        self.wallet_id = None
        self.public_key = None

    def _ensure_secure_environment(self):
        if not os.path.exists(WALLET_DIR):
            os.makedirs(WALLET_DIR, mode=0o700)

        os.chmod(WALLET_DIR, 0o700)

    # -----------------------------
    # Wallet Creation
    # -----------------------------
    def create_wallet(self, password: str):

        console.print("[cyan]Generating cryptographic keys...[/cyan]")

        pwd = bytearray(password.encode())

        private_key, public_key = CryptoUtils.generate_key_pair()

        self.wallet_id = str(uuid.uuid4())
        self.public_key = public_key

        private_key_str = CryptoUtils.serialize_private_key(
            private_key, password=password
        )

        keys_data = {
            "wallet_id": self.wallet_id,
            "private_key_encrypted": private_key_str,
            "public_key": CryptoUtils.serialize_public_key(public_key),
            "created_at": datetime.now(timezone.utc).isoformat(),
        }

        _secure_write_json(KEY_STORAGE, keys_data)

        private_key = None
        _secure_delete(pwd)

        console.print("[green]Wallet created successfully![/green]")
        console.print(f"Wallet ID: {self.wallet_id}")

    # -----------------------------
    def is_initialized(self) -> bool:
        return os.path.exists(KEY_STORAGE)

    # -----------------------------
    def load_public_state(self):

        if not self.is_initialized():
            raise typer.Exit(console.print("[red]Wallet not initialized.[/red]"))

        keys_data = _secure_json_load(KEY_STORAGE)

        self.wallet_id = keys_data["wallet_id"]
        self.public_key = CryptoUtils.deserialize_public_key(
            keys_data["public_key"]
        )

    # -----------------------------
    def _get_decrypted_private_key(self, password: str):

        pwd = bytearray(password.encode())

        keys_data = _secure_json_load(KEY_STORAGE)

        try:
            key = CryptoUtils.deserialize_private_key(
                keys_data["private_key_encrypted"],
                password=password,
            )
        except Exception:
            _secure_delete(pwd)
            raise ValueError("Incorrect wallet password.")

        _secure_delete(pwd)
        return key

    # -----------------------------
    def get_public_key_str(self) -> str:
        self.load_public_state()
        return CryptoUtils.serialize_public_key(self.public_key)

    # -----------------------------
    # Sync UTXOs
    # -----------------------------
    def sync_utxos(self, node_url: str, api_key: Optional[str] = None):

        _validate_endpoint(node_url)

        pub_key_str = self.get_public_key_str()

        if api_key is None:
            api_key = os.getenv("HAMILTON_API_KEY")
            if api_key is None:
                raise ValueError("API key required")

        console.print(f"[cyan]Syncing UTXOs from {node_url}...[/cyan]")

        response = _safe_request(
            "GET",
            f"{node_url}/utxos/{pub_key_str}",
            headers={"X-API-Key": api_key},
        )

        if response.status_code != 200:
            raise ValueError("Failed to sync")

        _secure_write_json(UTXO_CACHE, response.json())

        console.print("[green]UTXO sync complete.[/green]")

    # -----------------------------
    def get_local_utxos(self) -> List[UTXO]:

        if not os.path.exists(UTXO_CACHE):
            return []

        data = _secure_json_load(UTXO_CACHE)
        return [UTXO(**u) for u in data]

    # -----------------------------
    def prepare_unsigned_payment(
        self, merchant_id: str, amount: Decimal, currency: str = "INR"
    ) -> Transaction:

        if len(merchant_id) < 32:
            raise ValueError("Invalid merchant public key")

        self.load_public_state()
        pub_key_str = self.get_public_key_str()

        utxos = self.get_local_utxos()

        selected = []
        total_amount = Decimal("0")

        for utxo in utxos:
            if utxo.currency == currency:
                selected.append(utxo)
                total_amount += Decimal(str(utxo.amount))
                if total_amount >= amount:
                    break

        if total_amount < amount:
            raise ValueError("Insufficient funds")

        inputs = [
            TransactionInput(token_id=u.token_id, signature="")
            for u in selected
        ]

        outputs = [
            TransactionOutput(
                amount=amount,
                currency=currency,
                owner_public_key=merchant_id,
            )
        ]

        change = total_amount - amount
        if change > 0:
            outputs.append(
                TransactionOutput(
                    amount=change,
                    currency=currency,
                    owner_public_key=pub_key_str,
                )
            )

        return Transaction(
            transaction_id=str(uuid.uuid4()),
            inputs=inputs,
            outputs=outputs,
            fee=Decimal("0"),
        )

    # -----------------------------
    def sign_transaction(self, tx: Transaction, password: str) -> Transaction:

        private_key = self._get_decrypted_private_key(password)
        local_utxos = {u.token_id: u for u in self.get_local_utxos()}

        for idx, input_item in enumerate(tx.inputs):

            utxo = local_utxos.get(input_item.token_id)
            if not utxo:
                raise ValueError("UTXO missing")

            payload = CryptoUtils.create_token_payload(
                {
                    "token_id": utxo.token_id,
                    "amount": utxo.amount,
                    "currency": utxo.currency,
                    "owner_public_key": utxo.owner_public_key,
                }
            )

            tx.inputs[idx].signature = CryptoUtils.sign_data(
                private_key, payload
            )

        private_key = None
        gc.collect()

        return tx

# =====================================================
# CLI COMMANDS (UNCHANGED)
# =====================================================

@app.command()
def init():
    wallet = SecureWallet()

    if wallet.is_initialized():
        console.print("[yellow]Wallet already exists.[/yellow]")
        raise typer.Exit()

    password = Prompt.ask("Enter wallet password", password=True)
    confirm = Prompt.ask("Confirm password", password=True)

    if password != confirm:
        console.print("[red]Passwords do not match[/red]")
        raise typer.Exit(1)

    wallet.create_wallet(password)


@app.command()
def balance(currency: str = "INR"):
    wallet = SecureWallet()
    utxos = wallet.get_local_utxos()

    bal = sum(
        (Decimal(str(u.amount)) for u in utxos if u.currency == currency),
        Decimal("0"),
    )

    console.print(f"[bold green]{bal} {currency}[/bold green]")


if __name__ == "__main__":
    app()