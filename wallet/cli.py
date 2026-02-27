from __future__ import annotations

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
from typing import Optional, List, Dict

import typer
from rich.console import Console
from rich.prompt import Prompt
import qrcode

# local imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.models import Transaction, TransactionInput, TransactionOutput, UTXO
from core.crypto import CryptoUtils


app = typer.Typer()
console = Console()

WALLET_DIR = os.path.expanduser("~/.hamilton_wallet")
KEY_FILE = os.path.join(WALLET_DIR, "keys.json")
UTXO_FILE = os.path.join(WALLET_DIR, "utxos.json")

MAX_RESPONSE_SIZE = 5_000_000

def ensure_wallet_dir():
    if not os.path.exists(WALLET_DIR):
        os.makedirs(WALLET_DIR, mode=0o700)
    os.chmod(WALLET_DIR, 0o700)


def _atomic_write(path: str, data: Dict):
    fd, tmp = tempfile.mkstemp(dir=WALLET_DIR, text=True)
    try:
        with os.fdopen(fd, "w") as f:
            json.dump(data, f, indent=2)
        os.chmod(tmp, 0o600)
        os.replace(tmp, path)
    except Exception:
        os.remove(tmp)
        raise


def _secure_read(path: str):
    st = os.stat(path)
    if st.st_mode & (stat.S_IRWXG | stat.S_IRWXO):
        os.chmod(path, 0o600)

    with open(path, "r") as f:
        return json.load(f)


def _wipe_bytes(buf: bytearray):
    for i in range(len(buf)):
        buf[i] = 0
    gc.collect()

def validate_endpoint(url: str):
    if not url.startswith("https://") and "localhost" not in url:
        raise ValueError("endpoint must use HTTPS")


def safe_request(method: str, url: str, **kwargs):
    kwargs.setdefault("timeout", 10)
    r = requests.request(method, url, **kwargs)

    if len(r.content) > MAX_RESPONSE_SIZE:
        raise ValueError("response exceeds allowed size")

    return r

class Wallet:

    def __init__(self):
        ensure_wallet_dir()
        self.wallet_id: Optional[str] = None
        self.public_key = None

    def exists(self) -> bool:
        return os.path.exists(KEY_FILE)

    def create(self, password: str):
        console.print("Generating keys...")

        pwd = bytearray(password.encode())

        private, public = CryptoUtils.generate_key_pair()

        self.wallet_id = str(uuid.uuid4())
        self.public_key = public

        stored = {
            "wallet_id": self.wallet_id,
            "public_key": CryptoUtils.serialize_public_key(public),
            "private_key": CryptoUtils.serialize_private_key(
                private,
                password=password,
            ),
            "created_at": datetime.now(timezone.utc).isoformat(),
        }

        _atomic_write(KEY_FILE, stored)

        private = None
        _wipe_bytes(pwd)

        console.print(f"Wallet created: {self.wallet_id}")

    def load_public(self):
        if not self.exists():
            raise typer.Exit("Wallet not initialized")

        data = _secure_read(KEY_FILE)
        self.wallet_id = data["wallet_id"]
        self.public_key = CryptoUtils.deserialize_public_key(
            data["public_key"]
        )

    def _unlock_private(self, password: str):
        pwd = bytearray(password.encode())
        data = _secure_read(KEY_FILE)

        try:
            key = CryptoUtils.deserialize_private_key(
                data["private_key"],
                password=password,
            )
        finally:
            _wipe_bytes(pwd)

        return key

    def public_key_str(self) -> str:
        self.load_public()
        return CryptoUtils.serialize_public_key(self.public_key)

    def sync_utxos(self, node_url: str, api_key: str):
        validate_endpoint(node_url)

        pub = self.public_key_str()

        console.print(f"Syncing from {node_url}")

        r = safe_request(
            "GET",
            f"{node_url}/utxos/{pub}",
            headers={"X-API-Key": api_key},
        )

        if r.status_code != 200:
            raise ValueError("sync failed")

        _atomic_write(UTXO_FILE, r.json())
        console.print("Sync complete")

    def local_utxos(self) -> List[UTXO]:
        if not os.path.exists(UTXO_FILE):
            return []

        data = _secure_read(UTXO_FILE)
        return [UTXO(**u) for u in data]

    def build_payment(
        self,
        merchant_key: str,
        amount: Decimal,
        currency: str = "INR",
    ) -> Transaction:

        self.load_public()
        my_key = self.public_key_str()

        utxos = self.local_utxos()

        chosen = []
        total = Decimal("0")

        for u in utxos:
            if u.currency == currency:
                chosen.append(u)
                total += Decimal(str(u.amount))
                if total >= amount:
                    break

        if total < amount:
            raise ValueError("insufficient balance")

        inputs = [
            TransactionInput(token_id=u.token_id, signature="")
            for u in chosen
        ]

        outputs = [
            TransactionOutput(
                amount=amount,
                currency=currency,
                owner_public_key=merchant_key,
            )
        ]

        change = total - amount
        if change > 0:
            outputs.append(
                TransactionOutput(
                    amount=change,
                    currency=currency,
                    owner_public_key=my_key,
                )
            )

        return Transaction(
            transaction_id=str(uuid.uuid4()),
            inputs=inputs,
            outputs=outputs,
            fee=Decimal("0"),
        )

    

    def sign(self, tx: Transaction, password: str) -> Transaction:

        private = self._unlock_private(password)
        utxo_map = {u.token_id: u for u in self.local_utxos()}

        for i, inp in enumerate(tx.inputs):
            utxo = utxo_map.get(inp.token_id)
            if not utxo:
                raise ValueError("missing utxo")

            payload = CryptoUtils.create_token_payload(
                {
                    "token_id": utxo.token_id,
                    "amount": utxo.amount,
                    "currency": utxo.currency,
                    "owner_public_key": utxo.owner_public_key,
                }
            )

            tx.inputs[i].signature = CryptoUtils.sign_data(
                private,
                payload,
            )

        private = None
        gc.collect()

        return tx


@app.command()
def init():
    wallet = Wallet()

    if wallet.exists():
        console.print("Wallet already initialized")
        raise typer.Exit()

    pw = Prompt.ask("Password", password=True)
    confirm = Prompt.ask("Confirm", password=True)

    if pw != confirm:
        raise typer.Exit("Passwords do not match")

    wallet.create(pw)


@app.command()
def balance(currency: str = "INR"):
    wallet = Wallet()
    utxos = wallet.local_utxos()

    total = sum(
        (Decimal(str(u.amount)) for u in utxos if u.currency == currency),
        Decimal("0"),
    )

    console.print(f"{total} {currency}")


@app.command()
def qr(tx_file: str):
    with open(tx_file, "r") as f:
        tx = json.load(f)

    img = qrcode.make(json.dumps(tx))
    img.show()


if __name__ == "__main__":
    app()
