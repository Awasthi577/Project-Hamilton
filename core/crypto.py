from __future__ import annotations

import base64
import binascii
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation
from typing import Dict, Any, Optional, Tuple

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature


_DECIMAL_QUANT = Decimal("0.00")


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _b64encode(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _b64decode(data: str) -> bytes:
    try:
        return base64.b64decode(data, validate=True)
    except binascii.Error:
        raise ValueError("invalid base64 encoding")


def _normalize_amount(value: Any) -> str:
    try:
        dec = Decimal(str(value))
        return str(dec.quantize(_DECIMAL_QUANT))
    except (InvalidOperation, ValueError):
        raise ValueError("invalid monetary amount")


def _canonical_json(obj: Dict[str, Any]) -> str:
    return json.dumps(
        obj,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )

class KeyPair:
    __slots__ = ("private", "public")

    def __init__(
        self,
        private: Ed25519PrivateKey,
        public: Ed25519PublicKey,
    ):
        self.private = private
        self.public = public

    @classmethod
    def generate(cls) -> "KeyPair":
        private = Ed25519PrivateKey.generate()
        return cls(private, private.public_key())


def serialize_public_key(key: Ed25519PublicKey) -> str:
    raw = key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return _b64encode(raw)


def load_public_key(data: str) -> Ed25519PublicKey:
    raw = _b64decode(data)
    if len(raw) != 32:
        raise ValueError("invalid ed25519 public key length")
    return Ed25519PublicKey.from_public_bytes(raw)


def serialize_private_key(
    key: Ed25519PrivateKey,
    password: Optional[str] = None,
) -> str:

    if password is not None and len(password) < 8:
        raise ValueError("password too short")

    enc = (
        serialization.BestAvailableEncryption(password.encode())
        if password
        else serialization.NoEncryption()
    )

    pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=enc,
    )

    return _b64encode(pem)


def load_private_key(
    data: str,
    password: Optional[str] = None,
) -> Ed25519PrivateKey:

    pem = _b64decode(data)

    try:
        return serialization.load_pem_private_key(
            pem,
            password=password.encode() if password else None,
        )
    except ValueError as exc:
        msg = str(exc).lower()
        if "decrypt" in msg:
            raise ValueError("incorrect password")
        raise ValueError("invalid private key")

def sign_bytes(key: Ed25519PrivateKey, message: bytes) -> str:
    sig = key.sign(message)
    return _b64encode(sig)


def verify_bytes(
    key: Ed25519PublicKey,
    message: bytes,
    signature: str,
) -> bool:
    try:
        key.verify(_b64decode(signature), message)
        return True
    except (InvalidSignature, ValueError):
        return False

REQUIRED_FIELDS = (
    "token_id",
    "amount",
    "currency",
    "owner_public_key",
)


@dataclass(frozen=True)
class TokenPayload:
    token_id: str
    amount: str
    currency: str
    owner_public_key: str
    version: int = 1
    key_id: str = "v1"
    type: str = "upi_token"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "token_id": self.token_id,
            "amount": self.amount,
            "currency": self.currency,
            "owner_public_key": self.owner_public_key,
            "version": self.version,
            "key_id": self.key_id,
            "type": self.type,
        }


def build_payload(data: Dict[str, Any]) -> str:
    for field in REQUIRED_FIELDS:
        if field not in data:
            raise ValueError(f"missing field: {field}")

    payload = TokenPayload(
        token_id=str(data["token_id"]),
        amount=_normalize_amount(data["amount"]),
        currency=str(data["currency"]),
        owner_public_key=str(data["owner_public_key"]),
    )

    return _canonical_json(payload.to_dict())


def create_signed_token(
    private_key: Ed25519PrivateKey,
    token_data: Dict[str, Any],
) -> Dict[str, str]:

    payload = build_payload(token_data)

    signature = sign_bytes(
        private_key,
        payload.encode("utf-8"),
    )

    return {
        "payload": payload,
        "signature": signature,
        "public_key": serialize_public_key(
            private_key.public_key()
        ),
        "created_at": _utc_now(),
    }


def verify_signed_token(token: Dict[str, str]) -> bool:
    try:
        payload = token["payload"]
        signature = token["signature"]
        pub = load_public_key(token["public_key"])
    except KeyError:
        return False

    return verify_bytes(
        pub,
        payload.encode("utf-8"),
        signature,
    )
