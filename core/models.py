from __future__ import annotations

import uuid
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation
from enum import Enum
from typing import Optional, List, Dict, Any

from pydantic import BaseModel, Field, model_validator, field_validator

_DECIMAL_ZERO = Decimal("0.00")


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _normalize_decimal(value: Decimal) -> Decimal:
    try:
        return Decimal(str(value)).quantize(_DECIMAL_ZERO)
    except (InvalidOperation, ValueError):
        raise ValueError("invalid decimal value")


def _ensure_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        raise ValueError("datetime must be timezone aware")
    return value.astimezone(timezone.utc)

class Currency(str, Enum):
    INR = "INR"
    USD = "USD"
    EUR = "EUR"


class TokenType(str, Enum):
    PAYMENT = "PAYMENT"
    REFUND = "REFUND"
    MINT = "MINT"
    BURN = "BURN"


class TransactionStatus(str, Enum):
    PENDING = "PENDING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    REJECTED = "REJECTED"
    EXPIRED = "EXPIRED"

class UTXO(BaseModel):
    token_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    amount: Decimal = Field(..., gt=_DECIMAL_ZERO)
    currency: Currency
    owner_public_key: str

    lock_script: Optional[str] = None

    created_at: datetime = Field(default_factory=_utc_now)
    expires_at: Optional[datetime] = None

    @field_validator("amount")
    @classmethod
    def normalize_amount(cls, v: Decimal) -> Decimal:
        return _normalize_decimal(v)

    @field_validator("created_at", "expires_at")
    @classmethod
    def enforce_utc(cls, v: Optional[datetime]):
        if v is None:
            return v
        return _ensure_utc(v)

    @model_validator(mode="after")
    def validate_expiry(self) -> "UTXO":
        if self.expires_at and self.expires_at <= self.created_at:
            raise ValueError("expiry must be later than creation time")
        return self


class TransactionInput(BaseModel):
    token_id: str
    signature: str
    unlock_script: Optional[str] = None

    @field_validator("token_id")
    @classmethod
    def validate_uuid(cls, v: str) -> str:
        uuid.UUID(v)
        return v


class TransactionOutput(BaseModel):
    amount: Decimal = Field(..., gt=_DECIMAL_ZERO)
    currency: Currency
    owner_public_key: str
    lock_script: Optional[str] = None

    @field_validator("amount")
    @classmethod
    def normalize_amount(cls, v: Decimal) -> Decimal:
        return _normalize_decimal(v)


class Transaction(BaseModel):
    transaction_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    inputs: List[TransactionInput] = Field(..., min_length=1)
    outputs: List[TransactionOutput] = Field(..., min_length=1)

    fee: Decimal = Field(default=_DECIMAL_ZERO, ge=_DECIMAL_ZERO)
    timestamp: datetime = Field(default_factory=_utc_now)

    status: TransactionStatus = TransactionStatus.PENDING
    metadata: Optional[Dict[str, Any]] = None

    @field_validator("timestamp")
    @classmethod
    def validate_timestamp(cls, v: datetime):
        return _ensure_utc(v)

    @field_validator("fee")
    @classmethod
    def normalize_fee(cls, v: Decimal):
        return _normalize_decimal(v)

    @model_validator(mode="after")
    def validate_currency_consistency(self) -> "Transaction":
        currency = self.outputs[0].currency
        for out in self.outputs:
            if out.currency != currency:
                raise ValueError("mixed output currencies are not allowed")
        return self

class PaymentRequest(BaseModel):
    merchant_id: str
    amount: Decimal = Field(..., gt=_DECIMAL_ZERO)
    currency: Currency
    description: Optional[str] = None
    callback_url: Optional[str] = None
    expires_at: Optional[datetime] = None

    @field_validator("amount")
    @classmethod
    def normalize_amount(cls, v: Decimal):
        return _normalize_decimal(v)

    @field_validator("expires_at")
    @classmethod
    def validate_expiry(cls, v: Optional[datetime]):
        if v:
            v = _ensure_utc(v)
            if v <= _utc_now():
                raise ValueError("expiration must be in the future")
        return v


class PaymentResponse(BaseModel):
    transaction_id: str
    status: TransactionStatus
    signed_transaction: Optional[Transaction] = None
    error: Optional[str] = None


class MintRequest(BaseModel):
    account_id: str
    amount: Decimal = Field(..., gt=_DECIMAL_ZERO)
    currency: Currency
    public_key: str
    bank_reference: str
    compliance_data: Optional[Dict[str, Any]] = None

    @field_validator("amount")
    @classmethod
    def normalize_amount(cls, v: Decimal):
        return _normalize_decimal(v)


class BurnRequest(BaseModel):
    token_ids: List[str] = Field(..., min_length=1)
    account_id: str
    bank_reference: str

    @field_validator("token_ids")
    @classmethod
    def validate_ids(cls, ids: List[str]):
        for token_id in ids:
            uuid.UUID(token_id)
        return ids
