from __future__ import annotations

import hashlib
import json
import uuid
from datetime import datetime, timezone
from decimal import Decimal
from enum import Enum
from typing import Annotated, Any

from pydantic import (
    BaseModel,
    Field,
    model_validator,
    field_validator,
    AwareDatetime,
    UUID4,
)
from pydantic.functional_validators import AfterValidator

_DECIMAL_ZERO = Decimal("0.00")
MAX_METADATA_BYTES = 4096
MAX_SCRIPT_LENGTH = 2048


def _utc_now() -> AwareDatetime:
    return datetime.now(timezone.utc)


def _quantize_decimal(v: Decimal) -> Decimal:
    return v.quantize(_DECIMAL_ZERO)


CurrencyAmount = Annotated[
    Decimal,
    Field(gt=_DECIMAL_ZERO),
    AfterValidator(_quantize_decimal)
]

FeeAmount = Annotated[
    Decimal,
    Field(ge=_DECIMAL_ZERO),
    AfterValidator(_quantize_decimal)
]


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


_VALID_TRANSITIONS = {
    TransactionStatus.PENDING: {
        TransactionStatus.COMPLETED,
        TransactionStatus.FAILED,
        TransactionStatus.REJECTED,
        TransactionStatus.EXPIRED,
    },
    TransactionStatus.COMPLETED: frozenset(),
    TransactionStatus.FAILED: frozenset(),
    TransactionStatus.REJECTED: frozenset(),
    TransactionStatus.EXPIRED: frozenset(),
}


class UTXO(BaseModel):
    token_id: UUID4 = Field(default_factory=uuid.uuid4)
    amount: CurrencyAmount
    currency: Currency
    owner_public_key: str

    lock_script: str | None = Field(default=None, max_length=MAX_SCRIPT_LENGTH)

    created_at: AwareDatetime = Field(default_factory=_utc_now)
    expires_at: AwareDatetime | None = None

    @model_validator(mode="after")
    def validate_expiry(self) -> UTXO:
        if self.expires_at and self.expires_at <= self.created_at:
            raise ValueError("Expiry must be strictly later than creation time")
        return self


class TransactionInput(BaseModel):
    token_id: UUID4
    signature: str
    unlock_script: str | None = Field(default=None, max_length=MAX_SCRIPT_LENGTH)


class TransactionOutput(BaseModel):
    amount: CurrencyAmount
    currency: Currency
    owner_public_key: str
    lock_script: str | None = Field(default=None, max_length=MAX_SCRIPT_LENGTH)


class Transaction(BaseModel):
    transaction_id: UUID4 = Field(default_factory=uuid.uuid4)
    inputs: list[TransactionInput] = Field(..., min_length=1)
    outputs: list[TransactionOutput] = Field(..., min_length=1)

    fee: FeeAmount = _DECIMAL_ZERO
    timestamp: AwareDatetime = Field(default_factory=_utc_now)

    status: TransactionStatus = TransactionStatus.PENDING
    metadata: dict[str, Any] | None = None

    @field_validator("metadata")
    @classmethod
    def validate_metadata_constraints(cls, v: dict[str, Any] | None) -> dict[str, Any] | None:
        if v is not None:
            if "reserved" in v:
                raise ValueError("Metadata contains protected 'reserved' keys")
            if len(json.dumps(v)) > MAX_METADATA_BYTES:
                raise ValueError(f"Metadata payload exceeds {MAX_METADATA_BYTES} bytes limit")
        return v

    @model_validator(mode="after")
    def validate_currency_consistency(self) -> Transaction:
        target_currency = self.outputs[0].currency
        if any(out.currency != target_currency for out in self.outputs):
            raise ValueError("Mixed output currencies are not allowed in a single transaction")
        return self

    def advance_status(self, new_status: TransactionStatus) -> None:
        """Transitions transaction state enforcing terminal constraints."""
        allowed = _VALID_TRANSITIONS[self.status]
        if new_status not in allowed:
            raise ValueError(f"Illegal state transition from {self.status.value} to {new_status.value}")
        self.status = new_status

    def verify_economic_validity(self, input_utxos: list[UTXO]) -> None:
        """
        Validates value conservation (inputs = outputs + fee), input/output currency match,
        and ensures no input tokens are expired.
        """
        if len(input_utxos) != len(self.inputs):
            raise ValueError("Input UTXO count mismatches transaction input references")

        utxo_map = {utxo.token_id: utxo for utxo in input_utxos}
        target_currency = self.outputs[0].currency
        total_in = Decimal("0.00")

        now = _utc_now()
        for tx_in in self.inputs:
            utxo = utxo_map.get(tx_in.token_id)
            if not utxo:
                raise ValueError(f"Missing backing UTXO for input {tx_in.token_id}")
            
            if utxo.currency != target_currency:
                raise ValueError(f"Input currency mismatch: {utxo.currency} != {target_currency}")
                
            if utxo.expires_at and utxo.expires_at <= now:
                raise ValueError(f"Input UTXO {utxo.token_id} is expired")

            total_in += utxo.amount

        total_out = sum((out.amount for out in self.outputs), Decimal("0.00"))

        if total_in != (total_out + self.fee):
            raise ValueError(f"Value conservation violation: inputs({total_in}) != outputs({total_out}) + fee({self.fee})")

    def get_canonical_dict(self) -> dict[str, Any]:
        """Returns standard dictionary excluding volatile operational fields."""
        return self.model_dump(
            mode="json",
            exclude={"status", "metadata", "timestamp"}
        )

    def get_canonical_json(self) -> str:
        """Deterministically serializes transaction data for signing/hashing."""
        return json.dumps(
            self.get_canonical_dict(),
            sort_keys=True,
            separators=(",", ":")
        )

    def compute_hash(self) -> bytes:
        """Computes the SHA-256 hash of the canonical transaction representation."""
        payload = self.get_canonical_json().encode("utf-8")
        return hashlib.sha256(payload).digest()


class PaymentRequest(BaseModel):
    merchant_id: str
    amount: CurrencyAmount
    currency: Currency
    description: str | None = None
    callback_url: str | None = None
    expires_at: AwareDatetime | None = None

    @field_validator("expires_at")
    @classmethod
    def validate_future_expiry(cls, v: AwareDatetime | None) -> AwareDatetime | None:
        if v and v <= _utc_now():
            raise ValueError("Expiration must be a future datetime")
        return v


class PaymentResponse(BaseModel):
    transaction_id: UUID4
    status: TransactionStatus
    signed_transaction: Transaction | None = None
    error: str | None = None


class MintRequest(BaseModel):
    account_id: str
    amount: CurrencyAmount
    currency: Currency
    public_key: str
    bank_reference: str
    compliance_data: dict[str, Any] | None = None


class BurnRequest(BaseModel):
    token_ids: list[UUID4] = Field(..., min_length=1)
    account_id: str
    bank_reference: str
