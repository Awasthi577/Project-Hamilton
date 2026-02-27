"""
Core data models for UPI 2.0 tokenized payment system
"""
from pydantic import BaseModel, Field, model_validator
from typing import Optional, List, Dict, Any
from datetime import datetime, timezone
from decimal import Decimal
from enum import Enum
import uuid

# ==========================================
# 1. ENUMS
# ==========================================
class Currency(str, Enum):
    """Supported fiat and digital currencies"""
    INR = "INR"
    USD = "USD"
    EUR = "EUR"

class TokenType(str, Enum):
    """Token lifecycle types"""
    PAYMENT = "PAYMENT"
    REFUND = "REFUND"
    MINT = "MINT"
    BURN = "BURN"

class TransactionStatus(str, Enum):
    """Transaction state machine statuses (Uppercase to match APIs)"""
    PENDING = "PENDING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    REJECTED = "REJECTED"
    EXPIRED = "EXPIRED"

# ==========================================
# 2. CORE DOMAIN MODELS
# ==========================================
class UTXO(BaseModel):
    """Unspent Transaction Output - represents a tokenized amount on the ledger"""
    token_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    # Strict decimal > 0 constraint
    amount: Decimal = Field(..., gt=Decimal("0.00"))
    currency: Currency
    owner_public_key: str
    
    # Smart contract conditions (Must be strictly evaluated by a VM, never eval())
    lock_script: Optional[str] = None 
    
    # Timezone-aware datetimes
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    expires_at: Optional[datetime] = None
    
    class Config:
        json_schema_extra = {
            "example": {
                "token_id": "tok_abc123",
                "amount": "100.50",
                "currency": "INR",
                "owner_public_key": "pub_key_xyz"
            }
        }

class TransactionInput(BaseModel):
    """
    Input to a transaction - references a UTXO.
    CRITICAL SECURITY FIX: 'amount' has been removed. The core engine MUST look up 
    the true amount from the ledger using the token_id to prevent spoofing.
    """
    token_id: str
    signature: str  # Ed25519 cryptographic signature proving ownership
    unlock_script: Optional[str] = None  # Satisfies lock_script conditions if present

class TransactionOutput(BaseModel):
    """Output from a transaction - dictates the creation of new UTXOs"""
    amount: Decimal = Field(..., gt=Decimal("0.00"))
    currency: Currency
    owner_public_key: str
    lock_script: Optional[str] = None

class Transaction(BaseModel):
    """A structurally validated tokenized transaction"""
    transaction_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    
    # Must have at least one input and one output
    inputs: List[TransactionInput] = Field(..., min_length=1)
    outputs: List[TransactionOutput] = Field(..., min_length=1)
    
    # Fee cannot be negative (prevents infinite money glitch)
    fee: Decimal = Field(default=Decimal("0.00"), ge=Decimal("0.00"))
    
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    status: TransactionStatus = TransactionStatus.PENDING
    metadata: Optional[Dict[str, Any]] = None

    @model_validator(mode='after')
    def validate_structural_integrity(self) -> 'Transaction':
        """
        Validates structural integrity ONLY. 
        Cryptographic and balance validation MUST happen in the core engine.
        """
        # Ensure outputs don't mix currencies (e.g., trying to convert INR to USD without an exchange)
        if not self.outputs:
            return self
            
        first_currency = self.outputs[0].currency
        for out in self.outputs:
            if out.currency != first_currency:
                raise ValueError("Transaction outputs cannot contain mixed currencies.")
                
        return self

# ==========================================
# 3. API REQUEST/RESPONSE MODELS
# ==========================================
class PaymentRequest(BaseModel):
    """Payment request from merchant to wallet"""
    merchant_id: str
    amount: Decimal = Field(..., gt=Decimal("0.00"))
    currency: Currency
    description: Optional[str] = None
    callback_url: Optional[str] = None
    expires_at: Optional[datetime] = None

class PaymentResponse(BaseModel):
    """Payment response from wallet to merchant"""
    transaction_id: str
    status: TransactionStatus
    signed_transaction: Optional[Transaction] = None
    error: Optional[str] = None

class MintRequest(BaseModel):
    """Request to mint new tokens from bank deposits"""
    account_id: str
    amount: Decimal = Field(..., gt=Decimal("0.00"))
    currency: Currency
    # The destination public key for the minted money
    public_key: str 
    bank_reference: str
    compliance_data: Optional[Dict[str, Any]] = None

class BurnRequest(BaseModel):
    """Request to burn tokens and return fiat to bank"""
    # Must provide at least one token to burn
    token_ids: List[str] = Field(..., min_length=1)
    account_id: str
    bank_reference: str