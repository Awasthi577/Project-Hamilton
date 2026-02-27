"""
Cryptographic utilities for UPI 2.0
Strict, Deterministic, and Type-Safe Implementation
"""
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature

from typing import Optional, Dict, Any
from decimal import Decimal, InvalidOperation
from datetime import datetime
import base64
import json
import binascii

class CanonicalJSONEncoder(json.JSONEncoder):
    """
    Custom JSON Encoder for Cryptographic Canonicalization.
    Ensures Decimals and Datetimes are serialized consistently across all nodes.
    """
    def default(self, obj: Any) -> Any:
        if isinstance(obj, Decimal):
            # Quantize to exactly 2 decimal places to prevent float drift and precision manipulation
            return str(obj.quantize(Decimal('0.00')))
        if isinstance(obj, datetime):
            return obj.isoformat()
        return super().default(obj)

class CryptoUtils:
    """Cryptographic utilities for deterministic token signing and verification"""
    
    @staticmethod
    def generate_key_pair() -> tuple[ed25519.Ed25519PrivateKey, ed25519.Ed25519PublicKey]:
        """Generate Ed25519 key pair"""
        private_key = ed25519.Ed25519PrivateKey.generate()
        public_key = private_key.public_key()
        return private_key, public_key
    
    @staticmethod
    def serialize_public_key(public_key: ed25519.Ed25519PublicKey) -> str:
        """Serialize public key to base64 (Raw format for compactness)"""
        public_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
        return base64.b64encode(public_bytes).decode('utf-8')
    
    @staticmethod
    def deserialize_public_key(public_key_str: str) -> ed25519.Ed25519PublicKey:
        """Deserialize public key from base64"""
        try:
            public_bytes = base64.b64decode(public_key_str)
            return ed25519.Ed25519PublicKey.from_public_bytes(public_bytes)
        except (binascii.Error, ValueError) as e:
            raise ValueError(f"Invalid public key format: {e}")
    
    @staticmethod
    def serialize_private_key(private_key: ed25519.Ed25519PrivateKey, password: Optional[str] = None) -> str:
        """
        Serialize private key to base64. 
        Uniformly uses PKCS8 PEM format for both encrypted and unencrypted keys.
        """
        # Enforce minimum entropy for wallet password protection
        if password is not None and len(password) < 8:
            raise ValueError("Password must be at least 8 characters long to secure the local wallet.")

        encryption_alg = (
            serialization.BestAvailableEncryption(password.encode('utf-8')) 
            if password 
            else serialization.NoEncryption()
        )
        
        pem_bytes = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=encryption_alg
        )
        return base64.b64encode(pem_bytes).decode('utf-8')
    
    @staticmethod
    def deserialize_private_key(private_key_str: str, password: Optional[str] = None) -> ed25519.Ed25519PrivateKey:
        """
        Deserialize private key from base64.
        Strictly handles password failures without falling back to raw bytes.
        """
        try:
            pem_bytes = base64.b64decode(private_key_str)
            return serialization.load_pem_private_key(
                pem_bytes,
                password=password.encode('utf-8') if password else None,
                backend=default_backend()
            )
        except ValueError as e:
            # Handles varying OpenSSL error formats
            if "Bad decrypt" in str(e) or "bad decrypt" in str(e).lower():
                raise ValueError("Incorrect wallet password.")
            raise ValueError(f"Corrupted or invalid private key: {e}")
        except binascii.Error:
            raise ValueError("Key is not valid base64.")
    
    @staticmethod
    def sign_data(private_key: ed25519.Ed25519PrivateKey, data: str) -> str:
        """Sign exact string data with Ed25519 private key"""
        signature = private_key.sign(data.encode('utf-8'))
        return base64.b64encode(signature).decode('utf-8')
    
    @staticmethod
    def verify_signature(public_key: ed25519.Ed25519PublicKey, data: str, signature: str) -> bool:
        """
        Verify signature securely. 
        Only catches exact cryptographic failures, allowing systemic errors to surface.
        """
        try:
            sig_bytes = base64.b64decode(signature)
            public_key.verify(sig_bytes, data.encode('utf-8'))
            return True
        except InvalidSignature:
            return False
        except (binascii.Error, ValueError):
            return False # Malformed base64 signature
    
    @staticmethod
    def create_token_payload(token_data: Dict[str, Any]) -> str:
        """
        Creates a deterministic, Canonical JSON payload for signing.
        Fails loudly if required fields are missing instead of generating random data.
        """
        required_fields = ["token_id", "amount", "currency", "owner_public_key"]
        for field in required_fields:
            if field not in token_data:
                raise ValueError(f"Cannot sign payload: Missing required field '{field}'")
                
        # Precision Locking: Format the amount exactly before hashing to prevent malleability
        try:
            strict_amount = str(Decimal(str(token_data["amount"])).quantize(Decimal("0.00")))
        except InvalidOperation:
            raise ValueError(f"Invalid currency amount format: {token_data['amount']}")

        # Build exact structure to be signed, enforcing strings to prevent JSON object injection
        payload = {
            "token_id": str(token_data["token_id"]),
            "amount": strict_amount,
            "currency": str(token_data["currency"]),
            "owner_public_key": str(token_data["owner_public_key"]),
            "type": "upi_token",
            "key_id": "v1",  # Key versioning field
            "version": 1     # Version field for future key rotation
        }
        
        # sort_keys=True is CRITICAL for deterministic cryptographic signatures
        return json.dumps(
            payload, 
            separators=(',', ':'), 
            sort_keys=True, 
            cls=CanonicalJSONEncoder
        )
    
    @staticmethod
    def generate_token_signature(private_key: ed25519.Ed25519PrivateKey, payload: str) -> str:
        """Generate token signature directly from payload string"""
        return CryptoUtils.sign_data(private_key, payload)
    
    @staticmethod
    def create_signed_token(private_key: ed25519.Ed25519PrivateKey, token_data: Dict[str, Any]) -> Dict[str, Any]:
        """Create a complete signed token dictionary"""
        payload_str = CryptoUtils.create_token_payload(token_data)
        signature = CryptoUtils.generate_token_signature(private_key, payload_str)
        
        return {
            "payload": payload_str,
            "signature": signature,
            "public_key": CryptoUtils.serialize_public_key(private_key.public_key())
        }