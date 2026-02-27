"""
Simple system test for UPI 2.0
"""
import sys
import os

# Add the parent directory to Python path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.models import UTXO, Transaction, TransactionInput, TransactionOutput, Currency
from core.crypto import CryptoUtils
from utxo.mock_store import MockUTXOStore
import uuid
from datetime import datetime

def test_crypto():
    """Test cryptographic functions"""
    print("Testing cryptographic functions...")
    
    # Generate key pair
    private_key, public_key = CryptoUtils.generate_key_pair()
    
    # Serialize keys
    public_key_str = CryptoUtils.serialize_public_key(public_key)
    private_key_str = CryptoUtils.serialize_private_key(private_key, password="test")
    
    # Deserialize keys
    deserialized_public_key = CryptoUtils.deserialize_public_key(public_key_str)
    deserialized_private_key = CryptoUtils.deserialize_private_key(private_key_str, password="test")
    
    # Test signing
    test_data = "Hello, UPI 2.0!"
    signature = CryptoUtils.sign_data(deserialized_private_key, test_data)
    
    # Test verification
    is_valid = CryptoUtils.verify_signature(deserialized_public_key, test_data, signature)
    
    assert is_valid, "Signature verification failed"
    print("Cryptographic functions work correctly")

def test_utxo_store():
    """Test UTXO store operations"""
    print("Testing UTXO store...")
    
    # Create UTXO store (mock for testing)
    store = MockUTXOStore()
    
    # Generate keys for testing
    private_key, public_key = CryptoUtils.generate_key_pair()
    public_key_str = CryptoUtils.serialize_public_key(public_key)
    
    # Create a UTXO
    utxo = UTXO(
        token_id=str(uuid.uuid4()),
        amount=100.0,
        currency=Currency.INR,
        owner_public_key=public_key_str
    )
    
    # Add to store
    store.add_utxo(utxo)
    
    # Retrieve UTXO
    retrieved_utxo = store.get_utxo(utxo.token_id)
    assert retrieved_utxo is not None, "UTXO not found in store"
    assert retrieved_utxo.amount == 100.0, "UTXO amount mismatch"
    
    # Test balance
    balance = store.get_balance(public_key_str, "INR")
    assert balance == 100.0, f"Balance mismatch: expected 100.0, got {balance}"
    
    # Test spending
    store.spend_utxo(utxo.token_id)
    spent_utxo = store.get_utxo(utxo.token_id)
    assert spent_utxo is None, "UTXO should be spent"
    
    print("UTXO store works correctly")

def test_transaction():
    """Test transaction creation and validation"""
    print("Testing transaction operations...")
    
    # Create UTXO store (mock for testing)
    store = MockUTXOStore()
    
    # Generate keys
    alice_private, alice_public = CryptoUtils.generate_key_pair()
    bob_private, bob_public = CryptoUtils.generate_key_pair()
    
    alice_public_str = CryptoUtils.serialize_public_key(alice_public)
    bob_public_str = CryptoUtils.serialize_public_key(bob_public)
    
    # Create UTXO for Alice
    utxo = UTXO(
        token_id=str(uuid.uuid4()),
        amount=200.0,
        currency=Currency.INR,
        owner_public_key=alice_public_str
    )
    store.add_utxo(utxo)
    
    # Create transaction: Alice sends 100 INR to Bob
    # Create input
    payload = CryptoUtils.create_token_payload({
        "token_id": utxo.token_id,
        "amount": utxo.amount,
        "currency": utxo.currency,
        "owner_public_key": utxo.owner_public_key
    })
    signature = CryptoUtils.sign_data(alice_private, payload)
    
    # For testing, we'll include the amount and original payload in the input
    # (in real system, this would come from UTXO lookup and the signed payload would be stored)
    transaction_input = TransactionInput(
        token_id=utxo.token_id,
        signature=signature,
        amount=utxo.amount  # Include amount for validation
    )
    # Store the original payload for verification (this simulates what would happen in a real system)
    transaction_input._original_payload = payload
    
    # Create outputs
    transaction_outputs = [
        TransactionOutput(
            amount=100.0,
            currency=Currency.INR,
            owner_public_key=bob_public_str
        ),
        TransactionOutput(
            amount=100.0,  # Change back to Alice
            currency=Currency.INR,
            owner_public_key=alice_public_str
        )
    ]
    
    # Create transaction
    transaction = Transaction(
        inputs=[transaction_input],
        outputs=transaction_outputs,
        fee=0.0
    )
    
    # Validate transaction
    assert transaction.is_valid(), "Transaction should be valid"
    
    # Process transaction
    success = store.process_transaction(transaction)
    assert success, "Transaction processing should succeed"
    
    # Check balances
    alice_balance = store.get_balance(alice_public_str, "INR")
    bob_balance = store.get_balance(bob_public_str, "INR")
    
    assert alice_balance == 100.0, f"Alice balance should be 100.0, got {alice_balance}"
    assert bob_balance == 100.0, f"Bob balance should be 100.0, got {bob_balance}"
    
    print("Transaction processing works correctly")

def main():
    """Run all tests"""
    print("Running UPI 2.0 System Tests...")
    print("=" * 50)
    
    try:
        test_crypto()
        test_utxo_store()
        test_transaction()
        
        print("=" * 50)
        print("All tests passed! UPI 2.0 system is working correctly.")
        
    except Exception as e:
        print(f"Test failed: {str(e)}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()
