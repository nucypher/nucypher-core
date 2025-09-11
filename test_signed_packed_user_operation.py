#!/usr/bin/env python3

import nucypher_core
from nucypher_core import PackedUserOperation, SignedPackedUserOperation

def test_signed_packed_user_operation():
    print("Testing SignedPackedUserOperation...")
    
    # Test creating a PackedUserOperation
    packed_op = PackedUserOperation(
        sender='0x1234567890123456789012345678901234567890',
        nonce=123,
        init_code=b'test_init',
        call_data=b'test_call',
        account_gas_limits=b'\x00' * 32,
        pre_verification_gas=50000,
        gas_fees=b'\x00' * 32,
        paymaster_and_data=b'',
        signature=b'original_signature'
    )
    
    # Test creating a SignedPackedUserOperation
    signed_op = SignedPackedUserOperation(packed_op, b'new_signature')
    print('✓ Created SignedPackedUserOperation successfully')
    
    # Test accessing properties
    print(f'✓ Signature length: {len(signed_op.signature)}')
    print(f'✓ Operation sender: {signed_op.operation.sender}')
    print(f'✓ Operation nonce: {signed_op.operation.nonce}')
    
    # Test that the operation part has no signature
    assert len(signed_op.operation.signature) == 0, "Operation should have empty signature"
    print('✓ Operation part has empty signature as expected')
    
    # Test from_packed_user_operation
    signed_from_existing = SignedPackedUserOperation.from_packed_user_operation(packed_op)
    print(f'✓ Extracted signature: {signed_from_existing.signature}')
    assert signed_from_existing.signature == b'original_signature'
    
    # Test converting back to PackedUserOperation
    reconstructed = signed_op.to_packed_user_operation()
    print(f'✓ Reconstructed signature: {reconstructed.signature}')
    assert reconstructed.signature == b'new_signature'
    
    # Test serialization
    serialized = bytes(signed_op)
    deserialized = SignedPackedUserOperation.from_bytes(serialized)
    assert deserialized.signature == signed_op.signature
    print('✓ Serialization test passed')
    
    # Test EIP-712 methods work
    try:
        eip712_message = signed_op._to_eip712_message("0.8.0")
        domain = signed_op._get_domain("0.8.0", 1)
        eip712_struct = signed_op.to_eip712_struct("0.8.0", 1)
        print('✓ EIP-712 methods work correctly')
    except Exception as e:
        print(f'✗ EIP-712 methods failed: {e}')
        raise
    
    print('✅ All SignedPackedUserOperation tests passed!')

if __name__ == '__main__':
    test_signed_packed_user_operation() 