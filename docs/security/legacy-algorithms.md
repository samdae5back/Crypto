# Legacy and compatibility algorithms

LiberaCrypt includes several primitives whose primary purpose is interoperability with existing systems, reproduction of standards-era test vectors, or primitive-level testing.

Their presence in the library is not a recommendation to select them for new protocol designs.

## SHA-1

SHA-1 remains available for compatibility with protocols and data formats that still require it. New security designs should use a stronger hash family unless an external specification requires SHA-1.

## Triple-DES / TDEA

Three-key Triple-DES EDE is available in the block-cipher API and as a legacy CTR_DRBG option. These selectors exist for interoperability and standards-era validation. New designs should normally use modern AES or an appropriate authenticated-encryption construction.

Two-key TDEA and single DES are not exposed by the block-cipher dispatcher.

## ECB

ECB mode is retained as a primitive/block-mode interface and for compatibility/testing. It does not hide repeated-block patterns and should not be treated as a general-purpose secure message-encryption mode.

## Raw RSA

Raw textbook RSA operations remain available for primitive testing and compatibility. Application-level RSA encryption should use RSAES-OAEP and signatures should use RSASSA-PSS or another protocol-mandated standardized scheme.

## Compatibility policy

Legacy support should remain clearly labeled at the API and documentation layers. When a legacy algorithm is retained:

- its compatibility purpose should be explicit;
- modern alternatives should be easy to identify;
- its presence should not force legacy parameters into unrelated modern APIs; and
- validation should ensure that compatibility code does not weaken the behavior of other algorithm families.
