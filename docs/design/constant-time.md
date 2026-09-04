# Constant-time policy

LiberaCrypt does not duplicate every arithmetic primitive into `_ct` and `_vartime` variants. Timing-sensitive behavior is separated where secret-dependent loop counts, branches, table indices, normalization, or operand lengths would otherwise expose secret information.

The generic bignum layer remains optimized for ordinary or public data. Dedicated fixed-width secret paths are used at call sites that require stronger timing behavior.

## Public versus secret exponentiation

Public/non-secret exponentiation may use variable-time optimizations such as adaptive sliding windows, odd-power precomputation, direct table lookup, zero-bit skipping, and trivial-value early exits.

Secret exponentiation uses the fixed-width Montgomery path:

- scan the complete public modulus width rather than the secret exponent's significant length;
- compute the required square/multiply candidates on each scheduled bit;
- select results with masks rather than secret-dependent table indices or multiply branches;
- keep secret residues in fixed-width Montgomery storage;
- use fixed-count normalization for secret results; and
- clear secret temporary storage before release.

RSA private operations and ElGamal secret exponentiation use this policy.

## Secret storage boundary

An ordinary `LiberaCBignum` already represents a significant `LENGTH`. Converting that existing variable-length object into fixed-width secret storage cannot truthfully be described as constant-schedule with respect to the pre-existing representation.

LiberaCrypt therefore treats promotion into fixed-width secret storage as an explicit boundary. Persistent secrets such as RSA `D` and ElGamal `X` are promoted when established; subsequent secret copies and serialization can traverse the complete caller-selected public width.

This distinction avoids labeling a helper constant-time while it still follows a secret object's significant length.

## Other arithmetic

- Generic add/subtract, reduction, compare, normalization, and serialization may remain variable-time for public data.
- Fixed-width secret helpers are added when a real secret call site requires them rather than by maintaining an unused duplicate arithmetic stack.
- Secret modular arithmetic prefers a fixed-width Montgomery representation instead of routing secret residues through a generic division-style remainder path.
- Prime generation and Miller-Rabin are deliberately variable-time; candidate and witness control flow is not handled as persistent secret-exponent state.

## Authentication comparison

Authentication-tag verification uses a shared constant-time byte-equality helper rather than algorithm-specific early-exit comparison loops.

## Scope of the claim

Constant-time implementation work reduces selected software timing side channels. It is not a claim that every operation in the library, the compiler output, the operating system, the hardware, or the complete application is side-channel resistant under every attacker model.

Any new constant-time claim should identify:

1. which values are secret;
2. which public width or iteration bound fixes the schedule;
3. which branches, memory indices, and loop counts were removed from secret dependence; and
4. how the path was validated without silently falling back to variable-length generic helpers.
