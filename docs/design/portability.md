# Portability

Portability in LiberaCrypt is treated as a correctness property, not merely as a list of platforms on which a build happened to succeed.

Code is not considered portable when its result depends on an unstated compiler, ABI, byte-order, character-representation, integer, or linker assumption that can change on another conforming environment.

## Policy

### Use defined integer behavior

Internal arithmetic uses fixed-width integer types when width is part of the algorithm or representation. Narrowing conversions are made only where the value range is known. Important representation and range invariants should be made explicit in code or compile-time assertions.

Signed arithmetic is not allowed to rely accidentally on behavior such as implementation-defined right shift of negative values. When an algorithm needs floor division, sign extraction, or a particular bit representation, the intended operation is written explicitly.

### Do not depend on plain `char` signedness

Platforms are allowed to choose whether plain `char` is signed or unsigned. Serialization and arithmetic that require an exact signed-byte mapping therefore define that mapping explicitly rather than depending on a cast through plain or implementation-defined character behavior.

HAETAE is one concrete example: decomposed low-byte serialization uses an explicit mapping for the signed `[-128, 127]` range so the representation does not change on an AIX/Power environment with unsigned plain `char`.

### Make byte order explicit

Serialization and low-level word handling do not assume host endianness. Endian-sensitive loads and stores are isolated in project utilities, and public wire formats are produced independently of native representation.

ChaCha20, for example, decodes its key, nonce, counter, and output words explicitly in little-endian form.

### Prove intermediate widths where practical

A fixed-width implementation should be able to explain why its intermediate type is wide enough. HAETAE's fixed-point FFT is an example: storage, Q16 products, butterfly expressions, squared magnitudes, and accumulation use widths selected from conservative bounds rather than from the width that happened to work on one machine.

### Avoid unnecessary implementation extensions

Portable baseline code should not depend on compiler extensions or unusually wide native integer types when a standard-width representation is practical. Poly1305, for example, uses range-bounded 26-bit limbs with `uint64_t` products rather than requiring a native 128-bit integer type.

### Keep platform behavior at narrow boundaries

Operating-system entropy acquisition and shared-library export policy necessarily vary by platform. Those differences are isolated instead of spreading conditional platform code through the cryptographic implementation.

The same public API can therefore use Windows DLL declarations, ELF version scripts, macOS exported-symbol lists, Solaris mapfiles, AIX `.exp` files, and HP-UX export options without changing algorithm code.

## Portability review checklist

When adding or adapting code, review at least the following questions:

- Does any result depend on host endianness?
- Does it depend on plain `char` signedness?
- Can a signed shift, division, overflow, or conversion have implementation-defined or undefined behavior?
- Are intermediate ranges justified for their integer widths?
- Does pointer arithmetic remain within valid objects and checked sizes?
- Does the code assume a compiler extension, native 128-bit integer, alignment, ABI, or linker model unnecessarily?
- Is OS-specific behavior isolated behind an explicit boundary?
- Can a different compiler or optimization level expose an assumption that the current one tolerates?

## Validation

CI covers mainstream Windows/MSVC, Linux, and macOS builds. Unit tests, KATs, warning-oriented builds, sanitizers, and focused portability checks are used to catch assumptions that a single toolchain may tolerate.

Passing those environments is evidence, not the definition of portability. The implementation policy above remains the stronger requirement, especially for legacy and non-mainstream Unix targets.

## Style consequence

A slightly more explicit expression is preferred over a shorter expression when the explicit form makes integer width, representation, range, byte order, or platform behavior unambiguous.
