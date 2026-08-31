# ECC test oracle

`Reference.c` contains the intentionally simple affine double-and-add scalar
multiplication used only as a correctness oracle and benchmark baseline for the
production ECC paths. It is compiled into ECC test/benchmark executables only
and is not linked into the LiberaCrypt library.

Production scalar multiplication lives in `src/Util/ECC` and exposes only the
optimized public-scalar path and the fixed-schedule secret-scalar path.
