/*
 * Copyright (C) 2026 Myungjun Kim
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#include "ecc_internal.h"

/*
 * NIST SP 800-186 domain parameters, represented as little-endian 32-bit
 * limbs. Field constants are already in the Montgomery domain used by the
 * portable field implementation.
 */
static const CryptoEcCurve CRYPTO_EC_P256 = {
    CRYPTO_EC_CURVE_P256,
    256u,
    32u,
    256u,
    32u,
    8u,
    UINT32_C(0x00000001),
    {
        UINT32_C(0xffffffff), UINT32_C(0xffffffff), UINT32_C(0xffffffff),
        UINT32_C(0x00000000), UINT32_C(0x00000000), UINT32_C(0x00000000),
        UINT32_C(0x00000001), UINT32_C(0xffffffff)
    },
    {
        UINT32_C(0xfc632551), UINT32_C(0xf3b9cac2), UINT32_C(0xa7179e84),
        UINT32_C(0xbce6faad), UINT32_C(0xffffffff), UINT32_C(0xffffffff),
        UINT32_C(0x00000000), UINT32_C(0xffffffff)
    },
    {
        UINT32_C(0x00000001), UINT32_C(0x00000000), UINT32_C(0x00000000),
        UINT32_C(0xffffffff), UINT32_C(0xffffffff), UINT32_C(0xffffffff),
        UINT32_C(0xfffffffe), UINT32_C(0x00000000)
    },
    {
        UINT32_C(0x00000003), UINT32_C(0x00000000), UINT32_C(0xffffffff),
        UINT32_C(0xfffffffb), UINT32_C(0xfffffffe), UINT32_C(0xffffffff),
        UINT32_C(0xfffffffd), UINT32_C(0x00000004)
    },
    {
        UINT32_C(0xd89cdf62), UINT32_C(0x77037d81), UINT32_C(0xf9b08ee1),
        UINT32_C(0x242a35bd), UINT32_C(0xcfe4f656), UINT32_C(0x8ee7eb4a),
        UINT32_C(0xb3ebbd55), UINT32_C(0xdc30061d)
    },
    {
        UINT32_C(0x18a9143c), UINT32_C(0x79e730d4), UINT32_C(0x5fedb601),
        UINT32_C(0x75ba95fc), UINT32_C(0x77622510), UINT32_C(0x79fb732b),
        UINT32_C(0xa53755c6), UINT32_C(0x18905f76)
    },
    {
        UINT32_C(0xce95560a), UINT32_C(0xddf25357), UINT32_C(0xba19e45c),
        UINT32_C(0x8b4ab8e4), UINT32_C(0xdd21f325), UINT32_C(0xd2e88688),
        UINT32_C(0x25885d85), UINT32_C(0x8571ff18)
    },
    {
        UINT32_C(0xfffffffd), UINT32_C(0xffffffff), UINT32_C(0xffffffff),
        UINT32_C(0x00000000), UINT32_C(0x00000000), UINT32_C(0x00000000),
        UINT32_C(0x00000001), UINT32_C(0xffffffff)
    },
    {
        UINT32_C(0x00000000), UINT32_C(0x00000000), UINT32_C(0x40000000),
        UINT32_C(0x00000000), UINT32_C(0x00000000), UINT32_C(0x40000000),
        UINT32_C(0xc0000000), UINT32_C(0x3fffffff)
    }
};

static const CryptoEcCurve CRYPTO_EC_P384 = {
    CRYPTO_EC_CURVE_P384,
    384u,
    48u,
    384u,
    48u,
    12u,
    UINT32_C(0x00000001),
    {
        UINT32_C(0xffffffff), UINT32_C(0x00000000), UINT32_C(0x00000000),
        UINT32_C(0xffffffff), UINT32_C(0xfffffffe), UINT32_C(0xffffffff),
        UINT32_C(0xffffffff), UINT32_C(0xffffffff), UINT32_C(0xffffffff),
        UINT32_C(0xffffffff), UINT32_C(0xffffffff), UINT32_C(0xffffffff)
    },
    {
        UINT32_C(0xccc52973), UINT32_C(0xecec196a), UINT32_C(0x48b0a77a),
        UINT32_C(0x581a0db2), UINT32_C(0xf4372ddf), UINT32_C(0xc7634d81),
        UINT32_C(0xffffffff), UINT32_C(0xffffffff), UINT32_C(0xffffffff),
        UINT32_C(0xffffffff), UINT32_C(0xffffffff), UINT32_C(0xffffffff)
    },
    {
        UINT32_C(0x00000001), UINT32_C(0xffffffff), UINT32_C(0xffffffff),
        UINT32_C(0x00000000), UINT32_C(0x00000001), UINT32_C(0x00000000),
        UINT32_C(0x00000000), UINT32_C(0x00000000), UINT32_C(0x00000000),
        UINT32_C(0x00000000), UINT32_C(0x00000000), UINT32_C(0x00000000)
    },
    {
        UINT32_C(0x00000001), UINT32_C(0xfffffffe), UINT32_C(0x00000000),
        UINT32_C(0x00000002), UINT32_C(0x00000000), UINT32_C(0xfffffffe),
        UINT32_C(0x00000000), UINT32_C(0x00000002), UINT32_C(0x00000001),
        UINT32_C(0x00000000), UINT32_C(0x00000000), UINT32_C(0x00000000)
    },
    {
        UINT32_C(0x08118871), UINT32_C(0xe59c80e7), UINT32_C(0xb0b8f501),
        UINT32_C(0xb62b21f4), UINT32_C(0x30f27082), UINT32_C(0x63fe9c9a),
        UINT32_C(0x3617de4a), UINT32_C(0x1d7e819d), UINT32_C(0xa7f9b8ee),
        UINT32_C(0x6cae4f37), UINT32_C(0xc5293a3a), UINT32_C(0x8dc9946f)
    },
    {
        UINT32_C(0x3a545e38), UINT32_C(0x5295df61), UINT32_C(0xf25dbf55),
        UINT32_C(0x6e1d3b62), UINT32_C(0x8ba79b98), UINT32_C(0x59f741e0),
        UINT32_C(0xf1d27103), UINT32_C(0x990e5ff0), UINT32_C(0x3344b51a),
        UINT32_C(0xef0e1ca6), UINT32_C(0xb143ef91), UINT32_C(0xaa87ca22)
    },
    {
        UINT32_C(0x7a431d7c), UINT32_C(0x0a60b1ce), UINT32_C(0x1d7e819d),
        UINT32_C(0xe9da3113), UINT32_C(0x289a147c), UINT32_C(0xf8f41dbd),
        UINT32_C(0x9292dc29), UINT32_C(0x5d9e98bf), UINT32_C(0x96262c6f),
        UINT32_C(0x62b70b29), UINT32_C(0xba7e387e), UINT32_C(0x3617de4a)
    },
    {
        UINT32_C(0xfffffffd), UINT32_C(0x00000000), UINT32_C(0x00000000),
        UINT32_C(0xffffffff), UINT32_C(0xfffffffe), UINT32_C(0xffffffff),
        UINT32_C(0xffffffff), UINT32_C(0xffffffff), UINT32_C(0xffffffff),
        UINT32_C(0xffffffff), UINT32_C(0xffffffff), UINT32_C(0xffffffff)
    },
    {
        UINT32_C(0x00000000), UINT32_C(0x00000000), UINT32_C(0xc0000000),
        UINT32_C(0xbfffffff), UINT32_C(0xffffffff), UINT32_C(0xffffffff),
        UINT32_C(0xffffffff), UINT32_C(0xffffffff), UINT32_C(0xffffffff),
        UINT32_C(0xffffffff), UINT32_C(0xffffffff), UINT32_C(0x3fffffff)
    }
};

static const CryptoEcCurve CRYPTO_EC_P521 = {
    CRYPTO_EC_CURVE_P521,
    521u,
    66u,
    521u,
    66u,
    17u,
    UINT32_C(0x00000001),
    {
        UINT32_C(0xffffffff), UINT32_C(0xffffffff), UINT32_C(0xffffffff),
        UINT32_C(0xffffffff), UINT32_C(0xffffffff), UINT32_C(0xffffffff),
        UINT32_C(0xffffffff), UINT32_C(0xffffffff), UINT32_C(0xffffffff),
        UINT32_C(0xffffffff), UINT32_C(0xffffffff), UINT32_C(0xffffffff),
        UINT32_C(0xffffffff), UINT32_C(0xffffffff), UINT32_C(0xffffffff),
        UINT32_C(0xffffffff), UINT32_C(0x000001ff)
    },
    {
        UINT32_C(0x91386409), UINT32_C(0xbb6fb71e), UINT32_C(0x899c47ae),
        UINT32_C(0x3bb5c9b8), UINT32_C(0xf709a5d0), UINT32_C(0x7fcc0148),
        UINT32_C(0xbf2f966b), UINT32_C(0x51868783), UINT32_C(0xfffffff a),
        UINT32_C(0xffffffff), UINT32_C(0xffffffff), UINT32_C(0xffffffff),
        UINT32_C(0xffffffff), UINT32_C(0xffffffff), UINT32_C(0xffffffff),
        UINT32_C(0xffffffff), UINT32_C(0x000001ff)
    },
    {
        UINT32_C(0x00800000), UINT32_C(0x00000000), UINT32_C(0x00000000),
        UINT32_C(0x00000000), UINT32_C(0x00000000), UINT32_C(0x00000000),
        UINT32_C(0x00000000), UINT32_C(0x00000000), UINT32_C(0x00000000),
        UINT32_C(0x00000000), UINT32_C(0x00000000), UINT32_C(0x00000000),
        UINT32_C(0x00000000), UINT32_C(0x00000000), UINT32_C(0x00000000),
        UINT32_C(0x00000000), UINT32_C(0x00000000)
    },
    {
        UINT32_C(0x00000000), UINT32_C(0x00004000), UINT32_C(0x00000000),
        UINT32_C(0x00000000), UINT32_C(0x00000000), UINT32_C(0x00000000),
        UINT32_C(0x00000000), UINT32_C(0x00000000), UINT32_C(0x00000000),
        UINT32_C(0x00000000), UINT32_C(0x00000000), UINT32_C(0x00000000),
        UINT32_C(0x00000000), UINT32_C(0x00000000), UINT32_C(0x00000000),
        UINT32_C(0x00000000), UINT32_C(0x00000000)
    },
    {
        UINT32_C(0x8014654f), UINT32_C(0xb17e1d69), UINT32_C(0x09f0753c),
        UINT32_C(0x4b0532f4), UINT32_C(0x522ca4a1), UINT32_C(0x6bb6bf9a),
        UINT32_C(0x4f61c3e4), UINT32_C(0x8df50a19), UINT32_C(0xfbd17273),
        UINT32_C(0x883d2c34), UINT32_C(0x251a1e1e), UINT32_C(0x9f3f5b82),
        UINT32_C(0xe9dcacbc), UINT32_C(0xf307a54f), UINT32_C(0xffd1c0d6),
        UINT32_C(0xbd3bb1bf), UINT32_C(0x00000005)
    },
    {
        UINT32_C(0x2e5bd66c), UINT32_C(0x1e709ee4), UINT32_C(0xa85a429b),
        UINT32_C(0xe7ef20f6), UINT32_C(0xc8a2ed6a), UINT32_C(0x01e47da9),
        UINT32_C(0xbb5c9b88), UINT32_C(0xb6fafd99), UINT32_C(0xefae7291),
        UINT32_C(0x08a7214f), UINT32_C(0xcb34f815), UINT32_C(0xe6aa05cc),
        UINT32_C(0x2d5d8e94), UINT32_C(0xb10e3b9c), UINT32_C(0x8e396c83),
        UINT32_C(0xbc76542d), UINT32_C(0x000000c6)
    },
    {
        UINT32_C(0xfd16650e), UINT32_C(0x47c5b30d), UINT32_C(0xd3cc810d),
        UINT32_C(0xe2a8c975), UINT32_C(0x3e662c97), UINT32_C(0xb48b3c18),
        UINT32_C(0x3401e0ed), UINT32_C(0x90fc1457), UINT32_C(0x3c633c07),
        UINT32_C(0x1616b5e4), UINT32_C(0x66487639), UINT32_C(0x9d2bd73a),
        UINT32_C(0xc1b86188), UINT32_C(0x7ce5c92e), UINT32_C(0x856a429b),
        UINT32_C(0x6b9e8e85), UINT32_C(0x00000118)
    },
    {
        UINT32_C(0xfffffffd), UINT32_C(0xffffffff), UINT32_C(0xffffffff),
        UINT32_C(0xffffffff), UINT32_C(0xffffffff), UINT32_C(0xffffffff),
        UINT32_C(0xffffffff), UINT32_C(0xffffffff), UINT32_C(0xffffffff),
        UINT32_C(0xffffffff), UINT32_C(0xffffffff), UINT32_C(0xffffffff),
        UINT32_C(0xffffffff), UINT32_C(0xffffffff), UINT32_C(0xffffffff),
        UINT32_C(0xffffffff), UINT32_C(0x000001ff)
    },
    {
        UINT32_C(0x00000000), UINT32_C(0x00000000), UINT32_C(0x00000000),
        UINT32_C(0x00000000), UINT32_C(0x00000000), UINT32_C(0x00000000),
        UINT32_C(0x00000000), UINT32_C(0x00000000), UINT32_C(0x00000000),
        UINT32_C(0x00000000), UINT32_C(0x00000000), UINT32_C(0x00000000),
        UINT32_C(0x00000000), UINT32_C(0x00000000), UINT32_C(0x00000000),
        UINT32_C(0xc0000000), UINT32_C(0x0000007f)
    }
};

const CryptoEcCurve *crypto_ec_curve_get(CryptoEcCurveId id) {
    switch (id) {
        case CRYPTO_EC_CURVE_P256:
            return &CRYPTO_EC_P256;
        case CRYPTO_EC_CURVE_P384:
            return &CRYPTO_EC_P384;
        case CRYPTO_EC_CURVE_P521:
            return &CRYPTO_EC_P521;
        default:
            return NULL;
    }
}
