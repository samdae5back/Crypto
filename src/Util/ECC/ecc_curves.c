/*
 * Copyright (C) 2026 Myungjun Kim
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#include "ecc_internal.h"

/*
 * NIST SP 800-186 domain parameters, represented as little-endian 32-bit
 * limbs. Field constants are preconverted to the Montgomery domain R mod p,
 * where R = 2^(32 * limbs). The inverse and square-root exponents remain
 * ordinary little-endian integers because they are scanned as public bits.
 */
static const CryptoEcCurve CRYPTO_EC_P256 = {
    CRYPTO_EC_CURVE_P256, 256u, 32u, 256u, 32u, 8u, UINT32_C(0x00000001),
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
        UINT32_C(0x29c4bddf), UINT32_C(0xd89cdf62), UINT32_C(0x78843090),
        UINT32_C(0xacf005cd), UINT32_C(0xf7212ed6), UINT32_C(0xe5a220ab),
        UINT32_C(0x04874834), UINT32_C(0xdc30061d)
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
    },
    UINT32_C(0xee00bc4f),
    {
        UINT32_C(0x039cdaaf), UINT32_C(0x0c46353d), UINT32_C(0x58e8617b),
        UINT32_C(0x43190552), UINT32_C(0x00000000), UINT32_C(0x00000000),
        UINT32_C(0xffffffff), UINT32_C(0x00000000)
    },
    {
        UINT32_C(0xbe79eea2), UINT32_C(0x83244c95), UINT32_C(0x49bd6fa6),
        UINT32_C(0x4699799c), UINT32_C(0x2b6bec59), UINT32_C(0x2845b239),
        UINT32_C(0xf3d95620), UINT32_C(0x66e12d94)
    },
    {
        UINT32_C(0xfc63254f), UINT32_C(0xf3b9cac2), UINT32_C(0xa7179e84),
        UINT32_C(0xbce6faad), UINT32_C(0xffffffff), UINT32_C(0xffffffff),
        UINT32_C(0x00000000), UINT32_C(0xffffffff)
    }
};

static const CryptoEcCurve CRYPTO_EC_P384 = {
    CRYPTO_EC_CURVE_P384, 384u, 48u, 384u, 48u, 12u, UINT32_C(0x00000001),
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
        UINT32_C(0x9d412dcc), UINT32_C(0x08118871), UINT32_C(0x7a4c32ec),
        UINT32_C(0xf729add8), UINT32_C(0x1920022e), UINT32_C(0x77f2209b),
        UINT32_C(0x94938ae2), UINT32_C(0xe3374bee), UINT32_C(0x1f022094),
        UINT32_C(0xb62b21f4), UINT32_C(0x604fbff9), UINT32_C(0xcd08114b)
    },
    {
        UINT32_C(0x49c0b528), UINT32_C(0x3dd07566), UINT32_C(0xa0d6ce38),
        UINT32_C(0x20e378e2), UINT32_C(0x541b4d6e), UINT32_C(0x879c3afc),
        UINT32_C(0x59a30eff), UINT32_C(0x64548684), UINT32_C(0x614ede2b),
        UINT32_C(0x812ff723), UINT32_C(0x299e1513), UINT32_C(0x4d3aadc2)
    },
    {
        UINT32_C(0x4b03a4fe), UINT32_C(0x23043dad), UINT32_C(0x7bb4a9ac),
        UINT32_C(0xa1bfa8bf), UINT32_C(0x2e83b050), UINT32_C(0x8bade756),
        UINT32_C(0x68f4ffd9), UINT32_C(0xc6c35219), UINT32_C(0x3969a840),
        UINT32_C(0xdd800226), UINT32_C(0x5a15c5e9), UINT32_C(0x2b78abc2)
    },
    {
        UINT32_C(0xfffffffd), UINT32_C(0x00000000), UINT32_C(0x00000000),
        UINT32_C(0xffffffff), UINT32_C(0xfffffffe), UINT32_C(0xffffffff),
        UINT32_C(0xffffffff), UINT32_C(0xffffffff), UINT32_C(0xffffffff),
        UINT32_C(0xffffffff), UINT32_C(0xffffffff), UINT32_C(0xffffffff)
    },
    {
        UINT32_C(0x40000000), UINT32_C(0x00000000), UINT32_C(0xc0000000),
        UINT32_C(0xbfffffff), UINT32_C(0xffffffff), UINT32_C(0xffffffff),
        UINT32_C(0xffffffff), UINT32_C(0xffffffff), UINT32_C(0xffffffff),
        UINT32_C(0xffffffff), UINT32_C(0xffffffff), UINT32_C(0x3fffffff)
    },
    UINT32_C(0xe88fdc45),
    {
        UINT32_C(0x333ad68d), UINT32_C(0x1313e695), UINT32_C(0xb74f5885),
        UINT32_C(0xa7e5f24d), UINT32_C(0x0bc8d220), UINT32_C(0x389cb27e),
        UINT32_C(0x00000000), UINT32_C(0x00000000), UINT32_C(0x00000000),
        UINT32_C(0x00000000), UINT32_C(0x00000000), UINT32_C(0x00000000)
    },
    {
        UINT32_C(0x19b409a9), UINT32_C(0x2d319b24), UINT32_C(0xdf1aa419),
        UINT32_C(0xff3d81e5), UINT32_C(0xfcb82947), UINT32_C(0xbc3e483a),
        UINT32_C(0x4aab1cc5), UINT32_C(0xd40d4917), UINT32_C(0x28266895),
        UINT32_C(0x3fb05b7a), UINT32_C(0x2b39bf21), UINT32_C(0x0c84ee01)
    },
    {
        UINT32_C(0xccc52971), UINT32_C(0xecec196a), UINT32_C(0x48b0a77a),
        UINT32_C(0x581a0db2), UINT32_C(0xf4372ddf), UINT32_C(0xc7634d81),
        UINT32_C(0xffffffff), UINT32_C(0xffffffff), UINT32_C(0xffffffff),
        UINT32_C(0xffffffff), UINT32_C(0xffffffff), UINT32_C(0xffffffff)
    }
};

static const CryptoEcCurve CRYPTO_EC_P521 = {
    CRYPTO_EC_CURVE_P521, 521u, 66u, 521u, 66u, 17u, UINT32_C(0x00000001),
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
        UINT32_C(0xbf2f966b), UINT32_C(0x51868783), UINT32_C(0xfffffffa),
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
        UINT32_C(0x8014654f), UINT32_C(0xea35a81f), UINT32_C(0x78f7a28f),
        UINT32_C(0xc41e961a), UINT32_C(0x839ab9ef), UINT32_C(0x5e9dd8df),
        UINT32_C(0xbd8b2960), UINT32_C(0xa8f63f49), UINT32_C(0xf0ab0c9c),
        UINT32_C(0xc8c77884), UINT32_C(0xf9dc5a44), UINT32_C(0x2dccd98a),
        UINT32_C(0x77516d39), UINT32_C(0xd05b42a0), UINT32_C(0x0fc94d10),
        UINT32_C(0xb0c70e4d), UINT32_C(0x0000015c)
    },
    {
        UINT32_C(0xb331a163), UINT32_C(0x18e172de), UINT32_C(0x4dfcbf3f),
        UINT32_C(0xe0c2b521), UINT32_C(0x6f19a459), UINT32_C(0x93d17fd4),
        UINT32_C(0x947f0ee0), UINT32_C(0x3bf7f3ac), UINT32_C(0xdd50a5af),
        UINT32_C(0xb035a69e), UINT32_C(0x90fc1457), UINT32_C(0x9c829fda),
        UINT32_C(0x214e3240), UINT32_C(0xb311cada), UINT32_C(0xe6cf1f65),
        UINT32_C(0x5b820274), UINT32_C(0x00000103)
    },
    {
        UINT32_C(0x28460e4a), UINT32_C(0x3b4fe8b3), UINT32_C(0x20445f4a),
        UINT32_C(0x43513961), UINT32_C(0xb09a9e38), UINT32_C(0x809fd683),
        UINT32_C(0x2062a85c), UINT32_C(0x4caf7a13), UINT32_C(0x164bf739),
        UINT32_C(0x8b939f33), UINT32_C(0x340bd7de), UINT32_C(0x24abcda2),
        UINT32_C(0xeccc7aa2), UINT32_C(0xda163e8d), UINT32_C(0x022e452f),
        UINT32_C(0x3c4d1de0), UINT32_C(0x000000b5)
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
        UINT32_C(0x00000000), UINT32_C(0x00000080)
    },
    UINT32_C(0x79a995c7),
    {
        UINT32_C(0xfb800000), UINT32_C(0x70b763cd), UINT32_C(0x28a24824),
        UINT32_C(0x23bb31dc), UINT32_C(0x17e2251b), UINT32_C(0x5b847b2d),
        UINT32_C(0xca4019ff), UINT32_C(0x3e206834), UINT32_C(0x02d73cbc),
        UINT32_C(0x00000000), UINT32_C(0x00000000), UINT32_C(0x00000000),
        UINT32_C(0x00000000), UINT32_C(0x00000000), UINT32_C(0x00000000),
        UINT32_C(0x00000000), UINT32_C(0x00000000)
    },
    {
        UINT32_C(0x61c64ca7), UINT32_C(0x1163115a), UINT32_C(0x4374a642),
        UINT32_C(0x18354a56), UINT32_C(0x0791d9dc), UINT32_C(0x5d4dd6d3),
        UINT32_C(0xd3402705), UINT32_C(0x4fb35b72), UINT32_C(0xb7756e3a),
        UINT32_C(0xcff3d142), UINT32_C(0xa8e567bc), UINT32_C(0x5bcc6d61),
        UINT32_C(0x492d0d45), UINT32_C(0x2d8e03d1), UINT32_C(0x8c44383d),
        UINT32_C(0x5b5a3afe), UINT32_C(0x0000019a)
    },
    {
        UINT32_C(0x91386407), UINT32_C(0xbb6fb71e), UINT32_C(0x899c47ae),
        UINT32_C(0x3bb5c9b8), UINT32_C(0xf709a5d0), UINT32_C(0x7fcc0148),
        UINT32_C(0xbf2f966b), UINT32_C(0x51868783), UINT32_C(0xfffffffa),
        UINT32_C(0xffffffff), UINT32_C(0xffffffff), UINT32_C(0xffffffff),
        UINT32_C(0xffffffff), UINT32_C(0xffffffff), UINT32_C(0xffffffff),
        UINT32_C(0xffffffff), UINT32_C(0x000001ff)
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
