// SPDX-License-Identifier: MIT

#include <string.h>

#include "haetae_poly.h"
#include "haetae_polyvec.h"
#include "haetae_polymat.h"
#include "haetae_encoding.h"
#include "haetae_packing.h"

/*************************************************
 * Name:        pack_pk
 *
 * Description: Bit-pack public key pk = (seed, b).
 *
 * Arguments:   - uint8_t  pk[]: output byte array
 *              - const crypto_haetae_polyveck *b: polynomial vector of length K containg b
 *              - const uint8_t  seed[]: seed for A'
 **************************************************/
void crypto_haetae_pack_pk(uint8_t  pk[CRYPTO_HAETAE_MAX_PUBLIC_KEY_BYTES],
                    crypto_haetae_polyveck *b, const uint8_t  seed[CRYPTO_HAETAE_SEED_BYTES],
                    const crypto_haetae_parameters *parameters) {
    unsigned int i;

    memcpy(pk, seed, CRYPTO_HAETAE_SEED_BYTES);

    pk += CRYPTO_HAETAE_SEED_BYTES;
    for (i = 0; i < parameters->k; ++i) {
        crypto_haetae_polyq_pack(pk + i * parameters->poly_q_packed_bytes, &b->vec[i], parameters);
    }
}

/*************************************************
 * Name:        unpack_pk
 *
 * Description: Unpack public key pk = (seed, b).
 *
 * Arguments:   - uint8_t  seed[]: seed for A'
 *              - crypto_haetae_polyveck *b: polynomial vector of length K containg b
 *              - const uint8_t  pk[]: output byte array
 **************************************************/
void crypto_haetae_unpack_pk(crypto_haetae_polyveck *b, uint8_t  seed[CRYPTO_HAETAE_SEED_BYTES],
                      const uint8_t  pk[CRYPTO_HAETAE_MAX_PUBLIC_KEY_BYTES],
                      const crypto_haetae_parameters *parameters) {
    unsigned int i;

    memcpy(seed, pk, CRYPTO_HAETAE_SEED_BYTES);

    pk += CRYPTO_HAETAE_SEED_BYTES;
    for (i = 0; i < parameters->k; ++i) {
        crypto_haetae_polyq_unpack(&b->vec[i], pk + i * parameters->poly_q_packed_bytes, parameters);
    }

}

/*************************************************
 * Name:        pack_sk
 *
 * Description: Bit-pack secret key sk = (pk, s).
 *
 * Arguments:   - uint8_t  sk[]: output byte array
 *              - const uint8_t  pk[PUBLICKEYBYTES]: packed pk
 *              - const crypto_haetae_polyvecl *s0: crypto_haetae_polyvecl pointer containing s0 (encoding
 *starting at offset 1)
 *              - const crypto_haetae_polyveck *s1: crypto_haetae_polyveck pointer containing s1
 **************************************************/
void crypto_haetae_pack_sk(uint8_t  sk[CRYPTO_HAETAE_MAX_PRIVATE_KEY_BYTES],
                    const uint8_t  pk[CRYPTO_HAETAE_MAX_PUBLIC_KEY_BYTES],
                    const crypto_haetae_polyvecm *s0, const crypto_haetae_polyveck *s1,
                    const uint8_t  key[CRYPTO_HAETAE_SEED_BYTES],
                    const crypto_haetae_parameters *parameters) {
    unsigned int i;

    const uint32_t haetae_m = parameters->l - 1u;
    const uint32_t haetae_d = parameters->d;
    const size_t haetae_pubkey_size = parameters->public_key_bytes;

    memcpy(sk, pk, parameters->public_key_bytes);

    sk += haetae_pubkey_size;
    for (i = 0; i < haetae_m; ++i)
        crypto_haetae_polyeta_pack(sk + i * CRYPTO_HAETAE_POLY_ETA_PACKED_BYTES, &s0->vec[i]);

    sk += haetae_m * CRYPTO_HAETAE_POLY_ETA_PACKED_BYTES;

    if(haetae_d) {
        for (i = 0; i < parameters->k; ++i)
            crypto_haetae_poly2eta_pack(sk + i * CRYPTO_HAETAE_POLY_2ETA_PACKED_BYTES, &s1->vec[i]);
        sk += parameters->k * CRYPTO_HAETAE_POLY_2ETA_PACKED_BYTES;
    }
    else { // D == 0
        for (i = 0; i < parameters->k; ++i)
            crypto_haetae_polyeta_pack(sk + i * CRYPTO_HAETAE_POLY_ETA_PACKED_BYTES, &s1->vec[i]);
        sk += parameters->k * CRYPTO_HAETAE_POLY_ETA_PACKED_BYTES;
    }

    memcpy(sk, key, CRYPTO_HAETAE_SEED_BYTES);
}

/*************************************************
 * Name:        unpack_sk
 *
 * Description: Unpack secret key sk = (A, s).
 *
 * Arguments:   - crypto_haetae_polyvecl A[K]: output crypto_haetae_polyvecl array for A
 *              - crypto_haetae_polyvecl s0: output crypto_haetae_polyvecl pointer for s0
 *              - crypto_haetae_polyveck s1: output crypto_haetae_polyveck pointer for s1
 *              - const uint8_t  sk[]: byte array containing bit-packed sk
 **************************************************/
void crypto_haetae_unpack_sk(crypto_haetae_polyvecl A[CRYPTO_HAETAE_MAX_K],
                      crypto_haetae_polyvecm *s0, crypto_haetae_polyveck *s1, uint8_t  *key,
                      const uint8_t  sk[CRYPTO_HAETAE_MAX_PRIVATE_KEY_BYTES],
                      const crypto_haetae_parameters *parameters) {
    unsigned int i;
    uint8_t  rhoprime[CRYPTO_HAETAE_SEED_BYTES];
    crypto_haetae_polyveck b1_storage;
    crypto_haetae_polyveck a_storage;
    crypto_haetae_polyveck *b1 = &b1_storage;
    crypto_haetae_polyveck *a = &a_storage;
    const uint32_t haetae_m = parameters->l - 1u;
    const uint32_t haetae_d = parameters->d;
    const size_t haetae_pubkey_size = parameters->public_key_bytes;

    memset(&b1_storage, 0, sizeof(b1_storage));
    memset(&a_storage, 0, sizeof(a_storage));

    crypto_haetae_unpack_pk(b1, rhoprime, sk, parameters);


    sk += haetae_pubkey_size;
    for (i = 0; i < haetae_m; ++i)
        crypto_haetae_polyeta_unpack(&s0->vec[i], sk + i * CRYPTO_HAETAE_POLY_ETA_PACKED_BYTES);
    sk += haetae_m * CRYPTO_HAETAE_POLY_ETA_PACKED_BYTES;

    if(haetae_d) {
        for (i = 0; i < parameters->k; ++i)
            crypto_haetae_poly2eta_unpack(&s1->vec[i], sk + i * CRYPTO_HAETAE_POLY_2ETA_PACKED_BYTES);
        sk += parameters->k * CRYPTO_HAETAE_POLY_2ETA_PACKED_BYTES;
    }
    else { // D == 0
        for (i = 0; i < parameters->k; ++i)
            crypto_haetae_polyeta_unpack(&s1->vec[i], sk + i * CRYPTO_HAETAE_POLY_ETA_PACKED_BYTES);
        sk += parameters->k * CRYPTO_HAETAE_POLY_ETA_PACKED_BYTES;
    }

    memcpy(key, sk, CRYPTO_HAETAE_SEED_BYTES);

    // A' = PRG(rhoprime)
    crypto_haetae_polymatkl_expand(A, rhoprime, parameters);
    crypto_haetae_polymatkl_double(A, parameters);


    if(haetae_d) {
        crypto_haetae_polyveck_expand(a, rhoprime, parameters);

        // first column of A = 2(a-b1*2^d)
        crypto_haetae_polyveck_double(b1, parameters);
        crypto_haetae_polyveck_sub(b1, a, b1, parameters);
        crypto_haetae_polyveck_double(b1, parameters);
        crypto_haetae_polyveck_ntt(b1, parameters);
    }

    // Append b to A.
    for (i = 0; i < parameters->k; ++i) {
        A[i].vec[0] = b1->vec[i];
    }
}

/*************************************************
 * Name:        pack_sig
 *
 * Description: Bit-pack signature sig = (c, LB(z1), len(x), len(y), x =
 *Enc(HB(z1)), y = Enc(h)), Zeropadding.
 *
 * Arguments:   - uint8_t  sig[]: output byte array
 *              - const crypto_haetae_poly *c: pointer to challenge polynomial
 *              - const crypto_haetae_polyvecl *lowbits_z1: pointer to vector LowBits(z1) of
 *length L
 *              - const crypto_haetae_polyvecl *highbits_z1: pointer to vector HighBits(z1) of
 *length L
 *              - const crypto_haetae_polyveck *h: pointer t vector h of length K
 * Returns 1 in case the signature packing failed; otherwise 0.
 **************************************************/
int crypto_haetae_pack_sig(uint8_t  *sig,
                    const crypto_haetae_poly *c, const crypto_haetae_polyvecl *lowbits_z1,
                    const crypto_haetae_polyvecl *highbits_z1, const crypto_haetae_polyveck *h,
                    const crypto_haetae_parameters *parameters)
{
    unsigned int i;
    size_t offset = 0;
    const size_t sig_size = parameters->signature_bytes;
    const size_t encode_hb_z1_size =
        CRYPTO_HAETAE_N * (size_t)parameters->l;
    uint8_t encoded_h[CRYPTO_HAETAE_MAX_HINT_COEFFICIENTS] = {0};
    uint8_t encoded_hb_z1[CRYPTO_HAETAE_MAX_Z1_COEFFICIENTS] = {0};
    uint16_t size_enc_h, size_enc_hb_z1;
    uint8_t  offset_enc_h, offset_enc_hb_z1;

    memset(sig, 0, sig_size);

    /* ---- 1. encode challenge c ---- */
    for (i = 0; i < CRYPTO_HAETAE_N; i++) {
        size_t byte_idx = i / 8;
        if (byte_idx >= sig_size) return 1; // overflow check
        sig[byte_idx] |= (c->coeffs[i] & 1) << (i % 8);
    }
    offset = CRYPTO_HAETAE_N / 8;

    /* ---- 2. encode lowbits_z1 ---- */
    if (offset + encode_hb_z1_size > sig_size) return 1;
    for (i = 0; i < parameters->l; ++i)
        crypto_haetae_poly_decomposed_pack(sig + offset + CRYPTO_HAETAE_N * i, &lowbits_z1->vec[i]);
    offset += encode_hb_z1_size;

    /* ---- 3. encode highbits_z1, h ---- */
    size_enc_hb_z1 = crypto_haetae_encode_hb_z1(encoded_hb_z1, &highbits_z1->vec[0].coeffs[0], parameters);
    size_enc_h = crypto_haetae_encode_h(encoded_h, &h->vec[0].coeffs[0], parameters);
    if (size_enc_h == 0 || size_enc_hb_z1 == 0) return 1;

    if (size_enc_h < parameters->base_encoding_hint || size_enc_hb_z1 < parameters->base_encoding_high_bits_z1 ||
        size_enc_h > parameters->base_encoding_hint + 255 ||
        size_enc_hb_z1 > parameters->base_encoding_high_bits_z1 + 255) {
        return 1;
    }

    offset_enc_hb_z1 = (uint8_t)(
        size_enc_hb_z1 - parameters->base_encoding_high_bits_z1);
    offset_enc_h = (uint8_t)(
        size_enc_h - parameters->base_encoding_hint);

    /* ---- 4. write encoded h, z1 ---- */
    if (offset + 2u + size_enc_hb_z1 + size_enc_h > sig_size)
        return 1; // overflow protection

    sig[offset++] = offset_enc_hb_z1;
    sig[offset++] = offset_enc_h;

    memcpy(sig + offset, encoded_hb_z1, size_enc_hb_z1);
    offset += size_enc_hb_z1;

    memcpy(sig + offset, encoded_h, size_enc_h);
    offset += size_enc_h;

    if (offset > sig_size) {
        return 1;
    }

    return 0;
}
/*************************************************
 * Name:        unpack_sig
 *
 * Description: Unpack signature sig = (c, LB(z1), len(x), len(y), x =
 *Enc(HB(z1)), y = Enc(h)), Zeropadding.
 *
 * Arguments:   - crypto_haetae_poly *c: pointer to challenge polynomial
 *              - crypto_haetae_polyvecl *lowbits_z1: pointer to output vector LowBits(z1)
 *              - crypto_haetae_polyvecl *highbits_z1: pointer to output vector HighBits(z1)
 *              - crypto_haetae_polyveck *h: pointer to output vector h
 *              - const uint8_t  sig[]: byte array containing
 *                bit-packed signature
 *
 * Returns 1 in case of malformed signature; otherwise 0.
 **************************************************/
int crypto_haetae_unpack_sig(crypto_haetae_poly *c,
                      crypto_haetae_polyvecl *lowbits_z1, crypto_haetae_polyvecl *highbits_z1, crypto_haetae_polyveck *h,
                      const uint8_t  sig[CRYPTO_HAETAE_MAX_SIGNATURE_BYTES],
                      const crypto_haetae_parameters *parameters) {

    unsigned int i;
    uint16_t size_enc_hb_z1, size_enc_h;

    const uint32_t haetae_l = parameters->l;
    const size_t sig_size = parameters->signature_bytes;

    for (i = 0; i < CRYPTO_HAETAE_N; i++)
    {
      c->coeffs[i] = (sig[i/8] >> (i%8)) & 1;
    }

    sig += CRYPTO_HAETAE_N / 8;

    for (i = 0; i < haetae_l; ++i)
        crypto_haetae_poly_decomposed_unpack(&lowbits_z1->vec[i], sig + CRYPTO_HAETAE_N * i);
    sig += haetae_l * CRYPTO_HAETAE_N;

    size_enc_hb_z1 = (uint16_t)sig[0] + parameters->base_encoding_high_bits_z1;
    size_enc_h = (uint16_t)sig[1] + parameters->base_encoding_hint;
    sig += 2;

    if (sig_size < (2u + (size_t)haetae_l * CRYPTO_HAETAE_N +
                    CRYPTO_HAETAE_SEED_BYTES + size_enc_h +
                    size_enc_hb_z1))
        return 1; // invalid size_enc_h and/or size_enc_hb_z1

    if (crypto_haetae_decode_hb_z1(&highbits_z1->vec[0].coeffs[0], sig, size_enc_hb_z1, parameters)) {
        return 1; // decoding failed
    }

    sig += size_enc_hb_z1;

    if (crypto_haetae_decode_h(&h->vec[0].coeffs[0], sig, size_enc_h, parameters)) {
        return 1; // decoding failed
    }

    sig += size_enc_h;

    for (i = 0; i < sig_size -
            (CRYPTO_HAETAE_SEED_BYTES +
             (size_t)haetae_l * CRYPTO_HAETAE_N + 2u +
             size_enc_hb_z1 + size_enc_h);
         i++)
        if (sig[i] != 0)
            return 1; // verify zero padding

    return 0;
}
