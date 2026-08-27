// SPDX-License-Identifier: MIT

#ifndef _HAETAE_ENCODING_H_
#define _HAETAE_ENCODING_H_

#include "haetae.h"
#include "haetae_rans_byte.h"

typedef struct crypto_haetae_rans_table {
    uint32_t m_h;
    uint32_t offset_h;
    uint32_t m_hb_z1;
    uint32_t offset_hb_z1;

    const RansEncSymbol *esyms_h;      // length = m_h
    const RansDecSymbol *dsyms_h;      // length = m_h
    const uint16_t      *symbol_h;     // length = (1<<10)

    const RansEncSymbol *esyms_hb_z1;  // length = m_hb_z1
    const RansDecSymbol *dsyms_hb_z1;  // length = m_hb_z1
    const uint16_t      *symbol_hb_z1; // length = (1<<10)
} crypto_haetae_rans_table;



uint16_t crypto_haetae_encode_h(uint8_t  *buf, const int *h, const crypto_haetae_parameters *parameters);
uint16_t crypto_haetae_decode_h(int *h, const uint8_t  *buf, uint16_t size_in, const crypto_haetae_parameters *parameters);
uint16_t crypto_haetae_encode_hb_z1(uint8_t  *buf, const int *hb_z1, const crypto_haetae_parameters *parameters);
uint16_t crypto_haetae_decode_hb_z1(int *hb_z1, const uint8_t  *buf, uint16_t size_in, const crypto_haetae_parameters *parameters);

#endif /* _HAETAE_ENCODING_H_ */
