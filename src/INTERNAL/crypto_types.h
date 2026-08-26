#ifndef CRYPTO_INTERNAL_TYPES_H
#define CRYPTO_INTERNAL_TYPES_H

/*
 * Internal portability shim.
 * If the public TYPES.h has already supplied size_t/fixed-width integers, use
 * those definitions. Otherwise prefer the implementation's standard headers.
 * Legacy MSVC is handled explicitly because older releases shipped without
 * <stdint.h>.
 */
#if defined(CRYPTO_PUBLIC_TYPES_H)
/* Types are already available through the public portability header. */
#elif defined(_MSC_VER) && (_MSC_VER < 1600)
#  ifndef _SIZE_T_DEFINED
#    if defined(_WIN64)
typedef unsigned __int64 size_t;
#    else
typedef unsigned int size_t;
#    endif
#    define _SIZE_T_DEFINED
#  endif
typedef signed __int8 int8_t;
typedef unsigned __int8 uint8_t;
typedef signed __int16 int16_t;
typedef unsigned __int16 uint16_t;
typedef signed __int32 int32_t;
typedef unsigned __int32 uint32_t;
typedef signed __int64 int64_t;
typedef unsigned __int64 uint64_t;
#else
#  include <stddef.h>
#  include <stdint.h>
#endif

typedef char CRYPTO_INTERNAL_U8_IS_1[(sizeof(uint8_t) == 1u) ? 1 : -1];
typedef char CRYPTO_INTERNAL_U16_IS_2[(sizeof(uint16_t) == 2u) ? 1 : -1];
typedef char CRYPTO_INTERNAL_U32_IS_4[(sizeof(uint32_t) == 4u) ? 1 : -1];
typedef char CRYPTO_INTERNAL_U64_IS_8[(sizeof(uint64_t) == 8u) ? 1 : -1];

#endif
