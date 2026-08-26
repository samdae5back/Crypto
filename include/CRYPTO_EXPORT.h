#ifndef CRYPTO_EXPORT_H
#define CRYPTO_EXPORT_H

#if defined(_WIN32)
#  if defined(CRYPTO_SHARED)
#    if defined(CRYPTO_BUILDING_LIBRARY)
#      define CRYPTO_API __declspec(dllexport)
#    else
#      define CRYPTO_API __declspec(dllimport)
#    endif
#  else
#    define CRYPTO_API
#  endif
#elif defined(__APPLE__) || defined(__linux__)
#  if defined(CRYPTO_SHARED)
#    define CRYPTO_API __attribute__((visibility("default")))
#  else
#    define CRYPTO_API
#  endif
#else
/* Other Unix targets will get an explicit export policy later. */
#  define CRYPTO_API
#endif

#endif
