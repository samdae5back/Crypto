#include "entropy.h"

#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <bcrypt.h>
#pragma comment(lib, "bcrypt.lib")

int crypto_entropy_get(uint8_t *out, size_t out_len) {
    if (!out && out_len) {
        return -1;
    }

    while (out_len) {
        ULONG chunk = out_len > 0xffffffffu ? 0xffffffffu : (ULONG)out_len;
        if (BCryptGenRandom(NULL, out, chunk, BCRYPT_USE_SYSTEM_PREFERRED_RNG) != 0) {
            return -1;
        }
        out += chunk;
        out_len -= chunk;
    }
    return 0;
}

#else

#include <errno.h>
#include <fcntl.h>
#include <unistd.h>

#if defined(__linux__)
#include <sys/random.h>
#endif

#define CRYPTO_ENTROPY_CHUNK (256u * 1024u)

static int read_urandom(uint8_t *out, size_t out_len) {
    int fd;

    do {
        fd = open("/dev/urandom", O_RDONLY);
    } while (fd < 0 && errno == EINTR);

    if (fd < 0) {
        return -1;
    }

    while (out_len) {
        size_t request = out_len > CRYPTO_ENTROPY_CHUNK ? CRYPTO_ENTROPY_CHUNK : out_len;
        ssize_t n = read(fd, out, request);
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            close(fd);
            return -1;
        }
        if (n == 0) {
            close(fd);
            return -1;
        }
        out += (size_t)n;
        out_len -= (size_t)n;
    }

    close(fd);
    return 0;
}

int crypto_entropy_get(uint8_t *out, size_t out_len) {
    if (!out && out_len) {
        return -1;
    }

#if defined(__linux__)
    while (out_len) {
        size_t request = out_len > CRYPTO_ENTROPY_CHUNK ? CRYPTO_ENTROPY_CHUNK : out_len;
        ssize_t n = getrandom(out, request, 0);
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            if (errno == ENOSYS) {
                break;
            }
            return -1;
        }
        if (n == 0) {
            break;
        }
        out += (size_t)n;
        out_len -= (size_t)n;
    }
    if (out_len == 0) {
        return 0;
    }
#endif

    return read_urandom(out, out_len);
}

#endif
