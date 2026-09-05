#include <LiberaCrypt/LiberaCrypt.h>

#include <stdint.h>

int main(void) {
    static const uint8_t message[] = {0u};
    uint8_t digest[LIBERAC_SHA2_256_DIGEST_BYTES];
    LiberaCError error = LIBERAC_HASH(
        digest, sizeof(digest),
        message, 0u,
        LIBERAC_ALG_HASH_SHA2_256);

    return error == LIBERAC_SUCCESS ? 0 : 1;
}
