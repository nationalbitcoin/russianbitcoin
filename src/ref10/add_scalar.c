#include "ed25519.h"
#include "ge.h"
#include "sc.h"

static void multiply(uint8_t *dst, const uint8_t *src, int bytes){
    int i;
    uint8_t prev_acc = 0;
    for (i = 0; i < bytes; i++) {
        dst[i] = (src[i] << 3) + (prev_acc & 0x7);
        prev_acc = src[i] >> 5;
    }
    dst[bytes] = src[bytes-1] >> 5;
}

static void scalar_add(const uint8_t *src1, const uint8_t *src2, uint8_t *res){
    uint16_t r = 0; int i;
    for (i = 0; i < 32; i++) {
        r = (uint16_t) src1[i] + (uint16_t) src2[i] + r;
        res[i] = (uint8_t) r;
        r >>= 8;
    }
}

int ed25519_add_scalar(unsigned char *public_key, unsigned char *private_key, const unsigned char *scalar) {
    unsigned char Z[32] = {0};
    unsigned char Z8[32] = {0};

    int i;

    /* Init Z by first 28 bytes of scalar */
    for (i = 0; i < 28; ++i) {
        Z[i] = scalar[i];
    }
    
    /* Multiply Z by 8 */
    multiply(Z8, Z, 32);

    /* private key: child = 8*Z + parent */
    if (private_key) {
        scalar_add(Z8, private_key, private_key);
    }

    /* public key: child = parent + 8*Z */
    if (public_key) {
        ge_point_add(public_key, Z8, public_key);
    }

    return 1;
}
