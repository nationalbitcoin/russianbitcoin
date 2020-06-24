#include "ed25519.h"
#include "hash/sha3.h"
#include "ge.h"
#include "sc.h"

int ed25519_verify(const unsigned char *signature, const unsigned char *message, size_t message_len, const unsigned char *public_key) {
    unsigned char h[64];
    unsigned char checker[32];
    SHA3_CTX hash;
    ge_p3 A;
    ge_p2 R;

    if (signature[63] & 224) {
        return 0;
    }

    if (ge_frombytes_negate_vartime(&A, public_key) != 0) {
        return 0;
    }

    sha3_512_Init(&hash);
    sha3_Update(&hash, signature, 32);
    sha3_Update(&hash, public_key, 32);
    sha3_Update(&hash, message, message_len);
    sha3_Final(&hash, h);
    
    sc_reduce(h);
    ge_double_scalarmult_vartime(&R, h, &A, signature + 32);
    ge_tobytes(checker, &R);

    if (!ed25519_consttime_equal_32(checker, signature)) {
        return 0;
    }

    return 1;
}
