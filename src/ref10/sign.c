#include "ed25519.h"
#include "sha3.h"
#include "ge.h"
#include "sc.h"


void ed25519_sign(unsigned char *signature, const unsigned char *message, size_t message_len, const unsigned char *public_key, const unsigned char *private_key) {
    SHA3_CTX hash;
    unsigned char hram[64];
    unsigned char tmp[64];
    unsigned char r[64];
    ge_p3 R;

    // Use double sha3-512 to generate
    //  r parameter for signing
    sha3_512_Init(&hash);
    sha3_Update(&hash, private_key, 32);
    sha3_Update(&hash, message, message_len);
    sha3_Final(&hash, tmp);

    sha3_512_Init(&hash);
    sha3_Update(&hash, tmp, 64);
    sha3_Final(&hash, r);

    sc_reduce(r);
    ge_scalarmult_base(&R, r);
    ge_p3_tobytes(signature, &R);

    sha3_512_Init(&hash);
    sha3_Update(&hash, signature, 32);
    sha3_Update(&hash, public_key, 32);
    sha3_Update(&hash, message, message_len);
    sha3_Final(&hash, hram);

    sc_reduce(hram);
    sc_muladd(signature + 32, hram, private_key, r);
}
