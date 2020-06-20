#include "ed25519.h"
#include "sha3.h"
#include "ge.h"

void ed25519_get_pubkey(unsigned char *public_key, const unsigned char *private_key) {
    ge_p3 A;

    ge_scalarmult_base(&A, private_key);
    ge_p3_tobytes(public_key, &A);
}

void ed25519_create_privkey(unsigned char *private_key, const unsigned char *seed) {
    sha3_512(seed, 32, private_key);
    private_key[0] &= 248;
    private_key[31] &= 63;
    private_key[31] |= 64;
}

void ed25519_create_keypair(unsigned char *public_key, unsigned char *private_key, const unsigned char *seed) {
    sha3_512(seed, 32, private_key);
    private_key[0] &= 248;
    private_key[31] &= 63;
    private_key[31] |= 64;
    ed25519_get_pubkey(public_key, private_key);
}
