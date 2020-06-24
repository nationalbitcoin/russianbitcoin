#ifndef ED25519_H
#define ED25519_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

static const unsigned int BIP32_EXTKEY_SIZE = 74;

// xpriv
typedef struct KEYCHAIN_PRIVATE_CTX {
    unsigned char nDepth;
    unsigned char vchFingerprint[4];
    unsigned int nChild;
    unsigned char chaincode[32];
    unsigned char key[32];
    unsigned char pubkey[32];
} KEYCHAIN_PRIVATE_CTX;

// xpub
typedef struct KEYCHAIN_PUBLIC_CTX {
    unsigned char nDepth;
    unsigned char vchFingerprint[4];
    unsigned int nChild;
    unsigned char chaincode[32];
    unsigned char pubkey[32];
} KEYCHAIN_PUBLIC_CTX;

void keychain_private_rebuild(const KEYCHAIN_PUBLIC_CTX *from, const unsigned char key[32], KEYCHAIN_PRIVATE_CTX *to);
void keychain_private_init(KEYCHAIN_PRIVATE_CTX *ctx, const unsigned char *seed, size_t seed_len);
void keychain_private_derive(const KEYCHAIN_PRIVATE_CTX *ctx, KEYCHAIN_PRIVATE_CTX *child_ctx, unsigned int nChild);
void keychain_private_neuter(const KEYCHAIN_PRIVATE_CTX *ctx, KEYCHAIN_PUBLIC_CTX *public_ctx);
void keychain_private_export(const KEYCHAIN_PRIVATE_CTX *ctx, unsigned char binary[BIP32_EXTKEY_SIZE]);
void keychain_private_import(KEYCHAIN_PRIVATE_CTX *ctx, const unsigned char binary[BIP32_EXTKEY_SIZE]);
int keychain_private_equals(const KEYCHAIN_PRIVATE_CTX *ctx1, const KEYCHAIN_PRIVATE_CTX *ctx2);
const unsigned char * keychain_private_get_key(const KEYCHAIN_PRIVATE_CTX *ctx);
const unsigned char * keychain_private_get_pubkey(const KEYCHAIN_PRIVATE_CTX *ctx);

void keychain_public_derive(const KEYCHAIN_PUBLIC_CTX *ctx, KEYCHAIN_PUBLIC_CTX *child_ctx, unsigned int nChild);
void keychain_public_export(const KEYCHAIN_PUBLIC_CTX *ctx, unsigned char binary[BIP32_EXTKEY_SIZE]);
void keychain_public_import(KEYCHAIN_PUBLIC_CTX *ctx, const unsigned char binary[BIP32_EXTKEY_SIZE]);
int keychain_public_equals(const KEYCHAIN_PUBLIC_CTX *ctx1, const KEYCHAIN_PUBLIC_CTX *ctx2);
const unsigned char * keychain_public_get_pubkey(const KEYCHAIN_PUBLIC_CTX *ctx);

inline int ed25519_consttime_equal_4(const unsigned char *x, const unsigned char *y) {
    unsigned char r = 0;

    r = x[0] ^ y[0];
    #define F(i) r |= x[i] ^ y[i]
    F(1);
    F(2);
    F(3);
    #undef F

    return !r;
}

inline int ed25519_consttime_equal_32(const unsigned char *x, const unsigned char *y) {
    unsigned char r = 0;

    r = x[0] ^ y[0];
    #define F(i) r |= x[i] ^ y[i]
    F(1);
    F(2);
    F(3);
    F(4);
    F(5);
    F(6);
    F(7);
    F(8);
    F(9);
    F(10);
    F(11);
    F(12);
    F(13);
    F(14);
    F(15);
    F(16);
    F(17);
    F(18);
    F(19);
    F(20);
    F(21);
    F(22);
    F(23);
    F(24);
    F(25);
    F(26);
    F(27);
    F(28);
    F(29);
    F(30);
    F(31);
    #undef F

    return !r;
}

void ed25519_create_privkey(unsigned char *private_key, const unsigned char *seed);
void ed25519_create_keypair(unsigned char *public_key, unsigned char *private_key, const unsigned char *seed);
void ed25519_get_pubkey(unsigned char *public_key, const unsigned char *private_key);
void ed25519_sign(unsigned char *signature, const unsigned char *message, size_t message_len, const unsigned char *public_key, const unsigned char *private_key);
int ed25519_verify(const unsigned char *signature, const unsigned char *message, size_t message_len, const unsigned char *public_key);
void ed25519_add_scalar(unsigned char *public_key, unsigned char *private_key, const unsigned char *scalar);
void ed25519_key_exchange(unsigned char *shared_secret, const unsigned char *public_key, const unsigned char *private_key);

#ifdef __cplusplus
}
#endif

#endif
