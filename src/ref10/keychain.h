// Deterministic key chain derivation

#ifndef KEYCHAIN_H
#define KEYCHAIN_H

#include "hash/hmac_sha3.h"

const unsigned int BIP32_EXTKEY_SIZE = 74;

#ifdef __cplusplus
extern "C" {
#endif

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

#ifdef __cplusplus
}
#endif

#endif
