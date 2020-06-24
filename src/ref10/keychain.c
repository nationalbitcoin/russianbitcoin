#include <string.h>
#include <assert.h>
#include "ed25519.h"
#include "hash/hmac_sha3.h"
#include "hash/ripemd160.h"

const unsigned int BIP32_EXTKEY_SIZE = 74;

static void BIP32Hash(const unsigned char chainCode[32], unsigned int nChild, unsigned char header, const unsigned char data[32], unsigned char output[64])
{
    unsigned char num[4];
    hmac_sha512_ctx hmac_ctx;

    num[0] = (nChild >> 24) & 0xFF;
    num[1] = (nChild >> 16) & 0xFF;
    num[2] = (nChild >>  8) & 0xFF;
    num[3] = (nChild >>  0) & 0xFF;

    // Calculate hmac for data and num using chain code as hash key
    hmac_sha3_512_init(&hmac_ctx, chainCode, 32);
    hmac_sha3_512_update(&hmac_ctx, &header, 1);
    hmac_sha3_512_update(&hmac_ctx, data, 32);
    hmac_sha3_512_update(&hmac_ctx, num, sizeof(num));
    hmac_sha3_512_final(&hmac_ctx, output, 64);
}

void keychain_private_rebuild(const KEYCHAIN_PUBLIC_CTX *from, const unsigned char key[32], KEYCHAIN_PRIVATE_CTX *to) {
    to->nDepth = from->nDepth;
    to->nChild = from->nChild;
    memcpy(to->key, key, 32);
    memcpy(to->pubkey, from->pubkey, 32);
    memcpy(to->chaincode, from->chaincode, 32);
    memcpy(to->vchFingerprint, from->vchFingerprint, 32);
}

void keychain_private_init(KEYCHAIN_PRIVATE_CTX *ctx, const unsigned char *seed, size_t seed_len) {
    static const unsigned char hashkey[] = {'E','D','2','5','5','1','9',' ','s','e','e','d'};
    unsigned char key_mac[64];
    hmac_sha512_ctx hmac_ctx;

    // Calculate hmac for given seed using hardcoded hash key
    hmac_sha3_512_init(&hmac_ctx, hashkey, sizeof(hashkey));
    hmac_sha3_512_update(&hmac_ctx, seed, seed_len);
    hmac_sha3_512_final(&hmac_ctx, key_mac, sizeof(key_mac));

    // Copy first part of hash to be used as key
    memcpy(ctx->key, key_mac, 32);

    // Public key is used for non-hardened generation and key fingerprinting
    ed25519_get_pubkey(ctx->pubkey, ctx->key);

    // Second part is used as chain code
    memcpy(ctx->chaincode, key_mac + 32, 32);

    // Root node params
    ctx->nDepth = 0;
    ctx->nChild = 0;
    memset(ctx->vchFingerprint, 0, sizeof(ctx->vchFingerprint));
}

void keychain_private_derive(const KEYCHAIN_PRIVATE_CTX *ctx, KEYCHAIN_PRIVATE_CTX *child_ctx, unsigned int nChild) {
    SHA3_CTX sha3_ctx;
    unsigned char prefix = 0x03;
    unsigned char bip32_hash[64];
    unsigned char tmp_hash[SHA3_256_DIGEST_LENGTH];
    unsigned char public_key_id[RIPEMD160_DIGEST_LENGTH];

    // Next children
    child_ctx->nChild = ctx->nChild + 1;
    
    // Get key fingerprint
    //   First 4 bytes of RIPEMD160(SHA3-256(0x03 + public key))
    sha3_256_Init(&sha3_ctx);
    sha3_Update(&sha3_ctx, &prefix, 1);
    sha3_Final(&sha3_ctx, tmp_hash);
    ripemd160(tmp_hash, sizeof(tmp_hash), public_key_id);
    memcpy(child_ctx->vchFingerprint, public_key_id, 4);

    // Derive child key
    if ((nChild >> 31) == 0) {
        // Non-hardened
        BIP32Hash(ctx->chaincode, nChild, 0x03, ctx->pubkey, bip32_hash);
    } else {
        // Hardened
        BIP32Hash(ctx->chaincode, nChild, 0, ctx->key, bip32_hash);
    }

    // Set chain code for child key
    memcpy(child_ctx->chaincode, bip32_hash+32, 32);

    // Generate children private key
    //  a = n + t
    memcpy(child_ctx->key, ctx->key, 32);
    ed25519_add_scalar(NULL, child_ctx->key, bip32_hash);

    // Public key is used for non-hardened generation and key fingerprinting
    ed25519_get_pubkey(child_ctx->pubkey, child_ctx->key);
}

void keychain_private_neuter(const KEYCHAIN_PRIVATE_CTX *ctx, KEYCHAIN_PUBLIC_CTX *public_ctx) {
    // Copy derivation context
    public_ctx->nDepth = ctx->nDepth;
    public_ctx->nChild = ctx->nChild;
    memcpy(public_ctx->vchFingerprint, ctx->vchFingerprint, 4);
    memcpy(public_ctx->chaincode, ctx->chaincode, sizeof(ctx->chaincode));
    // Copy public key
    memcpy(public_ctx->pubkey, ctx->pubkey, sizeof(ctx->pubkey));
}

void keychain_private_export(const KEYCHAIN_PRIVATE_CTX *ctx, unsigned char binary[BIP32_EXTKEY_SIZE]) {
    // Create xpriv binary representation
    //  Note: public key is not exported

    // Chain depth
    binary[0] = ctx->nDepth;
    // Save key fingerprint
    memcpy(binary+1, ctx->vchFingerprint, 4);
    // Child path
    binary[5] = (ctx->nChild >> 24) & 0xFF; binary[6] = (ctx->nChild >> 16) & 0xFF;
    binary[7] = (ctx->nChild >>  8) & 0xFF; binary[8] = (ctx->nChild >>  0) & 0xFF;
    // Copy chain code
    memcpy(binary+9, ctx->chaincode, 32);
    // Private key prefix is always 0x00
    binary[41] = 0;
    // Copy private key
    memcpy(binary+42, ctx->key, 32);
}

void keychain_private_import(KEYCHAIN_PRIVATE_CTX *ctx, const unsigned char binary[BIP32_EXTKEY_SIZE]) {
    // Init structure with data from binary representation
    ctx->nDepth = binary[0];
    memcpy(ctx->vchFingerprint, binary+1, 4);
    ctx->nChild = (binary[5] << 24) | (binary[6] << 16) | (binary[7] << 8) | binary[8];
    memcpy(ctx->chaincode, binary+9, 32);
    memcpy(ctx->key, binary+42, 32);
    // Public key is used for non-hardened generation and key fingerprinting
    ed25519_get_pubkey(ctx->pubkey, ctx->key);
}

int keychain_private_equals(const KEYCHAIN_PRIVATE_CTX *ctx1, const KEYCHAIN_PRIVATE_CTX *ctx2) {
    int r = 0;
    
    // Use xor / and for constant time comparison
    r |= ctx1->nDepth ^ ctx2->nDepth;
    r |= ctx1->nChild ^ ctx2->nChild;
    r |= !ed25519_consttime_equal_32(ctx1->key, ctx2->key);
    r |= !ed25519_consttime_equal_32(ctx1->pubkey, ctx2->pubkey);
    r |= !ed25519_consttime_equal_32(ctx1->chaincode, ctx2->chaincode);
    r |= !ed25519_consttime_equal_4(ctx1->vchFingerprint, ctx2->vchFingerprint);
    return !r;
}

const unsigned char * keychain_private_get_key(const KEYCHAIN_PRIVATE_CTX *ctx) {
    return &ctx->key[0];
}

const unsigned char * keychain_private_get_pubkey(const KEYCHAIN_PRIVATE_CTX *ctx) {
    return &ctx->pubkey[0];
}

void keychain_public_derive(const KEYCHAIN_PUBLIC_CTX *ctx, KEYCHAIN_PUBLIC_CTX *child_ctx, unsigned int nChild) {
    unsigned char bip32_hash[64];

    // Only non-hardened generation possible here
    assert((nChild >> 31) == 0);
    // Derive child key
    BIP32Hash(ctx->chaincode, nChild, 0x03, ctx->pubkey, bip32_hash);
    // Set chain code for child key
    memcpy(child_ctx->chaincode, bip32_hash+32, 32);

    // Generate children public key
    // A = nB + T
    memcpy(child_ctx->pubkey, ctx->pubkey, 32);
    ed25519_add_scalar(child_ctx->pubkey, NULL, bip32_hash);
}

void keychain_public_export(const KEYCHAIN_PUBLIC_CTX *ctx, unsigned char binary[BIP32_EXTKEY_SIZE]) {
    // Create xpub binary representation

    // Chain depth
    binary[0] = ctx->nDepth;
    // Save key fingerprint
    memcpy(binary+1, ctx->vchFingerprint, 4);
    // Child path
    binary[5] = (ctx->nChild >> 24) & 0xFF; binary[6] = (ctx->nChild >> 16) & 0xFF;
    binary[7] = (ctx->nChild >>  8) & 0xFF; binary[8] = (ctx->nChild >>  0) & 0xFF;
    // Copy chain code
    memcpy(binary+9, ctx->chaincode, 32);
    // Public key prefix is always 0x03
    binary[41] = 0x03;
    // Copy public key
    memcpy(binary+42, ctx->pubkey, 32);
}

void keychain_public_import(KEYCHAIN_PUBLIC_CTX *ctx, const unsigned char binary[BIP32_EXTKEY_SIZE]) {
    // Init structure with data from binary representation
    ctx->nDepth = binary[0];
    memcpy(ctx->vchFingerprint, binary+1, 4);
    ctx->nChild = (binary[5] << 24) | (binary[6] << 16) | (binary[7] << 8) | binary[8];
    memcpy(ctx->chaincode, binary+9, 32);
    memcpy(ctx->pubkey, binary+42, 32);
}

int keychain_public_equals(const KEYCHAIN_PUBLIC_CTX *ctx1, const KEYCHAIN_PUBLIC_CTX *ctx2) {
    int r = 0;
    
    // Use xor / and for constant time comparison
    r |= ctx1->nDepth ^ ctx2->nDepth;
    r |= ctx1->nChild ^ ctx2->nChild;
    r |= !ed25519_consttime_equal_32(ctx1->pubkey, ctx2->pubkey);
    r |= !ed25519_consttime_equal_32(ctx1->chaincode, ctx2->chaincode);
    r |= !ed25519_consttime_equal_4(ctx1->vchFingerprint, ctx2->vchFingerprint);
    return !r;
}

const unsigned char * keychain_public_get_pubkey(const KEYCHAIN_PUBLIC_CTX *ctx) {
    return &ctx->pubkey[0];
}
