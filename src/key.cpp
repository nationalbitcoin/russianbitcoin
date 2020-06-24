// Copyright (c) 2009-2019 The Bitcoin Core developers
// Copyright (c) 2017 The Zcash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <key.h>

#include <crypto/common.h>
#include <random.h>

void CKey::MakeNewKey() {
    CPrivKey seed(32);
    GetStrongRandBytes(seed.data(), seed.size());
    ed25519_create_privkey(keydata.data(), seed.data());
    ed25519_get_pubkey(pubkey, keydata.data());
    fValid = true;
}

CPrivKey CKey::GetPrivKey() const {
    assert(fValid);
    CPrivKey privkey;
    privkey.resize(SIZE);
    memcpy(privkey.data(), keydata.data(), keydata.size());
    return privkey;
}

CPubKey CKey::GetPubKey() const {
    assert(fValid);
    CPubKey result;
    result.Set32(pubkey);
    return result;
}

bool CKey::Sign(const uint512 &hash, std::vector<unsigned char>& vchSig, bool grind, uint32_t test_case) const {
    if (!fValid)
        return false;
    vchSig.resize(CPubKey::SIGNATURE_SIZE);
    ed25519_sign(vchSig.data(), hash.begin(), hash.size(), pubkey, keydata.data());
    return true;
}

bool CKey::VerifyPubKey(const CPubKey& pubkey) const {
    unsigned char rnd[8];
    std::string str = "Bitcoin key verification\n";
    GetRandBytes(rnd, sizeof(rnd));
    uint512 hash;
    CHashWriter512 ss(SER_GETHASH, 0);
    ss << str << rnd;
    hash = ss.GetHash();
    std::vector<unsigned char> vchSig;
    Sign(hash, vchSig);
    return pubkey.Verify(hash, vchSig);
}

bool CKey::SignCompact(const uint512 &hash, std::vector<unsigned char>& vchSig) const {
    if (!fValid)
        return false;
    // Enough to contain public key + signature
    vchSig.resize(CPubKey::JOINED_SIGNATURE_SIZE);
    // Pointer to beginning of signature
    unsigned char *signature = vchSig.data() + 32;
    // Copy public key
    memcpy(vchSig.data(), pubkey, 32);
    // Make signature
    ed25519_sign(signature, hash.begin(), hash.size(), pubkey, keydata.data());
    // Verify and return
    return ed25519_verify(signature, hash.begin(), hash.size(), pubkey) != 0;
}

bool CKey::Load(const CPrivKey &privkey, const CPubKey &vchPubKey, bool fSkipCheck=false) {
    // Must be either 32 or 64 bytes long
    if (privkey.size() != 32 && privkey.size() != 64)
        return false;

    // Copy private key
    //  We only really need the first 32 bytes
    memcpy((unsigned char*)begin(), privkey.data(), 32);
    // Cached public key
    ed25519_get_pubkey(pubkey, keydata.data());

    fValid = true;
    if (fSkipCheck)
        return true;

    return VerifyPubKey(vchPubKey);
}

bool CExtKey::Derive(CExtKey &out, unsigned int _nChild) const {
    keychain_private_derive(&ctx, &out.ctx, _nChild);
    return true;
}

void CExtKey::SetSeed(const unsigned char *seed, unsigned int nSeedLen) {
    keychain_private_init(&ctx, seed, nSeedLen);
}

CExtPubKey CExtKey::Neuter() const {
    KEYCHAIN_PUBLIC_CTX neutered;
    keychain_private_neuter(&ctx, &neutered);
    CExtPubKey pub;
    pub.Set(neutered);
    return pub;
}

void CExtKey::Encode(unsigned char code[BIP32_EXTKEY_SIZE]) const {
    keychain_private_export(&ctx, code);
}

void CExtKey::Decode(const unsigned char code[BIP32_EXTKEY_SIZE]) {
    keychain_private_import(&ctx, code);
}

CKey CExtKey::GetKey() const {
    CKey key;
    const unsigned char *raw = keychain_private_get_key(&ctx);
    key.Set(raw, raw + 32);
    return key;
}

CPubKey CExtKey::GetPubKey() const {
    CPubKey pubKey;
    const unsigned char *raw = keychain_private_get_pubkey(&ctx);
    pubKey.Set32(raw);
    return pubKey;
}
