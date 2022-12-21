// Copyright (c) 2009-2019 The Bitcoin Core developers
// Copyright (c) 2017 The Zcash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <pubkey.h>
#include <key.h>

bool CPubKey::Verify(const uint512 &hash, const std::vector<unsigned char>& vchSig) const {
    if (!IsValid())
        return false;
    return ed25519_verify(vchSig.data(), hash.begin(), hash.size(), &vch[1]) != 0;
}

bool CPubKey::RecoverCompact(const uint512 &hash, const std::vector<unsigned char>& vchSig) {
    // Must be enough to contain public key and signature
    if (vchSig.size() != JOINED_SIGNATURE_SIZE)
        return false;
    // Verify signature
    if(ed25519_verify(vchSig.data() + 32, hash.begin(), hash.size(), vchSig.data()) != 1)
        return false;
    // Set public key
    Set32(vchSig.data());
    return true;
}

void CExtPubKey::Encode(unsigned char code[BIP32_EXTKEY_SIZE]) const {
    keychain_public_export(&ctx, code);
}

void CExtPubKey::Decode(const unsigned char code[BIP32_EXTKEY_SIZE]) {
    keychain_public_import(&ctx, code);
}

bool CExtPubKey::Derive(CExtPubKey &out, unsigned int _nChild) const {
    keychain_public_derive(&ctx, &out.ctx, _nChild);
    return true;
}

CPubKey CExtPubKey::GetPubKey() const {
    CPubKey pubKey;
    const unsigned char *raw = keychain_public_get_pubkey(&ctx);
    pubKey.Set32(raw);
    return pubKey;
}

CExtKey CExtPubKey::Rebuild(const CKey &key) const {
    KEYCHAIN_PRIVATE_CTX priv;
    keychain_private_rebuild(&ctx, key.begin(), &priv);
    CExtKey rebuilt;
    rebuilt.Set(priv);
    return rebuilt;
}
