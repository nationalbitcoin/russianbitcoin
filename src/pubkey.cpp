// Copyright (c) 2009-2019 The Bitcoin Core developers
// Copyright (c) 2017 The Zcash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <pubkey.h>
#include <ed25519.h>
#include <iostream>
#include <util/strencodings.h>

bool CPubKey::Verify(const uint512 &hash, const std::vector<unsigned char>& vchSig) const {
    if (!IsValid())
        return false;
    return ed25519_verify(vchSig.data(), hash.begin(), hash.size(), &vch[1]) != 0;
}

bool CPubKey::RecoverCompact(const uint512 &hash, const std::vector<unsigned char>& vchSig) {
    // Must be enough to contain public key and signature
    if (vchSig.size() != JOINED_SIGNATURE_SIZE)
        return false;
    // Set public key
    Set32(vchSig.data());
    // Verify signature
    return ed25519_verify(vchSig.data() + 32, hash.begin(), hash.size(), vchSig.data()) != 0;
}

bool CPubKey::Derive(CPubKey& pubkeyChild, ChainCode &ccChild, unsigned int nChild, const ChainCode& cc) const {
    assert(IsValid());
    assert((nChild >> 31) == 0);
    assert(size() == SIZE);
    unsigned char out[64];
    BIP32Hash_32(cc, nChild, *begin(), begin()+1, out);
    memcpy(ccChild.begin(), out+32, 32);
    pubkeyChild.Set(begin(), end());
    ed25519_add_scalar((unsigned char*)(pubkeyChild.begin() + 1), nullptr, out);
    return true;
}

void CExtPubKey::Encode(unsigned char code[BIP32_EXTKEY_SIZE]) const {
    code[0] = nDepth;
    memcpy(code+1, vchFingerprint, 4);
    code[5] = (nChild >> 24) & 0xFF; code[6] = (nChild >> 16) & 0xFF;
    code[7] = (nChild >>  8) & 0xFF; code[8] = (nChild >>  0) & 0xFF;
    memcpy(code+9, chaincode.begin(), 32);
    assert(pubkey.size() == CPubKey::SIZE);
    memcpy(code+41, pubkey.begin(), CPubKey::SIZE);
}

void CExtPubKey::Decode(const unsigned char code[BIP32_EXTKEY_SIZE]) {
    nDepth = code[0];
    memcpy(vchFingerprint, code+1, 4);
    nChild = (code[5] << 24) | (code[6] << 16) | (code[7] << 8) | code[8];
    memcpy(chaincode.begin(), code+9, 32);
    pubkey.Set(code+41, code+BIP32_EXTKEY_SIZE);
}

bool CExtPubKey::Derive(CExtPubKey &out, unsigned int _nChild) const {
    out.nDepth = nDepth + 1;
    CKeyID id = pubkey.GetID();
    memcpy(&out.vchFingerprint[0], &id, 4);
    out.nChild = _nChild;
    return pubkey.Derive(out.pubkey, out.chaincode, _nChild, chaincode);
}
