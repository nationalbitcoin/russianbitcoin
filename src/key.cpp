// Copyright (c) 2009-2019 The Bitcoin Core developers
// Copyright (c) 2017 The Zcash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <key.h>

#include <crypto/common.h>
#include <crypto/hmac_sha3_512.h>
#include <random.h>

#include <ed25519.h>

void CKey::MakeNewKey() {
    CPrivKey seed(32);
    GetStrongRandBytes(seed.data(), seed.size());
    ed25519_create_privkey(keydata.data(), seed.data());
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
    unsigned char vch[32];
    ed25519_get_pubkey(&vch[0], keydata.data());
    CPubKey result;
    result.Set32(&vch[0]);
    return result;
}

bool CKey::Sign(const uint512 &hash, std::vector<unsigned char>& vchSig, bool grind, uint32_t test_case) const {
    if (!fValid)
        return false;
    vchSig.resize(CPubKey::SIGNATURE_SIZE);

    unsigned char vch[32];
    ed25519_get_pubkey(&vch[0], keydata.data());
    ed25519_sign(vchSig.data(), hash.begin(), hash.size(), &vch[0], keydata.data());
    
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

    unsigned char *pubkey = vchSig.data();
    unsigned char *signature = vchSig.data() + 32;

    // Get public key
    ed25519_get_pubkey(pubkey, keydata.data());
    // Make signature
    ed25519_sign(signature, hash.begin(), hash.size(), pubkey, keydata.data());

    return ed25519_verify(signature, hash.begin(), hash.size(), pubkey) != 0;
}

bool CKey::Load(const CPrivKey &privkey, const CPubKey &vchPubKey, bool fSkipCheck=false) {
    // Must be 64 bytes long
    if (privkey.size() != SIZE)
        return false;

    // Copy private key
    memcpy((unsigned char*)begin(), privkey.data(), privkey.size());

    fValid = true;

    if (fSkipCheck)
        return true;

    return VerifyPubKey(vchPubKey);
}

bool CKey::Derive(CKey& keyChild, ChainCode &ccChild, unsigned int nChild, const ChainCode& cc) const {
    assert(IsValid());
    std::vector<unsigned char, secure_allocator<unsigned char>> vout(64);
    if ((nChild >> 31) == 0) {
        CPubKey pubkey = GetPubKey();
        assert(pubkey.size() == CPubKey::SIZE);
        BIP32Hash_32(cc, nChild, *pubkey.begin(), pubkey.begin()+1, vout.data());
    } else {
        assert(size() == 64);
        BIP32Hash_64(cc, nChild, 0, begin(), vout.data());
    }
    memcpy(ccChild.begin(), vout.data()+32, 32);
    keyChild.Set(begin(), end());
    ed25519_add_scalar(nullptr, (unsigned char*)keyChild.begin(), vout.data());
    keyChild.fValid = true;
    return true;
}

bool CExtKey::Derive(CExtKey &out, unsigned int _nChild) const {
    out.nDepth = nDepth + 1;
    CKeyID id = key.GetPubKey().GetID();
    memcpy(&out.vchFingerprint[0], &id, 4);
    out.nChild = _nChild;
    return key.Derive(out.key, out.chaincode, _nChild, chaincode);
}

void CExtKey::SetSeed(const unsigned char *seed, unsigned int nSeedLen) {
    static const unsigned char hashkey[] = {'B','i','t','c','o','i','n',' ','s','e','e','d'};
    std::vector<unsigned char, secure_allocator<unsigned char>> vout(64);
    CHMAC_SHA3_512(hashkey, sizeof(hashkey)).Write(seed, nSeedLen).Finalize(vout.data());
    key.Set(vout.data(), vout.data() + 64);
    memcpy(chaincode.begin(), vout.data() + 32, 32);
    nDepth = 0;
    nChild = 0;
    memset(vchFingerprint, 0, sizeof(vchFingerprint));
}

CExtPubKey CExtKey::Neuter() const {
    CExtPubKey ret;
    ret.nDepth = nDepth;
    memcpy(&ret.vchFingerprint[0], &vchFingerprint[0], 4);
    ret.nChild = nChild;
    ret.pubkey = key.GetPubKey();
    ret.chaincode = chaincode;
    return ret;
}

void CExtKey::Encode(unsigned char code[BIP32_EXT_PRIVKEY_SIZE]) const {
    code[0] = nDepth;
    memcpy(code+1, vchFingerprint, 4);
    code[5] = (nChild >> 24) & 0xFF; code[6] = (nChild >> 16) & 0xFF;
    code[7] = (nChild >>  8) & 0xFF; code[8] = (nChild >>  0) & 0xFF;
    memcpy(code+9, chaincode.begin(), 32);
    code[41] = 0;
    assert(key.size() == 64);
    memcpy(code+42, key.begin(), 64);
}

void CExtKey::Decode(const unsigned char code[BIP32_EXT_PRIVKEY_SIZE]) {
    nDepth = code[0];
    memcpy(vchFingerprint, code+1, 4);
    nChild = (code[5] << 24) | (code[6] << 16) | (code[7] << 8) | code[8];
    memcpy(chaincode.begin(), code+9, 32);
    key.Set(code+42, code+BIP32_EXT_PRIVKEY_SIZE);
}
