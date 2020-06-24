// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2019 The Bitcoin Core developers
// Copyright (c) 2017 The Zcash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_KEY_H
#define BITCOIN_KEY_H

#include <pubkey.h>
#include <serialize.h>
#include <support/allocators/secure.h>
#include <uint256.h>
#include <ed25519.h>

#include <stdexcept>
#include <vector>

/**
 * secure_allocator is defined in allocators.h
 * CPrivKey is a serialized private key, with all parameters included
 * (SIZE bytes)
 */
typedef std::vector<unsigned char, secure_allocator<unsigned char> > CPrivKey;

/** An encapsulated private key. */
class CKey
{
public:
    static const unsigned int SIZE            = 32;

private:
    //! Whether this private key is valid. We check for correctness when modifying the key
    //! data, so fValid should always correspond to the actual state.
    bool fValid;

    //! The actual byte data
    std::vector<unsigned char, secure_allocator<unsigned char> > keydata;
    //! Cached public key
    unsigned char pubkey[32];

public:
    //! Construct an invalid private key.
    CKey() : fValid(false)
    {
        // Important: vch must be 32 bytes in length
        keydata.resize(32);
    }

    friend bool operator==(const CKey& a, const CKey& b)
    {
        return memcmp(a.keydata.data(), b.keydata.data(), a.size()) == 0 && memcmp(a.pubkey, b.pubkey, sizeof(a)) == 0;
    }

    //! Initialize using begin and end iterators to byte data.
    template <typename T>
    void Set(const T pbegin, const T pend)
    {
        if (size_t(pend - pbegin) != keydata.size()) {
            fValid = false;
        } else {
            memcpy(keydata.data(), (unsigned char*)&pbegin[0], keydata.size());
            ed25519_get_pubkey(pubkey, keydata.data());
            fValid = true;
        }
    }

    //! Simple read-only vector-like interface.
    unsigned int size() const { return (fValid ? keydata.size() : 0); }
    const unsigned char* begin() const { return keydata.data(); }
    const unsigned char* end() const { return keydata.data() + size(); }

    //! Check whether this private key is valid.
    bool IsValid() const { return fValid; }

    //! Generate a new private key using a cryptographic PRNG.
    void MakeNewKey();

    /**
     * Convert the private key to a CPrivKey (serialized OpenSSL private key data).
     * This is expensive.
     */
    CPrivKey GetPrivKey() const;

    /**
     * Compute the public key from a private key.
     * This is expensive.
     */
    CPubKey GetPubKey() const;

    /**
     * Create a DER-serialized signature.
     * The test_case parameter tweaks the deterministic nonce.
     */
    bool Sign(const uint512& hash, std::vector<unsigned char>& vchSig, bool grind = true, uint32_t test_case = 0) const;

    /**
     * Create a signature (96 bytes) which is joined with public key.
     */
    bool SignCompact(const uint512& hash, std::vector<unsigned char>& vchSig) const;

    /**
     * Verify thoroughly whether a private key and a public key match.
     * This is done using a different mechanism than just regenerating it.
     */
    bool VerifyPubKey(const CPubKey& vchPubKey) const;

    //! Load private key and check that public key matches.
    bool Load(const CPrivKey& privkey, const CPubKey& vchPubKey, bool fSkipCheck);
};

class CExtKey {
private:
    KEYCHAIN_PRIVATE_CTX ctx;
public:
    friend bool operator==(const CExtKey &a, const CExtKey &b)
    {
        return keychain_private_equals(&a.ctx, &b.ctx);
    }

    //! Replace derivation context
    void Set(KEYCHAIN_PRIVATE_CTX &ctx) {
        this->ctx = ctx;
    }
    void Encode(unsigned char code[BIP32_EXTKEY_SIZE]) const;
    void Decode(const unsigned char code[BIP32_EXTKEY_SIZE]);
    //! Derive new extended key
    bool Derive(CExtKey& out, unsigned int nChild) const;
    //! Remove secret and construct extended public key
    CExtPubKey Neuter() const;
    //! Initialize context with new seed
    void SetSeed(const unsigned char* seed, unsigned int nSeedLen);
    //! Get current private key
    CKey GetKey() const;
    //! Get current public key
    CPubKey GetPubKey() const;
};

#endif // BITCOIN_KEY_H
