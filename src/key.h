// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2019 The Bitcoin Core developers
// Copyright (c) 2017 The Zcash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_KEY_H
#define BITCOIN_KEY_H

#include <pubkey.h>
#include <serialize.h>
#include <ed25519.h>
#include <support/allocators/secure.h>
#include <uint256.h>

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
    /**
     * ed25519:
     */
    static const unsigned int SIZE            = 32;

private:
    //! Whether this private key is valid. We check for correctness when modifying the key
    //! data, so fValid should always correspond to the actual state.
    bool fValid;

    //! The actual byte data
    std::vector<unsigned char, secure_allocator<unsigned char> > keydata;

    //! Check whether the 32-byte array pointed to by vch is valid keydata.
    bool static Check(const unsigned char* vch) { return true; }

public:
    //! Construct an invalid private key.
    CKey() : fValid(false)
    {
        // Important: vch must be 32 bytes in length to not break serialization
        keydata.resize(32);
    }

    friend bool operator==(const CKey& a, const CKey& b)
    {
        return memcmp(a.keydata.data(), b.keydata.data(), a.size()) == 0;
    }

    //! Initialize using begin and end iterators to byte data.
    template <typename T>
    void Set(const T pbegin, const T pend)
    {
        if (size_t(pend - pbegin) != keydata.size()) {
            fValid = false;
        } else {
            memcpy(keydata.data(), (unsigned char*)&pbegin[0], keydata.size());
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

    CPrivKey GetPrivKey() const;

    /**
     * Compute the public key from a private key.
     * This is expensive.
     */
    CPubKey GetPubKey() const;

    /**
     * Create simple signature.
     */
    bool Sign(const uint512& hash, std::vector<unsigned char>& vchSig, bool grind = true) const;

    /**
     * Create a concatenated signature
     */
    bool SignCompact(const uint512& hash, std::vector<unsigned char>& vchSig) const;

    //! Derive BIP32 child key.
    bool Derive(CKey& keyChild, ChainCode &ccChild, unsigned int nChild, const ChainCode& cc) const;

    /**
     * Verify thoroughly whether a private key and a public key match.
     */
    bool VerifyPubKey(const CPubKey& vchPubKey) const;

    //! Load private key and check that public key matches.
    bool Load(const CPrivKey& privkey, const CPubKey& vchPubKey, bool fSkipCheck);
};

class CExtKey {
private:
    KEYCHAIN_PRIVATE_CTX ctx;
public:

    friend bool operator==(const CExtKey& a, const CExtKey& b)
    {
        return keychain_private_equals(&a.ctx, &b.ctx);
    }
    
    //! Replace derivation context
    void Set(KEYCHAIN_PRIVATE_CTX &ctx) {
        this->ctx = ctx;
    }

    void Encode(unsigned char code[BIP32_EXTKEY_SIZE]) const;
    void Decode(const unsigned char code[BIP32_EXTKEY_SIZE]);
    bool Derive(CExtKey& out, unsigned int nChild) const;
    CExtPubKey Neuter() const;
    void SetSeed(const unsigned char* seed, unsigned int nSeedLen);

    // Get current private key
    CKey GetKey() const;
    // Get current public key
    CPubKey GetPubKey() const;
};

#endif // BITCOIN_KEY_H
