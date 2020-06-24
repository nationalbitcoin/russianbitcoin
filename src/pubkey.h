// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2019 The Bitcoin Core developers
// Copyright (c) 2017 The Zcash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_PUBKEY_H
#define BITCOIN_PUBKEY_H

#include <hash.h>
#include <serialize.h>
#include <uint256.h>
#include <ed25519.h>

#include <stdexcept>
#include <vector>
#include <iostream>

/** A reference to a CKey: the Hash160 of its serialized public key */
class CKeyID : public uint160
{
public:
    CKeyID() : uint160() {}
    explicit CKeyID(const uint160& in) : uint160(in) {}
};

typedef uint256 ChainCode;

/** An encapsulated public key. */
class CPubKey
{
public:
    static constexpr unsigned int SIZE                   = 33;
    static constexpr unsigned int SIGNATURE_SIZE          = 64;
    static constexpr unsigned int JOINED_SIGNATURE_SIZE = 64 + 32;

private:

    /**
     * Just store the serialized data.
     * Its length can very cheaply be computed from the first byte.
     */
    unsigned char vch[SIZE];

    //! Compute the length of a pubkey with a given first byte.
    unsigned int static GetLen(unsigned char chHeader)
    {
        if (chHeader == 0x03)
            return SIZE;
        return 0;
    }

    //! Set this key data to be invalid
    void Invalidate()
    {
        vch[0] = 0xFF;
    }

public:

    bool static ValidSize(const std::vector<unsigned char> &vch) {
      return vch.size() > 0 && GetLen(vch[0]) == vch.size();
    }

    //! Construct an invalid public key.
    CPubKey()
    {
        Invalidate();
    }

    //! Initialize a public key using begin/end iterators to byte data.
    template <typename T>
    void Set(const T pbegin, const T pend)
    {
        int len = pend == pbegin ? 0 : GetLen(pbegin[0]);
        if (len && len == (pend - pbegin))
            memcpy(vch, (unsigned char*)&pbegin[0], len);
        else
            Invalidate();
    }

    template <typename T>
    void Set32(const T pbegin)
    {
        memcpy(&vch[1], (unsigned char*)&pbegin[0], 32);
        vch[0] = 0x03;
    }

    //! Construct a public key using begin/end iterators to byte data.
    template <typename T>
    CPubKey(const T pbegin, const T pend)
    {
        Set(pbegin, pend);
    }

    //! Construct a public key from a byte vector.
    explicit CPubKey(const std::vector<unsigned char>& _vch)
    {
        Set(_vch.begin(), _vch.end());
    }

    //! Simple read-only vector-like interface to the pubkey data.
    unsigned int size() const { return GetLen(vch[0]); }
    const unsigned char* data() const { return vch; }
    const unsigned char* begin() const { return vch; }
    const unsigned char* end() const { return vch + size(); }
    const unsigned char& operator[](unsigned int pos) const { return vch[pos]; }

    //! Comparator implementation.
    friend bool operator==(const CPubKey& a, const CPubKey& b)
    {
        return a.vch[0] == b.vch[0] &&
               memcmp(a.vch, b.vch, a.size()) == 0;
    }
    friend bool operator!=(const CPubKey& a, const CPubKey& b)
    {
        return !(a == b);
    }
    friend bool operator<(const CPubKey& a, const CPubKey& b)
    {
        return memcmp(a.vch, b.vch, a.size()) < 0;
    }

    //! Implement serialization, as if this was a byte vector.
    template <typename Stream>
    void Serialize(Stream& s) const
    {
        unsigned int len = size();
        ::WriteCompactSize(s, len);
        s.write((char*)vch, len);
    }
    template <typename Stream>
    void Unserialize(Stream& s)
    {
        unsigned int len = ::ReadCompactSize(s);
        if (len <= SIZE) {
            s.read((char*)vch, len);
        } else {
            // invalid pubkey, skip available data
            char dummy;
            while (len--)
                s.read(&dummy, 1);
            Invalidate();
        }
    }

    //! Get the KeyID of this public key (hash of its serialization)
    CKeyID GetID() const
    {
        return CKeyID(Hash160(vch, vch + size()));
    }

    //! Get the 256-bit hash of this public key.
    uint256 GetHash() const
    {
        return Hash(vch, vch + size());
    }

    /*
     * Check syntactic correctness.
     *
     * Note that this is consensus critical as CheckSig() calls it!
     */
    bool IsValid() const
    {
        return size() > 0;
    }

    /**
     * Verify a signature (64 bytes).
     * If this public key is not valid, the return value will be false.
     */
    bool Verify(const uint512& hash, const std::vector<unsigned char>& vchSig) const;

    //! Recover a public key from a compact signature.
    bool RecoverCompact(const uint512& hash, const std::vector<unsigned char>& vchSig);
};

class CKey;
class CExtKey;
class CExtPubKey {
private:
    KEYCHAIN_PUBLIC_CTX ctx;
public:
    friend bool operator==(const CExtPubKey &a, const CExtPubKey &b)
    {
        return keychain_public_equals(&a.ctx, &b.ctx);
    }
    //! Replace derivation context
    void Set(KEYCHAIN_PUBLIC_CTX &ctx) {
        this->ctx = ctx;
    }
    void Encode(unsigned char code[BIP32_EXTKEY_SIZE]) const;
    void Decode(const unsigned char code[BIP32_EXTKEY_SIZE]);
    //! Derive new extended key
    bool Derive(CExtPubKey& out, unsigned int nChild) const;
    //! Get current public key
    CPubKey GetPubKey() const;
    //! Build extended private key using our derivation metadata and provided key.
    CExtKey Rebuild(const CKey &key) const;
};

#endif // BITCOIN_PUBKEY_H
