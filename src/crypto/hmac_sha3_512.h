// Copyright (c) 2014-2018 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_CRYPTO_HMAC_SHA3_512_H
#define BITCOIN_CRYPTO_HMAC_SHA3_512_H

#include <crypto/sha3-512.h>

#include <stdint.h>
#include <stdlib.h>

/** A hasher class for HMAC-SHA-512. */
class CHMAC_SHA3_512
{
private:
    CSHA3_512 outer;
    CSHA3_512 inner;

public:
    static const size_t OUTPUT_SIZE = CSHA3_512::OUTPUT_SIZE;

    CHMAC_SHA3_512(const unsigned char* key, size_t keylen);
    CHMAC_SHA3_512& Write(const unsigned char* data, size_t len)
    {
        inner.Write(data, len);
        return *this;
    }
    void Finalize(unsigned char hash[OUTPUT_SIZE]);
};

#endif // BITCOIN_CRYPTO_HMAC_SHA3_512_H
