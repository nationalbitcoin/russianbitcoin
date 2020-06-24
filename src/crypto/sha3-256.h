// Copyright (c) 2014-2019 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_CRYPTO_SHA3_256_H
#define BITCOIN_CRYPTO_SHA3_256_H

#include <stdint.h>
#include <stdlib.h>
#include <ref10/hash/sha3.h>

/** A hasher class for SHA3-256. */
class CSHA3_256
{
private:
    SHA3_CTX ctx;

public:
    static constexpr size_t OUTPUT_SIZE = SHA3_256_DIGEST_LENGTH;

    CSHA3_256();
    CSHA3_256& Write(const unsigned char* data, size_t len);
    void Finalize(unsigned char hash[OUTPUT_SIZE]);
    CSHA3_256& Reset();
};

#endif // BITCOIN_CRYPTO_SHA3_256_H
