// Copyright (c) 2014-2019 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <crypto/sha3-256.h>

#include <crypto/common.h>

#include <string.h>


////// SHA3-256

CSHA3_256::CSHA3_256()
{
    sha3_256_Init(&ctx);
}

CSHA3_256& CSHA3_256::Write(const unsigned char* data, size_t len)
{
    sha3_Update(&ctx, data, len);
    return *this;
}

void CSHA3_256::Finalize(unsigned char hash[SHA3_512_DIGEST_LENGTH])
{
    sha3_Final(&ctx, &hash[0]);
}

CSHA3_256& CSHA3_256::Reset()
{
    sha3_256_Init(&ctx);
    return *this;
}
