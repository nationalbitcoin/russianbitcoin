// Copyright (c) 2014-2019 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "ripemd160.h"

////// RIPEMD160 wrapper

CRIPEMD160::CRIPEMD160()
{
    ripemd160_Init(&ctx);
}

CRIPEMD160& CRIPEMD160::Write(const unsigned char* data, size_t len)
{
    ripemd160_Update(&ctx, data, len);
    return *this;
}

void CRIPEMD160::Finalize(unsigned char hash[OUTPUT_SIZE])
{
    ripemd160_Final(&ctx, hash);
}

CRIPEMD160& CRIPEMD160::Reset()
{
    ripemd160_Init(&ctx);
    return *this;
}
