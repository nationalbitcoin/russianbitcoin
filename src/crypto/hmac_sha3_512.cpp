// Copyright (c) 2014-2018 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <crypto/hmac_sha3_512.h>

#include <string.h>

CHMAC_SHA3_512::CHMAC_SHA3_512(const unsigned char* key, size_t keylen)
{
    unsigned char rkey[128];
    if (keylen <= 128) {
        memcpy(rkey, key, keylen);
        memset(rkey + keylen, 0, 128 - keylen);
    } else {
        CSHA3_512().Write(key, keylen).Finalize(rkey);
        memset(rkey + 64, 0, 64);
    }

    for (int n = 0; n < 128; n++)
        rkey[n] ^= 0x5c;
    outer.Write(rkey, 128);

    for (int n = 0; n < 128; n++)
        rkey[n] ^= 0x5c ^ 0x36;
    inner.Write(rkey, 128);
}

void CHMAC_SHA3_512::Finalize(unsigned char hash[OUTPUT_SIZE])
{
    unsigned char temp[OUTPUT_SIZE];
    inner.Finalize(temp);
    outer.Write(temp, 64).Finalize(hash);
}
