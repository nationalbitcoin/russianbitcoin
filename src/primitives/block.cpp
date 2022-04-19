// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2019 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <primitives/block.h>

#include <hash.h>
#include <streams.h>
#include <tinyformat.h>
#include <util/strencodings.h>

uint256 CBlockHeader::GetHash() const
{
    // PoW blocks became PoA blocks retroactively
    bool fullHash = (nVersion != 1 && nNonce == 0);

    // Encode first 80 bytes
    CDataStream ss(SER_GETHASH, 0);
    ss << nVersion << hashPrevBlock << hashMerkleRoot << nTime << nBits << nNonce;

    // Append prevOut and signature
    if (fullHash || IsProofOfStake()) {
        ss << prevoutStake << vchBlockSig;
    }

    return Hash(ss);
}

uint512 CBlockHeader::GetHashWithoutSign() const
{
    return SerializeHash512(*(CBlockHeaderBase*)this, SER_GETHASH);
}

std::string CBlock::ToString() const
{
    std::stringstream s;
    s << strprintf("CBlock(hash=%s, ver=0x%08x, hashPrevBlock=%s, hashMerkleRoot=%s, nTime=%u, nBits=%08x, nNonce=%u, proof=%s, prevoutStake=%s, blockSig=%s, vtx=%u)\n",
        GetHash().ToString(),
        nVersion,
        hashPrevBlock.ToString(),
        hashMerkleRoot.ToString(),
        nTime, nBits, nNonce,
        IsProofOfStake() ? "PoS" : "PoA",
        prevoutStake.ToString(),
        HexStr(vchBlockSig),
        vtx.size());
    for (const auto& tx : vtx) {
        s << "  " << tx->ToString() << "\n";
    }
    return s.str();
}
