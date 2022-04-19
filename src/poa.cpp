// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2018 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <poa.h>

#include <arith_uint256.h>
#include <chain.h>
#include <primitives/block.h>
#include <uint256.h>

namespace {
    // returns a * exp(p/q) where |p/q| is small
    arith_uint256 mul_exp(arith_uint256 a, int64_t p, int64_t q)
    {
        bool isNegative = p < 0;
        uint64_t abs_p = p >= 0 ? p : -p;
        arith_uint256 result = a;
        uint64_t n = 0;
        while (a > 0) {
            ++n;
            a = a * abs_p / q / n;
            if (isNegative && (n % 2 == 1)) {
                result -= a;
            } else {
                result += a;
            }
        }
        return result;
    }
}

// ppcoin: find last block index up to pindex
const CBlockIndex* GetLastBlockIndex(const CBlockIndex* pindex, bool fProofOfStake)
{
    //CBlockIndex will be updated with information about the proof type later
    while (pindex && pindex->pprev && (pindex->IsProofOfStake() != fProofOfStake))
        pindex = pindex->pprev;
    return pindex;
}

inline arith_uint256 GetLimit(int nHeight, const Consensus::Params& params)
{
    return UintToArith256(params.posLimit);
}

unsigned int GetNextBitsRequired(const CBlockIndex* pindexLast, const CBlockHeader *pblock, const Consensus::Params& params)
{
    unsigned int nTargetLimit = GetLimit(pindexLast ? pindexLast->nHeight+1 : 0, params).GetCompact();

    // genesis block
    if (pindexLast == NULL)
        return nTargetLimit;

    // first block
    const CBlockIndex* pindexPrev = GetLastBlockIndex(pindexLast, true);
    if (pindexPrev->pprev == NULL)
        return nTargetLimit;

    // second block
    const CBlockIndex* pindexPrevPrev = GetLastBlockIndex(pindexPrev->pprev, true);
    if (pindexPrevPrev->pprev == NULL)
        return nTargetLimit;

    return CalculateNextBitsRequired(pindexPrev, pindexPrevPrev->GetBlockTime(), params);
}

unsigned int CalculateNextBitsRequired(const CBlockIndex* pindexLast, int64_t nFirstBlockTime, const Consensus::Params& params)
{
    if (params.fPoSNoRetargeting)
        return pindexLast->nBits;

    // Limit adjustment step
    int64_t nTargetSpacing = params.nTargetSpacing;
    int64_t nActualSpacing = pindexLast->GetBlockTime() - nFirstBlockTime;
    int64_t nInterval = params.nTargetTimespan;

    // Retarget
    const arith_uint256 bnTargetLimit = GetLimit(pindexLast->nHeight + 1, params);
    arith_uint256 bnNew;
    bnNew.SetCompact(pindexLast->nBits);

    if (nActualSpacing < 0)
        nActualSpacing = nTargetSpacing;
    if (nActualSpacing > nTargetSpacing * 20)
        nActualSpacing = nTargetSpacing * 20;
    bnNew = mul_exp(bnNew, 2 * (nActualSpacing - nTargetSpacing) / 16, (nInterval + 1) * nTargetSpacing / 16);

    if (bnNew <= 0 || bnNew > bnTargetLimit)
        bnNew = bnTargetLimit;

    return bnNew.GetCompact();
}

bool CheckProofOfAuthority(const CBlockHeader& header, const Consensus::Params& params)
{
    // Always true for genesis block
    if (header.GetHash() == params.hashGenesisBlock)
        return true;

    // Combined signature length is deterministic
    if (header.vchBlockSig.size() != CPubKey::JOINED_SIGNATURE_SIZE)
        return false;

    CPubKey pk;
    if (!pk.RecoverCompact(header.GetHashWithoutSign(), header.vchBlockSig))
        return false;

    if (params.authorityID != pk.GetID())
        return false; // Unexpected pubkey

    return true;
}
