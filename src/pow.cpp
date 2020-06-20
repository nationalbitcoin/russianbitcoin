// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2018 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <pow.h>

#include <arith_uint256.h>
#include <chain.h>
#include <primitives/block.h>
#include <uint256.h>

unsigned int GetNextWorkRequired(const CBlockIndex* pindexLast, const Consensus::Params& params)
{
    assert(pindexLast != nullptr);

    if (pindexLast->pprev == nullptr)
        return params.powLimit.GetCompact(); // first block
    if (pindexLast->pprev->pprev == nullptr)
        return params.powLimit.GetCompact(); // second block
    if (params.fPowNoRetargeting)
        return params.powLimit.GetCompact(); // no retargeting on this chain

    // Retarget with exponential moving toward target spacing
    arith_uint256 bnNew;
    bnNew.SetCompact(pindexLast->pprev->nBits);
    int64_t nTargetSpacing = params.nPowTargetSpacing;
    int64_t nInterval = params.nPowTargetTimespan / nTargetSpacing;
    int64_t nActualSpacing = pindexLast->pprev->GetBlockTime() - pindexLast->pprev->pprev->GetBlockTime();
    bnNew *= ((nInterval - 1) * nTargetSpacing + nActualSpacing + nActualSpacing);
    bnNew /= ((nInterval + 1) * nTargetSpacing);

    if (bnNew > params.powLimit)
        bnNew = params.powLimit;

    return bnNew.GetCompact();
}

bool CheckProofOfWork(uint256 hash, unsigned int nBits, const Consensus::Params& params)
{
    // Always true for genesis block
    if (hash == params.hashGenesisBlock)
        return true;

    bool fNegative;
    bool fOverflow;
    arith_uint256 bnTarget;
    bnTarget.SetCompact(nBits, &fNegative, &fOverflow);

    // Check range
    if (fNegative || bnTarget == 0 || fOverflow || bnTarget > params.powLimit)
        return false;

    // Check proof of work matches claimed amount
    if (UintToArith256(hash) > bnTarget)
        return false;

    return true;
}
