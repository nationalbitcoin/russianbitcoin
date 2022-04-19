// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2018 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_POA_H
#define BITCOIN_POA_H

#include <consensus/params.h>

#include <stdint.h>

class CBlockHeader;
class CBlockIndex;
class uint256;

// The target spacing used up to the synchronization block
static const int64_t STAKE_V1_TARGET_SPACING = 15;

const CBlockIndex* GetLastBlockIndex(const CBlockIndex* pindex, bool fProofOfStake);
unsigned int GetNextBitsRequired(const CBlockIndex* pindexLast, const CBlockHeader *pblock, const Consensus::Params&);
unsigned int CalculateNextBitsRequired(const CBlockIndex* pindexLast, int64_t nFirstBlockTime, const Consensus::Params&);

/** Check whether a block hash satisfies the proof-of-authority requirement */
bool CheckProofOfAuthority(const CBlockHeader& header, const Consensus::Params&);

#endif // BITCOIN_POA_H
