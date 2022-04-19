// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2020 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <amount.h>
#include <chain.h>
#include <chainparams.h>
#include <consensus/consensus.h>
#include <consensus/params.h>
#include <consensus/validation.h>
#include <core_io.h>
#include <key_io.h>
#include <miner.h>
#include <net.h>
#include <node/context.h>
#include <policy/fees.h>
#include <poa.h>
#include <rpc/blockchain.h>
#include <rpc/mining.h>
#include <rpc/server.h>
#include <rpc/util.h>
#include <script/descriptor.h>
#include <script/script.h>
#include <script/signingprovider.h>
#include <shutdown.h>
#include <txmempool.h>
#include <univalue.h>
#include <util/fees.h>
#include <util/strencodings.h>
#include <util/string.h>
#include <util/system.h>
#include <util/translation.h>
#include <validation.h>
#include <validationinterface.h>
#include <versionbitsinfo.h>
#include <warnings.h>
#include <miner.h>

#ifdef ENABLE_WALLET
#include <wallet/wallet.h>
#include <wallet/walletdb.h>
#include <wallet/rpcwallet.h>
#endif

#include <memory>
#include <stdint.h>

static bool getScriptFromDescriptor(const std::string& descriptor, CScript& script, std::string& error)
{
    FlatSigningProvider key_provider;
    const auto desc = Parse(descriptor, key_provider, error, /* require_checksum = */ false);
    if (desc) {
        if (desc->IsRange()) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Ranged descriptor not accepted. Maybe pass through deriveaddresses first?");
        }

        FlatSigningProvider provider;
        std::vector<CScript> scripts;
        if (!desc->Expand(0, key_provider, scripts, provider)) {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, strprintf("Cannot derive script without private keys"));
        }

        // Combo descriptors can have 2 or 4 scripts, so we can't just check scripts.size() == 1
        CHECK_NONFATAL(scripts.size() > 0 && scripts.size() <= 4);

        if (scripts.size() == 1) {
            script = scripts.at(0);
        } else if (scripts.size() == 4) {
            // For uncompressed keys, take the 3rd script, since it is p2wpkh
            script = scripts.at(2);
        } else {
            // Else take the 2nd script, since it is p2pkh
            script = scripts.at(1);
        }

        return true;
    } else {
        return false;
    }
}

static RPCHelpMan generateblock()
{
    return RPCHelpMan{"generateblock",
        "\nCreate a proof-of-authority block with a set of ordered transactions immediately (before the RPC call returns)\n",
        {
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR_HEX, "hash", "hash of generated block"},
            }
        },
        RPCExamples{
            "\nGenerate proof-of-authority block\n"
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    CChainParams chainparams(Params());
    ChainstateManager& chainman = EnsureChainman(request.context);
    bool regtestMode = chainparams.MineBlocksOnDemand();

    if (!regtestMode && gArgs.GetBoolArg("-emergencypublishing", false)) {
        NodeContext& node = EnsureNodeContext(request.context);
        if(!node.connman)
            throw JSONRPCError(RPC_CLIENT_P2P_DISABLED, "Error: Peer-to-peer functionality missing or disabled");

        if (node.connman->GetNodeCount(CConnman::CONNECTIONS_ALL) == 0)
            throw JSONRPCError(RPC_CLIENT_NOT_CONNECTED, PACKAGE_NAME " is not connected!");
    }

    const CTxMemPool& mempool = EnsureMemPool(request.context);
    std::shared_ptr<CBlock> pblock = SignAuhority(mempool);

    {
        LOCK(cs_main);

        BlockValidationState state;
        if (!TestBlockValidity(state, chainparams, *pblock, LookupBlockIndex(pblock->hashPrevBlock), false, false)) {
            throw JSONRPCError(RPC_VERIFY_ERROR, strprintf("TestBlockValidity failed: %s", state.ToString()));
        }
    }

    bool new_block = false;
    bool accepted = chainman.ProcessNewBlock(chainparams, pblock, /* fForceProcessing */ true, /* fNewBlock */ &new_block);

    if (!accepted)
        throw JSONRPCError(RPC_VERIFY_ERROR, "generated block is not accepted");

    UniValue obj(UniValue::VOBJ);
    obj.pushKV("hash", pblock->GetHash().GetHex());
    return obj;
},
    };
}

static RPCHelpMan getmininginfo()
{
    return RPCHelpMan{"getmininginfo",
                "\nReturns a json object containing mining-related information.",
                {},
                RPCResult{
                    RPCResult::Type::OBJ, "", "",
                    {
                        {RPCResult::Type::NUM, "blocks", "The current block"},
                        {RPCResult::Type::NUM, "currentblockweight", /* optional */ true, "The block weight of the last assembled block (only present if a block was ever assembled)"},
                        {RPCResult::Type::NUM, "currentblocktx", /* optional */ true, "The number of block transactions of the last assembled block (only present if a block was ever assembled)"},
                        {RPCResult::Type::NUM, "difficulty", "The current difficulty"},
                        {RPCResult::Type::NUM, "networkhashps", "The network hashes per second"},
                        {RPCResult::Type::NUM, "pooledtx", "The size of the mempool"},
                        {RPCResult::Type::STR, "chain", "current network name (main, test, regtest)"},
                        {RPCResult::Type::STR, "warnings", "any network and blockchain warnings"},
                    }},
                RPCExamples{
                    HelpExampleCli("getmininginfo", "")
            + HelpExampleRpc("getmininginfo", "")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    LOCK(cs_main);
    const CTxMemPool& mempool = EnsureMemPool(request.context);

    UniValue obj(UniValue::VOBJ);
    UniValue diff(UniValue::VOBJ);
    UniValue weight(UniValue::VOBJ);

    obj.pushKV("blocks",           (int)::ChainActive().Height());
    if (BlockAssembler::m_last_block_weight) obj.pushKV("currentblockweight", *BlockAssembler::m_last_block_weight);
    if (BlockAssembler::m_last_block_num_txs) obj.pushKV("currentblocktx", *BlockAssembler::m_last_block_num_txs);

    uint64_t nWeight = 0;
    uint64_t lastCoinStakeSearchInterval = 0;
#ifdef ENABLE_WALLET
    std::shared_ptr<CWallet> const wallet = GetWalletForJSONRPCRequest(request);
    CWallet* const pwallet = wallet.get();
    if (pwallet)
    {
        LOCK(pwallet->cs_wallet);
        nWeight = pwallet->GetStakeWeight();
        lastCoinStakeSearchInterval = pwallet->m_last_coin_stake_search_interval;
    }
#endif
    diff.pushKV("proof-of-stake",  (double)GetDifficulty(GetLastBlockIndex(::ChainActive().Tip(), true)));
    diff.pushKV("search-interval", (int)lastCoinStakeSearchInterval);
    obj.pushKV("difficulty",       diff);
    const Consensus::Params& consensusParams = Params().GetConsensus();
    obj.pushKV("blockvalue",    (uint64_t)GetBlockSubsidy(::ChainActive().Height(), consensusParams));
    obj.pushKV("netstakeweight",   GetPoSKernelPS());
    obj.pushKV("errors",           GetWarnings("statusbar").original);
    obj.pushKV("pooledtx",         (uint64_t)mempool.size());
    weight.pushKV("minimum",       (uint64_t)nWeight);
    weight.pushKV("maximum",       (uint64_t)0);
    weight.pushKV("combined",      (uint64_t)nWeight);
    obj.pushKV("stakeweight",      weight);
    obj.pushKV("chain",            Params().NetworkIDString());
    obj.pushKV("warnings",         GetWarnings(false).original);
    return obj;
},
    };
}

static UniValue getstakinginfo(const JSONRPCRequest& request)
{
            RPCHelpMan{"getstakinginfo",
                "\nReturns an object containing staking-related information.",
                {},
                RPCResult{
                    RPCResult::Type::OBJ, "", "",
                    {
                        {RPCResult::Type::BOOL, "enabled", "'true' if staking is enabled"},
                        {RPCResult::Type::BOOL, "staking", "'true' if wallet is currently staking"},
                        {RPCResult::Type::STR,  "errors", "errors"},
                        {RPCResult::Type::NUM,  "pooledtx", "The size of the mempool"},
                        {RPCResult::Type::NUM,  "difficulty", "The current difficulty"},
                        {RPCResult::Type::NUM,  "search-interval", "The size of the mempool"},
                        {RPCResult::Type::NUM,  "weight", "The size of the mempool"},
                        {RPCResult::Type::NUM,  "netstakeweight", "The size of the mempool"},
                        {RPCResult::Type::NUM,  "expectedtime", "The size of the mempool"},
                    }
                },
                RPCExamples{
                    HelpExampleCli("getstakinginfo", "")
            + HelpExampleRpc("getstakinginfo", "")
                },
            }.Check(request);

    LOCK(cs_main);
    const CTxMemPool& mempool = EnsureMemPool(request.context);

    uint64_t nWeight = 0;
    uint64_t lastCoinStakeSearchInterval = 0;
#ifdef ENABLE_WALLET
    std::shared_ptr<CWallet> const wallet = GetWalletForJSONRPCRequest(request);
    CWallet* const pwallet = wallet.get();

    if (pwallet)
    {
        LOCK(pwallet->cs_wallet);
        nWeight = pwallet->GetStakeWeight();
        lastCoinStakeSearchInterval = pwallet->m_enabled_staking ? pwallet->m_last_coin_stake_search_interval : 0;
    }
#endif

    uint64_t nNetworkWeight = GetPoSKernelPS();
    bool staking = lastCoinStakeSearchInterval && nWeight;
    const Consensus::Params& consensusParams = Params().GetConsensus();
    int64_t nTargetSpacing = consensusParams.nTargetSpacing;
    uint64_t nExpectedTime = staking ? (nTargetSpacing * nNetworkWeight / nWeight) : 0;

    UniValue obj(UniValue::VOBJ);

    obj.pushKV("enabled", gArgs.GetBoolArg("-staking", true));
    obj.pushKV("staking", staking);
    obj.pushKV("errors", GetWarnings("statusbar").original);

    if (BlockAssembler::m_last_block_num_txs) obj.pushKV("currentblocktx", *BlockAssembler::m_last_block_num_txs);
    obj.pushKV("pooledtx", (uint64_t)mempool.size());

    obj.pushKV("difficulty", GetDifficulty(GetLastBlockIndex(pindexBestHeader, true)));
    obj.pushKV("search-interval", (int)lastCoinStakeSearchInterval);

    obj.pushKV("weight", (uint64_t)nWeight);
    obj.pushKV("netstakeweight", (uint64_t)nNetworkWeight);

    obj.pushKV("expectedtime", nExpectedTime);

    return obj;
}

static UniValue getstakingstatus(const JSONRPCRequest& request)
{
            RPCHelpMan{"getstakingstatus",
                "\nReturns an object containing staking status information.",
                {},
                RPCResult{
                    RPCResult::Type::OBJ, "", "",
                    {
                        {RPCResult::Type::BOOL, "enabled", "'true' if staking is enabled"},
                        {RPCResult::Type::BOOL, "staking", "'true' if wallet is currently staking"},
                        {RPCResult::Type::BOOL, "walletstakingenabled", "'true' if wallet is has staking enabled"},
                        {RPCResult::Type::NUM,  "stakesearchinterval", "last coin stake interval"},
                        {RPCResult::Type::BOOL, "walletunlocked", "'true' if wallet is unlocked"},
                        {RPCResult::Type::BOOL, "nodeconnections", "'true' if wallet is online (has connections)"},
                        {RPCResult::Type::BOOL, "nodesynced", "'true' if wallet is synced"},
                        {RPCResult::Type::BOOL, "stakeablecoins", "'true' if there are stakeable coins"},
                        {RPCResult::Type::STR,  "errors", "errors"},
                    }
                },
                RPCExamples{
                    HelpExampleCli("getstakingstatus", "")
            + HelpExampleRpc("getstakingstatus", "")
                },
            }.Check(request);

    LOCK(cs_main);

    NodeContext& node = EnsureNodeContext(request.context);
    if(!node.connman)
        throw JSONRPCError(RPC_CLIENT_P2P_DISABLED, "Error: Peer-to-peer functionality missing or disabled");

    uint64_t nWeight = 0;
    uint64_t lastCoinStakeSearchInterval = 0;
    bool isUnlocked = false;
    bool walletStakingEnabled = false;
#ifdef ENABLE_WALLET
    std::shared_ptr<CWallet> const wallet = GetWalletForJSONRPCRequest(request);
    CWallet* const pwallet = wallet.get();

    if (pwallet)
    {
        LOCK(pwallet->cs_wallet);
        nWeight = pwallet->GetStakeWeight();
        lastCoinStakeSearchInterval = pwallet->m_last_coin_stake_search_interval;
        isUnlocked = !pwallet->IsLocked();
        walletStakingEnabled = pwallet->m_enabled_staking;
    }
#endif

    bool staking = walletStakingEnabled && lastCoinStakeSearchInterval && nWeight;
    bool hasConnections = node.connman->GetNodeCount(CConnman::CONNECTIONS_ALL) >= 4;
    bool isSynced = !::ChainstateActive().IsInitialBlockDownload();
    bool hasCoins = nWeight != 0;

    UniValue obj(UniValue::VOBJ);

    obj.pushKV("enabled", gArgs.GetBoolArg("-staking", true));
    obj.pushKV("staking", staking);
    obj.pushKV("walletstakingenabled", walletStakingEnabled);
    obj.pushKV("stakesearchinterval", lastCoinStakeSearchInterval);
    obj.pushKV("walletunlocked", isUnlocked);
    obj.pushKV("nodeconnections", hasConnections);
    obj.pushKV("nodesynced", isSynced);
    obj.pushKV("stakeablecoins", hasCoins);
    obj.pushKV("errors", GetWarnings("statusbar").original);

    return obj;
}

// NOTE: Unlike wallet RPC (which use BTC values), mining RPCs follow GBT (BIP 22) in using satoshi amounts
static RPCHelpMan prioritisetransaction()
{
    return RPCHelpMan{"prioritisetransaction",
                "Accepts the transaction into mined blocks at a higher (or lower) priority\n",
                {
                    {"txid", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The transaction id."},
                    {"dummy", RPCArg::Type::NUM, RPCArg::Optional::OMITTED_NAMED_ARG, "API-Compatibility for previous API. Must be zero or null.\n"
            "                  DEPRECATED. For forward compatibility use named arguments and omit this parameter."},
                    {"fee_delta", RPCArg::Type::NUM, RPCArg::Optional::NO, "The fee value (in satoshis) to add (or subtract, if negative).\n"
            "                  Note, that this value is not a fee rate. It is a value to modify absolute fee of the TX.\n"
            "                  The fee is not actually paid, only the algorithm for selecting transactions into a block\n"
            "                  considers the transaction as it would have paid a higher (or lower) fee."},
                },
                RPCResult{
                    RPCResult::Type::BOOL, "", "Returns true"},
                RPCExamples{
                    HelpExampleCli("prioritisetransaction", "\"txid\" 0.0 10000")
            + HelpExampleRpc("prioritisetransaction", "\"txid\", 0.0, 10000")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    LOCK(cs_main);

    uint256 hash(ParseHashV(request.params[0], "txid"));
    CAmount nAmount = request.params[2].get_int64();

    if (!(request.params[1].isNull() || request.params[1].get_real() == 0)) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Priority is no longer supported, dummy argument to prioritisetransaction must be 0.");
    }

    EnsureMemPool(request.context).PrioritiseTransaction(hash, nAmount);
    return true;
},
    };
}

// NOTE: Assumes a conclusive result; if result is inconclusive, it must be handled by caller
static UniValue BIP22ValidationResult(const BlockValidationState& state)
{
    if (state.IsValid())
        return NullUniValue;

    if (state.IsError())
        throw JSONRPCError(RPC_VERIFY_ERROR, state.ToString());
    if (state.IsInvalid())
    {
        std::string strRejectReason = state.GetRejectReason();
        if (strRejectReason.empty())
            return "rejected";
        return strRejectReason;
    }
    // Should be impossible
    return "valid?";
}

class submitblock_StateCatcher final : public CValidationInterface
{
public:
    uint256 hash;
    bool found;
    BlockValidationState state;

    explicit submitblock_StateCatcher(const uint256 &hashIn) : hash(hashIn), found(false), state() {}

protected:
    void BlockChecked(const CBlock& block, const BlockValidationState& stateIn) override {
        if (block.GetHash() != hash)
            return;
        found = true;
        state = stateIn;
    }
};

static RPCHelpMan submitblock()
{
    // We allow 2 arguments for compliance with BIP22. Argument 2 is ignored.
    return RPCHelpMan{"submitblock",
                "\nAttempts to submit new proof-of-authority block to network.\n",
                {
                    {"hexdata", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "the hex-encoded block data to submit"},
                    {"suffix", RPCArg::Type::NUM, /* default */ "0", "Insert block header suffix before decoding."},
                },
                RPCResult{RPCResult::Type::NONE, "", "Returns JSON Null when valid, a string according to BIP22 otherwise"},
                RPCExamples{
                    HelpExampleCli("submitblock", "\"mydata\"")
            + HelpExampleRpc("submitblock", "\"mydata\"")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    std::shared_ptr<CBlock> blockptr = std::make_shared<CBlock>();
    CBlock& block = *blockptr;

    // Original block data
    std::string hexData = request.params[0].get_str();

    if (!request.params[1].isNull()) {
        // Add suffix: zero txhash, 2^32 nout and empty signature
        hexData.insert(160, std::string("0000000000000000000000000000000000000000000000000000000000000000ffffffff00"));
    }

    if (!DecodeHexBlk(block, hexData)) {
        throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "Block decode failed");
    }
    if (block.vtx.empty() || !block.vtx[0]->IsCoinBase()) {
        throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "Block does not start with a coinbase");
    }

    // Try to sign block if unsigned
    if (block.vchBlockSig.empty()) {
        SignAuthority(block);
    }

    uint256 hash = block.GetHash();
    {
        LOCK(cs_main);
        const CBlockIndex* pindex = LookupBlockIndex(hash);
        if (pindex) {
            if (pindex->IsValid(BLOCK_VALID_SCRIPTS)) {
                return "duplicate";
            }
            if (pindex->nStatus & BLOCK_FAILED_MASK) {
                return "duplicate-invalid";
            }
        }
    }

    {
        LOCK(cs_main);
        const CBlockIndex* pindex = LookupBlockIndex(block.hashPrevBlock);
        if (pindex) {
            UpdateUncommittedBlockStructures(block, pindex, Params().GetConsensus());
        }
    }

    bool new_block;
    auto sc = std::make_shared<submitblock_StateCatcher>(block.GetHash());
    RegisterSharedValidationInterface(sc);
    bool accepted = EnsureChainman(request.context).ProcessNewBlock(Params(), blockptr, /* fForceProcessing */ true, /* fNewBlock */ &new_block);
    UnregisterSharedValidationInterface(sc);
    if (!new_block && accepted) {
        return "duplicate";
    }
    if (!sc->found) {
        return "inconclusive";
    }
    return BIP22ValidationResult(sc->state);
},
    };
}

static RPCHelpMan estimatesmartfee()
{
    return RPCHelpMan{"estimatesmartfee",
                "\nEstimates the approximate fee per kilobyte needed for a transaction to begin\n"
                "confirmation within conf_target blocks if possible and return the number of blocks\n"
                "for which the estimate is valid. Uses virtual transaction size as defined\n"
                "in BIP 141 (witness data is discounted).\n",
                {
                    {"conf_target", RPCArg::Type::NUM, RPCArg::Optional::NO, "Confirmation target in blocks (1 - 1008)"},
                    {"estimate_mode", RPCArg::Type::STR, /* default */ "CONSERVATIVE", "The fee estimate mode.\n"
            "                   Whether to return a more conservative estimate which also satisfies\n"
            "                   a longer history. A conservative estimate potentially returns a\n"
            "                   higher feerate and is more likely to be sufficient for the desired\n"
            "                   target, but is not as responsive to short term drops in the\n"
            "                   prevailing fee market.  Must be one of:\n"
            "       \"UNSET\"\n"
            "       \"ECONOMICAL\"\n"
            "       \"CONSERVATIVE\""},
                },
                RPCResult{
                    RPCResult::Type::OBJ, "", "",
                    {
                        {RPCResult::Type::NUM, "feerate", /* optional */ true, "estimate fee rate in " + CURRENCY_UNIT + "/kB (only present if no errors were encountered)"},
                        {RPCResult::Type::ARR, "errors", /* optional */ true, "Errors encountered during processing (if there are any)",
                            {
                                {RPCResult::Type::STR, "", "error"},
                            }},
                        {RPCResult::Type::NUM, "blocks", "block number where estimate was found\n"
            "The request target will be clamped between 2 and the highest target\n"
            "fee estimation is able to return based on how long it has been running.\n"
            "An error is returned if not enough transactions and blocks\n"
            "have been observed to make an estimate for any number of blocks."},
                    }},
                RPCExamples{
                    HelpExampleCli("estimatesmartfee", "6")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    RPCTypeCheck(request.params, {UniValue::VNUM, UniValue::VSTR});
    RPCTypeCheckArgument(request.params[0], UniValue::VNUM);
    unsigned int max_target = ::feeEstimator.HighestTargetTracked(FeeEstimateHorizon::LONG_HALFLIFE);
    unsigned int conf_target = ParseConfirmTarget(request.params[0], max_target);
    bool conservative = true;
    if (!request.params[1].isNull()) {
        FeeEstimateMode fee_mode;
        if (!FeeModeFromString(request.params[1].get_str(), fee_mode)) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, InvalidEstimateModeErrorMessage());
        }
        if (fee_mode == FeeEstimateMode::ECONOMICAL) conservative = false;
    }

    UniValue result(UniValue::VOBJ);
    UniValue errors(UniValue::VARR);
    FeeCalculation feeCalc;
    CFeeRate feeRate = ::feeEstimator.estimateSmartFee(conf_target, &feeCalc, conservative);
    if (feeRate != CFeeRate(0)) {
        result.pushKV("feerate", ValueFromAmount(feeRate.GetFeePerK()));
    } else {
        errors.push_back("Insufficient data or no feerate found");
        result.pushKV("errors", errors);
    }
    result.pushKV("blocks", feeCalc.returnedTarget);
    return result;
},
    };
}

static RPCHelpMan estimaterawfee()
{
    return RPCHelpMan{"estimaterawfee",
                "\nWARNING: This interface is unstable and may disappear or change!\n"
                "\nWARNING: This is an advanced API call that is tightly coupled to the specific\n"
                "         implementation of fee estimation. The parameters it can be called with\n"
                "         and the results it returns will change if the internal implementation changes.\n"
                "\nEstimates the approximate fee per kilobyte needed for a transaction to begin\n"
                "confirmation within conf_target blocks if possible. Uses virtual transaction size as\n"
                "defined in BIP 141 (witness data is discounted).\n",
                {
                    {"conf_target", RPCArg::Type::NUM, RPCArg::Optional::NO, "Confirmation target in blocks (1 - 1008)"},
                    {"threshold", RPCArg::Type::NUM, /* default */ "0.95", "The proportion of transactions in a given feerate range that must have been\n"
            "               confirmed within conf_target in order to consider those feerates as high enough and proceed to check\n"
            "               lower buckets."},
                },
                RPCResult{
                    RPCResult::Type::OBJ, "", "Results are returned for any horizon which tracks blocks up to the confirmation target",
                    {
                        {RPCResult::Type::OBJ, "short", /* optional */ true, "estimate for short time horizon",
                            {
                                {RPCResult::Type::NUM, "feerate", /* optional */ true, "estimate fee rate in " + CURRENCY_UNIT + "/kB"},
                                {RPCResult::Type::NUM, "decay", "exponential decay (per block) for historical moving average of confirmation data"},
                                {RPCResult::Type::NUM, "scale", "The resolution of confirmation targets at this time horizon"},
                                {RPCResult::Type::OBJ, "pass", /* optional */ true, "information about the lowest range of feerates to succeed in meeting the threshold",
                                {
                                        {RPCResult::Type::NUM, "startrange", "start of feerate range"},
                                        {RPCResult::Type::NUM, "endrange", "end of feerate range"},
                                        {RPCResult::Type::NUM, "withintarget", "number of txs over history horizon in the feerate range that were confirmed within target"},
                                        {RPCResult::Type::NUM, "totalconfirmed", "number of txs over history horizon in the feerate range that were confirmed at any point"},
                                        {RPCResult::Type::NUM, "inmempool", "current number of txs in mempool in the feerate range unconfirmed for at least target blocks"},
                                        {RPCResult::Type::NUM, "leftmempool", "number of txs over history horizon in the feerate range that left mempool unconfirmed after target"},
                                }},
                                {RPCResult::Type::OBJ, "fail", /* optional */ true, "information about the highest range of feerates to fail to meet the threshold",
                                {
                                    {RPCResult::Type::ELISION, "", ""},
                                }},
                                {RPCResult::Type::ARR, "errors", /* optional */ true, "Errors encountered during processing (if there are any)",
                                {
                                    {RPCResult::Type::STR, "error", ""},
                                }},
                        }},
                        {RPCResult::Type::OBJ, "medium", /* optional */ true, "estimate for medium time horizon",
                        {
                            {RPCResult::Type::ELISION, "", ""},
                        }},
                        {RPCResult::Type::OBJ, "long", /* optional */ true, "estimate for long time horizon",
                        {
                            {RPCResult::Type::ELISION, "", ""},
                        }},
                    }},
                RPCExamples{
                    HelpExampleCli("estimaterawfee", "6 0.9")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    RPCTypeCheck(request.params, {UniValue::VNUM, UniValue::VNUM}, true);
    RPCTypeCheckArgument(request.params[0], UniValue::VNUM);
    unsigned int max_target = ::feeEstimator.HighestTargetTracked(FeeEstimateHorizon::LONG_HALFLIFE);
    unsigned int conf_target = ParseConfirmTarget(request.params[0], max_target);
    double threshold = 0.95;
    if (!request.params[1].isNull()) {
        threshold = request.params[1].get_real();
    }
    if (threshold < 0 || threshold > 1) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid threshold");
    }

    UniValue result(UniValue::VOBJ);

    for (const FeeEstimateHorizon horizon : {FeeEstimateHorizon::SHORT_HALFLIFE, FeeEstimateHorizon::MED_HALFLIFE, FeeEstimateHorizon::LONG_HALFLIFE}) {
        CFeeRate feeRate;
        EstimationResult buckets;

        // Only output results for horizons which track the target
        if (conf_target > ::feeEstimator.HighestTargetTracked(horizon)) continue;

        feeRate = ::feeEstimator.estimateRawFee(conf_target, threshold, horizon, &buckets);
        UniValue horizon_result(UniValue::VOBJ);
        UniValue errors(UniValue::VARR);
        UniValue passbucket(UniValue::VOBJ);
        passbucket.pushKV("startrange", round(buckets.pass.start));
        passbucket.pushKV("endrange", round(buckets.pass.end));
        passbucket.pushKV("withintarget", round(buckets.pass.withinTarget * 100.0) / 100.0);
        passbucket.pushKV("totalconfirmed", round(buckets.pass.totalConfirmed * 100.0) / 100.0);
        passbucket.pushKV("inmempool", round(buckets.pass.inMempool * 100.0) / 100.0);
        passbucket.pushKV("leftmempool", round(buckets.pass.leftMempool * 100.0) / 100.0);
        UniValue failbucket(UniValue::VOBJ);
        failbucket.pushKV("startrange", round(buckets.fail.start));
        failbucket.pushKV("endrange", round(buckets.fail.end));
        failbucket.pushKV("withintarget", round(buckets.fail.withinTarget * 100.0) / 100.0);
        failbucket.pushKV("totalconfirmed", round(buckets.fail.totalConfirmed * 100.0) / 100.0);
        failbucket.pushKV("inmempool", round(buckets.fail.inMempool * 100.0) / 100.0);
        failbucket.pushKV("leftmempool", round(buckets.fail.leftMempool * 100.0) / 100.0);

        // CFeeRate(0) is used to indicate error as a return value from estimateRawFee
        if (feeRate != CFeeRate(0)) {
            horizon_result.pushKV("feerate", ValueFromAmount(feeRate.GetFeePerK()));
            horizon_result.pushKV("decay", buckets.decay);
            horizon_result.pushKV("scale", (int)buckets.scale);
            horizon_result.pushKV("pass", passbucket);
            // buckets.fail.start == -1 indicates that all buckets passed, there is no fail bucket to output
            if (buckets.fail.start != -1) horizon_result.pushKV("fail", failbucket);
        } else {
            // Output only information that is still meaningful in the event of error
            horizon_result.pushKV("decay", buckets.decay);
            horizon_result.pushKV("scale", (int)buckets.scale);
            horizon_result.pushKV("fail", failbucket);
            errors.push_back("Insufficient data or no feerate found which meets threshold");
            horizon_result.pushKV("errors",errors);
        }
        result.pushKV(StringForFeeEstimateHorizon(horizon), horizon_result);
    }
    return result;
},
    };
}

void RegisterMiningRPCCommands(CRPCTable &t)
{
// clang-format off
static const CRPCCommand commands[] =
{ //  category              name                      actor (function)         argNames
  //  --------------------- ------------------------  -----------------------  ----------
    { "mining",             "getmininginfo",          &getmininginfo,          {} },
    { "mining",             "prioritisetransaction",  &prioritisetransaction,  {"txid","dummy","fee_delta"} },
    { "mining",             "submitblock",            &submitblock,            {"hexdata","suffix"} },

    { "mining",             "getstakinginfo",         &getstakinginfo,         {} },
    { "mining",             "getstakingstatus",       &getstakingstatus,       {} },

    { "generating",         "generateblock",          &generateblock,          {} },

    { "util",               "estimatesmartfee",       &estimatesmartfee,       {"conf_target", "estimate_mode"} },

    { "hidden",             "estimaterawfee",         &estimaterawfee,         {"conf_target", "threshold"} },
};
// clang-format on
    for (const auto& c : commands) {
        t.appendCommand(c.name, &c);
    }
}
