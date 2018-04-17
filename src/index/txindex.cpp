// Copyright (c) 2017 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chainparams.h>
#include <index/txindex.h>
#include <dbwrapper.h>
#include <init.h>
#include <pubkey.h>
#include <script/standard.h>
#include <tinyformat.h>
#include <ui_interface.h>
#include <util.h>
#include <validation.h>
#include <warnings.h>

constexpr int64_t SYNC_LOG_INTERVAL = 30; // seconds

std::unique_ptr<TxIndex> g_txindex;

template<typename... Args>
static void FatalError(const char* fmt, const Args&... args)
{
    std::string strMessage = tfm::format(fmt, args...);
    SetMiscWarning(strMessage);
    LogPrintf("*** %s\n", strMessage);
    uiInterface.ThreadSafeMessageBox(
        "Error: A fatal internal error occurred, see debug.log for details",
        "", CClientUIInterface::MSG_ERROR);
    StartShutdown();
}

TxIndex::TxIndex(std::unique_ptr<TxIndexDB> db) :
    m_db(std::move(db)), m_synced(false), m_best_block_index(nullptr)
{}

TxIndex::~TxIndex()
{
    Interrupt();
    Stop();
}

bool TxIndex::Init()
{
    LOCK(cs_main);

    // Attempt to migrate txindex from the old database to the new one. Even if
    // chain_tip is null, the node could be reindexing and we still want to
    // delete txindex records in the old database.
    if (!m_db->MigrateData(*pblocktree, chainActive.GetLocator())) {
        return false;
    }

    CBlockLocator locator;
    if (!m_db->ReadBestBlock(locator)) {
        FatalError("%s: Failed to read from tx index database", __func__);
        return false;
    }

    m_best_block_index = FindForkInGlobalIndex(chainActive, locator);
    m_synced = m_best_block_index.load() == chainActive.Tip();
    return true;
}

static const CBlockIndex* NextSyncBlock(const CBlockIndex* pindex_prev)
{
    AssertLockHeld(cs_main);

    if (!pindex_prev) {
        return chainActive.Genesis();
    }

    const CBlockIndex* pindex = chainActive.Next(pindex_prev);
    if (pindex) {
        return pindex;
    }

    return chainActive.Next(chainActive.FindFork(pindex_prev));
}

void TxIndex::ThreadSync()
{
    const CBlockIndex* pindex = m_best_block_index.load();
    if (!m_synced) {
        auto& consensus_params = Params().GetConsensus();

        int64_t last_log_time = 0;
        while (true) {
            if (m_interrupt) {
                return;
            }

            {
                LOCK(cs_main);
                const CBlockIndex* pindex_next = NextSyncBlock(pindex);
                if (!pindex_next) {
                    if (!m_db->WriteBestBlock(chainActive.GetLocator())) {
                        error("%s: Failed to write locator to disk", __func__);
                    }
                    m_best_block_index = pindex;
                    m_synced = true;
                    break;
                }
                pindex = pindex_next;
            }

            int64_t current_time = GetTime();
            if (last_log_time + SYNC_LOG_INTERVAL < current_time) {
                LogPrintf("Syncing txindex with block chain from height %d\n", pindex->nHeight);
                last_log_time = current_time;
            }

            CBlock block;
            if (!ReadBlockFromDisk(block, pindex, consensus_params)) {
                FatalError("%s: Failed to read block %s from disk",
                           __func__, pindex->GetBlockHash().ToString());
                return;
            }
            if (!WriteBlock(block, pindex)) {
                FatalError("%s: Failed to write block %s to tx index database",
                           __func__, pindex->GetBlockHash().ToString());
                return;
            }
        }
    }

    if (pindex) {
        LogPrintf("txindex is enabled at height %d\n", pindex->nHeight);
    } else {
        LogPrintf("txindex is enabled\n");
    }
}

bool TxIndex::WriteBlock(const CBlock& block, const CBlockIndex* pindex)
{
    CDiskTxPos pos(pindex->GetBlockPos(), GetSizeOfCompactSize(block.vtx.size()));
    std::vector<std::pair<uint256, CDiskTxPos>> vPos;
    vPos.reserve(block.vtx.size());
    std::vector<std::pair<CTxDestination, uint256>> vAddr;
    for (const auto& tx : block.vtx) {
        vPos.emplace_back(tx->GetHash(), pos);
        pos.nTxOffset += ::GetSerializeSize(*tx, SER_DISK, CLIENT_VERSION);

        for (const CTxOut& out : tx->vout) {
            CTxDestination address;
            if (ExtractDestination(out.scriptPubKey, address)) {
                //const CKeyID *keyID = boost::get<CKeyID>(address);
                vAddr.emplace_back(address, tx->GetHash());
            }
        }
    }

    std::unique_ptr<CDBIterator> pcursor(m_db->NewIterator());
    CDBBatch batch(*m_db);
    for (const auto& tuple : vAddr) {
        if (auto key_id = boost::get<CKeyID>(&tuple.first)) {
            //batch.Write(std::make_pair('a', *key_id), tuple.second);
        }
        if (auto script_id = boost::get<CScriptID>(&tuple.first)) {
            batch.Write(std::make_pair('a', *script_id), tuple.second);

            pcursor->Seek(std::make_pair('a', *script_id));

            while (pcursor->Valid()) {
                boost::this_thread::interruption_point();
                CScriptID key;
                uint256 txid;
                if (pcursor->GetKey(key) && pcursor->GetValue(txid)) {
                    int i = 0;
                }
                pcursor->Next();
            }
        }
    }
    m_db->WriteBatch(batch);

    return m_db->WriteTxs(vPos);
}

void TxIndex::BlockConnected(const std::shared_ptr<const CBlock>& block, const CBlockIndex* pindex,
                    const std::vector<CTransactionRef>& txn_conflicted)
{
    if (!m_synced) {
        return;
    }

    const CBlockIndex* best_block_index = m_best_block_index.load();
    if (!best_block_index) {
        if (pindex->nHeight != 0) {
            FatalError("%s: First block connected is not the genesis block (height=%d)",
                       __func__, pindex->nHeight);
            return;
        }
    } else {
        // Ensure block connects to an ancestor of the current best block. This should be the case
        // most of the time, but may not be immediately after the the sync thread catches up and sets
        // m_synced. Consider the case where there is a reorg and the blocks on the stale branch are
        // in the ValidationInterface queue backlog even after the sync thread has caught up to the
        // new chain tip. In this unlikely event, log a warning and let the queue clear.
        if (best_block_index->GetAncestor(pindex->nHeight - 1) != pindex->pprev) {
            LogPrintf("%s: WARNING: Block %s does not connect to an ancestor of known best chain "
                      "(tip=%s); not updating txindex\n",
                      __func__, pindex->GetBlockHash().ToString(),
                      best_block_index->GetBlockHash().ToString());
            return;
        }
    }

    if (WriteBlock(*block, pindex)) {
        m_best_block_index = pindex;
    } else {
        FatalError("%s: Failed to write block %s to txindex",
                   __func__, pindex->GetBlockHash().ToString());
        return;
    }
}

void TxIndex::SetBestChain(const CBlockLocator& locator)
{
    if (!m_synced) {
        return;
    }

    const uint256& locator_tip_hash = locator.vHave.front();
    const CBlockIndex* locator_tip_index;
    {
        LOCK(cs_main);
        locator_tip_index = LookupBlockIndex(locator_tip_hash);
    }

    if (!locator_tip_index) {
        FatalError("%s: First block (hash=%s) in locator was not found",
                   __func__, locator_tip_hash.ToString());
        return;
    }

    // This checks that SetBestChain callbacks are received after BlockConnected. The check may fail
    // immediately after the the sync thread catches up and sets m_synced. Consider the case where
    // there is a reorg and the blocks on the stale branch are in the ValidationInterface queue
    // backlog even after the sync thread has caught up to the new chain tip. In this unlikely
    // event, log a warning and let the queue clear.
    const CBlockIndex* best_block_index = m_best_block_index.load();
    if (best_block_index->GetAncestor(locator_tip_index->nHeight) != locator_tip_index) {
        LogPrintf("%s: WARNING: Locator contains block (hash=%s) not on known best chain "
                  "(tip=%s); not writing txindex locator\n",
                  __func__, locator_tip_hash.ToString(),
                  best_block_index->GetBlockHash().ToString());
        return;
    }

    if (!m_db->WriteBestBlock(locator)) {
        error("%s: Failed to write locator to disk", __func__);
    }
}

bool TxIndex::BlockUntilSyncedToCurrentChain()
{
    AssertLockNotHeld(cs_main);

    if (!m_synced) {
        return false;
    }

    {
        // Skip the queue-draining stuff if we know we're caught up with
        // chainActive.Tip().
        LOCK(cs_main);
        const CBlockIndex* chain_tip = chainActive.Tip();
        const CBlockIndex* best_block_index = m_best_block_index.load();
        if (best_block_index->GetAncestor(chain_tip->nHeight) == chain_tip) {
            return true;
        }
    }

    LogPrintf("%s: txindex is catching up on block notifications\n", __func__);
    SyncWithValidationInterfaceQueue();
    return true;
}

void TxIndex::PruneUpdateTx(const CBlock& block, int height) const
{
    std::vector<std::pair<uint256, CDiskTxPos>> vPos;
    unsigned int txpos = 0;
    for(const auto& tx : block.vtx)
    {
        CDiskTxPos pos(CDiskBlockPos(std::numeric_limits<int>::max(), height), GetSizeOfCompactSize(txpos++));
        vPos.emplace_back(tx->GetHash(), pos);
    }
    m_db->EraseAndWriteTxs(vPos);
}

GetTransactionResult TxIndex::FindTx(const uint256& tx_hash, uint256& block_hash, CTransactionRef& tx) const
{
    CDiskTxPos postx;
    if (!m_db->ReadTxPos(tx_hash, postx)) {
        return GetTransactionResult::NOT_FOUND;
    }
    if (postx.nFile == std::numeric_limits<int>::max()) {
        // file is pruned
        block_hash = *chainActive[postx.nPos]->phashBlock;
        return GetTransactionResult::BLOCK_PRUNED;
    }

    CAutoFile file(OpenBlockFile(postx, true), SER_DISK, CLIENT_VERSION);
    if (file.IsNull()) {
        error("%s: OpenBlockFile failed", __func__);
        return GetTransactionResult::BLOCK_LOAD_ERROR;
    }
    CBlockHeader header;
    try {
        file >> header;
        fseek(file.Get(), postx.nTxOffset, SEEK_CUR);
        file >> tx;
    } catch (const std::exception& e) {
        error("%s: Deserialize or I/O error - %s", __func__, e.what());
        return GetTransactionResult::BLOCK_LOAD_ERROR;
    }
    if (tx->GetHash() != tx_hash) {
        error("%s: txid mismatch", __func__);
        return GetTransactionResult::BLOCK_LOAD_ERROR;
    }
    block_hash = header.GetHash();
    return GetTransactionResult::LOAD_OK;
}

void TxIndex::Interrupt()
{
    m_interrupt();
}

void TxIndex::Start()
{
    // Need to register this ValidationInterface before running Init(), so that
    // callbacks are not missed if Init sets m_synced to true.
    RegisterValidationInterface(this);
    if (!Init()) {
        return;
    }

    m_thread_sync = std::thread(&TraceThread<std::function<void()>>, "txindex",
                                std::bind(&TxIndex::ThreadSync, this));
}

void TxIndex::Stop()
{
    UnregisterValidationInterface(this);

    if (m_thread_sync.joinable()) {
        m_thread_sync.join();
    }
}
