// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2018 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <protocol.h>

#include <util/system.h>
#include <util/strencodings.h>

#ifndef WIN32
# include <arpa/inet.h>
#endif

static std::atomic<bool> g_initial_block_download_completed(false);

namespace NetMsgType {
const char *VERSION="version";
const char *VERACK="verack";
const char *ADDR="addr";
const char *INV="inv";
const char *GETDATA="getdata";
const char *MERKLEBLOCK="merkleblock";
const char *GETBLOCKS="getblocks";
const char *GETHEADERS="getheaders";
const char *TX="tx";
const char *HEADERS="headers";
const char *BLOCK="block";
const char *GETADDR="getaddr";
const char *MEMPOOL="mempool";
const char *PING="ping";
const char *PONG="pong";
const char *NOTFOUND="notfound";
const char *FILTERLOAD="filterload";
const char *FILTERADD="filteradd";
const char *FILTERCLEAR="filterclear";
const char *REJECT="reject";
const char *SENDHEADERS="sendheaders";
const char *FEEFILTER="feefilter";
const char *SENDCMPCT="sendcmpct";
const char *CMPCTBLOCK="cmpctblock";
const char *GETBLOCKTXN="getblocktxn";
const char *BLOCKTXN="blocktxn";
} // namespace NetMsgType

/** All known message types. Keep this in the same order as the list of
 * messages above and in protocol.h.
 */
const static std::string allNetMessageTypes[] = {
    NetMsgType::VERSION,
    NetMsgType::VERACK,
    NetMsgType::ADDR,
    NetMsgType::INV,
    NetMsgType::GETDATA,
    NetMsgType::MERKLEBLOCK,
    NetMsgType::GETBLOCKS,
    NetMsgType::GETHEADERS,
    NetMsgType::TX,
    NetMsgType::HEADERS,
    NetMsgType::BLOCK,
    NetMsgType::GETADDR,
    NetMsgType::MEMPOOL,
    NetMsgType::PING,
    NetMsgType::PONG,
    NetMsgType::NOTFOUND,
    NetMsgType::FILTERLOAD,
    NetMsgType::FILTERADD,
    NetMsgType::FILTERCLEAR,
    NetMsgType::REJECT,
    NetMsgType::SENDHEADERS,
    NetMsgType::FEEFILTER,
    NetMsgType::SENDCMPCT,
    NetMsgType::CMPCTBLOCK,
    NetMsgType::GETBLOCKTXN,
    NetMsgType::BLOCKTXN,
};
const static std::vector<std::string> allNetMessageTypesVec(allNetMessageTypes, allNetMessageTypes+ARRAYLEN(allNetMessageTypes));

CMessageHeader::CMessageHeader(const MessageStartChars& pchMessageStartIn)
{
    memcpy(pchMessageStart, pchMessageStartIn, MESSAGE_START_SIZE);
    memset(pchCommand, 0, sizeof(pchCommand));
    nMessageSize = -1;
    memset(pchChecksum, 0, CHECKSUM_SIZE);
}

CMessageHeader::CMessageHeader(const MessageStartChars& pchMessageStartIn, const char* pszCommand, unsigned int nMessageSizeIn)
{
    memcpy(pchMessageStart, pchMessageStartIn, MESSAGE_START_SIZE);
    memset(pchCommand, 0, sizeof(pchCommand));
    strncpy(pchCommand, pszCommand, COMMAND_SIZE);
    nMessageSize = nMessageSizeIn;
    memset(pchChecksum, 0, CHECKSUM_SIZE);
}

std::string CMessageHeader::GetCommand() const
{
    return std::string(pchCommand, pchCommand + strnlen(pchCommand, COMMAND_SIZE));
}

bool CMessageHeader::IsValid(const MessageStartChars& pchMessageStartIn) const
{
    // Check start string
    if (memcmp(pchMessageStart, pchMessageStartIn, MESSAGE_START_SIZE) != 0)
        return false;

    // Check the command string for errors
    for (const char* p1 = pchCommand; p1 < pchCommand + COMMAND_SIZE; p1++)
    {
        if (*p1 == 0)
        {
            // Must be all zeros after the first zero
            for (; p1 < pchCommand + COMMAND_SIZE; p1++)
                if (*p1 != 0)
                    return false;
        }
        else if (*p1 < ' ' || *p1 > 0x7E)
            return false;
    }

    // Message size
    if (nMessageSize > MAX_SIZE)
    {
        LogPrintf("CMessageHeader::IsValid(): (%s, %u bytes) nMessageSize > MAX_SIZE\n", GetCommand(), nMessageSize);
        return false;
    }

    return true;
}


ServiceFlags GetDesirableServiceFlags(ServiceFlags services) {
    if ((services & NODE_NETWORK_LIMITED) && g_initial_block_download_completed) {
        return ServiceFlags(NODE_NETWORK_LIMITED | NODE_WITNESS);
    }
    return ServiceFlags(NODE_NETWORK | NODE_WITNESS);
}

void SetServiceFlagsIBDCache(bool state) {
    g_initial_block_download_completed = state;
}


CAddress::CAddress() : CService()
{
    Init();
}

CAddress::CAddress(CService ipIn, ServiceFlags nServicesIn) : CService(ipIn)
{
    Init();
    nServices = nServicesIn;
}

void CAddress::Init()
{
    nServices = NODE_NONE;
    nTime = 100000000;
}

CInv::CInv()
{
    type = 0;
    hash.SetNull();
}

CInv::CInv(int typeIn, const uint256& hashIn) : type(typeIn), hash(hashIn) {}

bool operator<(const CInv& a, const CInv& b)
{
    return (a.type < b.type || (a.type == b.type && a.hash < b.hash));
}

std::string CInv::GetCommand() const
{
    std::string cmd;
    if (type & MSG_WITNESS_FLAG)
        cmd.append("witness-");
    int masked = type & MSG_TYPE_MASK;
    switch (masked)
    {
    case MSG_TX:             return cmd.append(NetMsgType::TX);
    case MSG_BLOCK:          return cmd.append(NetMsgType::BLOCK);
    case MSG_FILTERED_BLOCK: return cmd.append(NetMsgType::MERKLEBLOCK);
    case MSG_CMPCT_BLOCK:    return cmd.append(NetMsgType::CMPCTBLOCK);
    default:
        throw std::out_of_range(strprintf("CInv::GetCommand(): type=%d unknown type", type));
    }
}

std::string CInv::ToString() const
{
    try {
        return strprintf("%s %s", GetCommand(), hash.ToString());
    } catch(const std::out_of_range &) {
        return strprintf("0x%08x %s", type, hash.ToString());
    }
}

const std::vector<std::string> &getAllNetMessageTypes()
{
    return allNetMessageTypesVec;
}


uint8_t GetShortCommandIDFromCommand(const std::string cmd) {
    if (cmd == NetMsgType::ADDR) {
        return NetMsgType::ADDR_SHORT_ID;
    } else if (cmd == NetMsgType::BLOCK) {
        return NetMsgType::BLOCK_SHORT_ID;
    } else if (cmd == NetMsgType::BLOCKTXN) {
        return NetMsgType::BLOCKTXN_SHORT_ID;
    } else if (cmd == NetMsgType::CMPCTBLOCK) {
       return NetMsgType::CMPCTBLOCK_SHORT_ID;;
    } else if (cmd == NetMsgType::FEEFILTER) {
        return NetMsgType::FEEFILTER_SHORT_ID;
    } else if (cmd == NetMsgType::FILTERADD) {
        return NetMsgType::FILTERADD_SHORT_ID;
    } else if (cmd == NetMsgType::FILTERCLEAR) {
       return NetMsgType::FILTERCLEAR_SHORT_ID;;
    } else if (cmd == NetMsgType::FILTERLOAD) {
        return NetMsgType::FILTERLOAD_SHORT_ID;
    } else if (cmd == NetMsgType::GETADDR) {
        return NetMsgType::GETADDR_SHORT_ID;
    } else if (cmd == NetMsgType::GETBLOCKS) {
       return NetMsgType::GETBLOCKS_SHORT_ID;;
    } else if (cmd == NetMsgType::GETBLOCKTXN) {
        return NetMsgType::GETBLOCKTXN_SHORT_ID;
    } else if (cmd == NetMsgType::GETDATA) {
        return NetMsgType::GETDATA_SHORT_ID;
    } else if (cmd == NetMsgType::GETHEADERS) {
       return NetMsgType::GETHEADERS_SHORT_ID;;
    } else if (cmd == NetMsgType::HEADERS) {
        return NetMsgType::HEADERS_SHORT_ID;
    } else if (cmd == NetMsgType::INV) {
        return NetMsgType::INV_SHORT_ID;
    } else if (cmd == NetMsgType::MEMPOOL) {
       return NetMsgType::MEMPOOL_SHORT_ID;;
    } else if (cmd == NetMsgType::MERKLEBLOCK) {
        return NetMsgType::MERKLEBLOCK_SHORT_ID;
    } else if (cmd == NetMsgType::NOTFOUND) {
        return NetMsgType::NOTFOUND_SHORT_ID;
    } else if (cmd == NetMsgType::PING) {
       return NetMsgType::PING_SHORT_ID;;
    } else if (cmd == NetMsgType::PONG) {
        return NetMsgType::PONG_SHORT_ID;
    } else if (cmd == NetMsgType::REJECT) {
        return NetMsgType::REJECT_SHORT_ID;
    } else if (cmd == NetMsgType::SENDCMPCT) {
       return NetMsgType::SENDCMPCT_SHORT_ID;;
    } else if (cmd == NetMsgType::SENDHEADERS) {
       return NetMsgType::SENDHEADERS_SHORT_ID;;
    } else if (cmd == NetMsgType::TX) {
        return NetMsgType::TX_SHORT_ID;
    } else if (cmd == NetMsgType::VERACK) {
        return NetMsgType::VERACK_SHORT_ID;
    } else if (cmd == NetMsgType::VERSION) {
       return NetMsgType::VERSION_SHORT_ID;;
    }
    return 0; //no short command
}

bool GetCommandFromShortCommandID(uint8_t shortID, std::string& cmd) {
    if (shortID == NetMsgType::ADDR_SHORT_ID) {
        cmd = NetMsgType::ADDR;
    } else if (shortID == NetMsgType::BLOCK_SHORT_ID) {
        cmd = NetMsgType::BLOCK;
    } else if (shortID == NetMsgType::BLOCKTXN_SHORT_ID) {
        cmd = NetMsgType::BLOCKTXN;
    } else if (shortID == NetMsgType::CMPCTBLOCK_SHORT_ID) {
       cmd = NetMsgType::CMPCTBLOCK;
    } else if (shortID == NetMsgType::FEEFILTER_SHORT_ID) {
        cmd = NetMsgType::FEEFILTER;
    } else if (shortID == NetMsgType::FILTERADD_SHORT_ID) {
        cmd = NetMsgType::FILTERADD;
    } else if (shortID == NetMsgType::FILTERCLEAR_SHORT_ID) {
       cmd = NetMsgType::FILTERCLEAR;
    } else if (shortID == NetMsgType::FILTERLOAD_SHORT_ID) {
        cmd = NetMsgType::FILTERLOAD;
    } else if (shortID == NetMsgType::GETADDR_SHORT_ID) {
        cmd = NetMsgType::GETADDR;
    } else if (shortID == NetMsgType::GETBLOCKS_SHORT_ID) {
       cmd = NetMsgType::GETBLOCKS;
    } else if (shortID == NetMsgType::GETBLOCKTXN_SHORT_ID) {
        cmd = NetMsgType::GETBLOCKTXN;
    } else if (shortID == NetMsgType::GETDATA_SHORT_ID) {
        cmd = NetMsgType::GETDATA;
    } else if (shortID == NetMsgType::GETHEADERS_SHORT_ID) {
       cmd = NetMsgType::GETHEADERS;
    } else if (shortID == NetMsgType::HEADERS_SHORT_ID) {
        cmd = NetMsgType::HEADERS;
    } else if (shortID == NetMsgType::INV_SHORT_ID) {
        cmd = NetMsgType::INV;
    } else if (shortID == NetMsgType::MEMPOOL_SHORT_ID) {
       cmd = NetMsgType::MEMPOOL;
    } else if (shortID == NetMsgType::MERKLEBLOCK_SHORT_ID) {
        cmd = NetMsgType::MERKLEBLOCK;
    } else if (shortID == NetMsgType::NOTFOUND_SHORT_ID) {
        cmd = NetMsgType::NOTFOUND;
    } else if (shortID == NetMsgType::PING_SHORT_ID) {
       cmd = NetMsgType::PING;
    } else if (shortID == NetMsgType::PONG_SHORT_ID) {
       cmd = NetMsgType::PONG;
    } else if (shortID == NetMsgType::REJECT_SHORT_ID) {
        cmd = NetMsgType::REJECT;
    } else if (shortID == NetMsgType::SENDCMPCT_SHORT_ID) {
        cmd = NetMsgType::SENDCMPCT;
    } else if (shortID == NetMsgType::SENDHEADERS_SHORT_ID) {
       cmd = NetMsgType::SENDHEADERS;
    } else if (shortID == NetMsgType::TX_SHORT_ID) {
        cmd = NetMsgType::TX;
    } else if (shortID == NetMsgType::VERACK_SHORT_ID) {
        cmd = NetMsgType::VERACK;
    } else if (shortID == NetMsgType::VERSION_SHORT_ID) {
       cmd = NetMsgType::VERSION;
    } else {
        return false; //ID not found
    }
    return true;
}
