// Copyright (c) 2012-2019 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <addrdb.h>
#include <addrman.h>
#include <clientversion.h>
#include <test/setup_common.h>
#include <string>
#include <boost/test/unit_test.hpp>
#include <serialize.h>
#include <streams.h>
#include <net.h>
#include <netbase.h>
#include <netmessagemaker.h>
#include <chainparams.h>
#include <util/memory.h>
#include <util/strencodings.h>
#include <util/system.h>

#include <memory>

class CAddrManSerializationMock : public CAddrMan
{
public:
    virtual void Serialize(CDataStream& s) const = 0;

    //! Ensure that bucket placement is always the same for testing purposes.
    void MakeDeterministic()
    {
        nKey.SetNull();
        insecure_rand = FastRandomContext(true);
    }
};

class CAddrManUncorrupted : public CAddrManSerializationMock
{
public:
    void Serialize(CDataStream& s) const override
    {
        CAddrMan::Serialize(s);
    }
};

class CAddrManCorrupted : public CAddrManSerializationMock
{
public:
    void Serialize(CDataStream& s) const override
    {
        // Produces corrupt output that claims addrman has 20 addrs when it only has one addr.
        unsigned char nVersion = 1;
        s << nVersion;
        s << ((unsigned char)32);
        s << nKey;
        s << 10; // nNew
        s << 10; // nTried

        int nUBuckets = ADDRMAN_NEW_BUCKET_COUNT ^ (1 << 30);
        s << nUBuckets;

        CService serv;
        BOOST_CHECK(Lookup("252.1.1.1", serv, 7777, false));
        CAddress addr = CAddress(serv, NODE_NONE);
        CNetAddr resolved;
        BOOST_CHECK(LookupHost("252.2.2.2", resolved, false));
        CAddrInfo info = CAddrInfo(addr, resolved);
        s << info;
    }
};

static CDataStream AddrmanToStream(CAddrManSerializationMock& _addrman)
{
    CDataStream ssPeersIn(SER_DISK, CLIENT_VERSION);
    ssPeersIn << Params().MessageStart();
    ssPeersIn << _addrman;
    std::string str = ssPeersIn.str();
    std::vector<unsigned char> vchData(str.begin(), str.end());
    return CDataStream(vchData, SER_DISK, CLIENT_VERSION);
}

BOOST_FIXTURE_TEST_SUITE(net_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(cnode_listen_port)
{
    // test default
    unsigned short port = GetListenPort();
    BOOST_CHECK(port == Params().GetDefaultPort());
    // test set port
    unsigned short altPort = 12345;
    BOOST_CHECK(gArgs.SoftSetArg("-port", std::to_string(altPort)));
    port = GetListenPort();
    BOOST_CHECK(port == altPort);
}

BOOST_AUTO_TEST_CASE(caddrdb_read)
{
    CAddrManUncorrupted addrmanUncorrupted;
    addrmanUncorrupted.MakeDeterministic();

    CService addr1, addr2, addr3;
    BOOST_CHECK(Lookup("250.7.1.1", addr1, 8333, false));
    BOOST_CHECK(Lookup("250.7.2.2", addr2, 9999, false));
    BOOST_CHECK(Lookup("250.7.3.3", addr3, 9999, false));

    // Add three addresses to new table.
    CService source;
    BOOST_CHECK(Lookup("252.5.1.1", source, 8333, false));
    BOOST_CHECK(addrmanUncorrupted.Add(CAddress(addr1, NODE_NONE), source));
    BOOST_CHECK(addrmanUncorrupted.Add(CAddress(addr2, NODE_NONE), source));
    BOOST_CHECK(addrmanUncorrupted.Add(CAddress(addr3, NODE_NONE), source));

    // Test that the de-serialization does not throw an exception.
    CDataStream ssPeers1 = AddrmanToStream(addrmanUncorrupted);
    bool exceptionThrown = false;
    CAddrMan addrman1;

    BOOST_CHECK(addrman1.size() == 0);
    try {
        unsigned char pchMsgTmp[4];
        ssPeers1 >> pchMsgTmp;
        ssPeers1 >> addrman1;
    } catch (const std::exception&) {
        exceptionThrown = true;
    }

    BOOST_CHECK(addrman1.size() == 3);
    BOOST_CHECK(exceptionThrown == false);

    // Test that CAddrDB::Read creates an addrman with the correct number of addrs.
    CDataStream ssPeers2 = AddrmanToStream(addrmanUncorrupted);

    CAddrMan addrman2;
    CAddrDB adb;
    BOOST_CHECK(addrman2.size() == 0);
    BOOST_CHECK(adb.Read(addrman2, ssPeers2));
    BOOST_CHECK(addrman2.size() == 3);
}


BOOST_AUTO_TEST_CASE(caddrdb_read_corrupted)
{
    CAddrManCorrupted addrmanCorrupted;
    addrmanCorrupted.MakeDeterministic();

    // Test that the de-serialization of corrupted addrman throws an exception.
    CDataStream ssPeers1 = AddrmanToStream(addrmanCorrupted);
    bool exceptionThrown = false;
    CAddrMan addrman1;
    BOOST_CHECK(addrman1.size() == 0);
    try {
        unsigned char pchMsgTmp[4];
        ssPeers1 >> pchMsgTmp;
        ssPeers1 >> addrman1;
    } catch (const std::exception&) {
        exceptionThrown = true;
    }
    // Even through de-serialization failed addrman is not left in a clean state.
    BOOST_CHECK(addrman1.size() == 1);
    BOOST_CHECK(exceptionThrown);

    // Test that CAddrDB::Read leaves addrman in a clean state if de-serialization fails.
    CDataStream ssPeers2 = AddrmanToStream(addrmanCorrupted);

    CAddrMan addrman2;
    CAddrDB adb;
    BOOST_CHECK(addrman2.size() == 0);
    BOOST_CHECK(!adb.Read(addrman2, ssPeers2));
    BOOST_CHECK(addrman2.size() == 0);
}

BOOST_AUTO_TEST_CASE(cnode_simple_test)
{
    SOCKET hSocket = INVALID_SOCKET;
    NodeId id = 0;
    int height = 0;

    in_addr ipv4Addr;
    ipv4Addr.s_addr = 0xa0b0c001;

    CAddress addr = CAddress(CService(ipv4Addr, 7777), NODE_NETWORK);
    std::string pszDest;
    bool fInboundIn = false;

    // Test that fFeeler is false by default.
    std::unique_ptr<CNode> pnode1 = MakeUnique<CNode>(id++, NODE_NETWORK, height, hSocket, addr, 0, 0, CAddress(), pszDest, fInboundIn);
    BOOST_CHECK(pnode1->fInbound == false);
    BOOST_CHECK(pnode1->fFeeler == false);

    fInboundIn = true;
    std::unique_ptr<CNode> pnode2 = MakeUnique<CNode>(id++, NODE_NETWORK, height, hSocket, addr, 1, 1, CAddress(), pszDest, fInboundIn);
    BOOST_CHECK(pnode2->fInbound == true);
    BOOST_CHECK(pnode2->fFeeler == false);
}

// prior to PR #14728, this test triggers an undefined behavior
BOOST_AUTO_TEST_CASE(ipv4_peer_with_ipv6_addrMe_test)
{
    // set up local addresses; all that's necessary to reproduce the bug is
    // that a normal IPv4 address is among the entries, but if this address is
    // !IsRoutable the undefined behavior is easier to trigger deterministically
    {
        LOCK(cs_mapLocalHost);
        in_addr ipv4AddrLocal;
        ipv4AddrLocal.s_addr = 0x0100007f;
        CNetAddr addr = CNetAddr(ipv4AddrLocal);
        LocalServiceInfo lsi;
        lsi.nScore = 23;
        lsi.nPort = 42;
        mapLocalHost[addr] = lsi;
    }

    // create a peer with an IPv4 address
    in_addr ipv4AddrPeer;
    ipv4AddrPeer.s_addr = 0xa0b0c001;
    CAddress addr = CAddress(CService(ipv4AddrPeer, 7777), NODE_NETWORK);
    std::unique_ptr<CNode> pnode = MakeUnique<CNode>(0, NODE_NETWORK, 0, INVALID_SOCKET, addr, 0, 0, CAddress{}, std::string{}, false);
    pnode->fSuccessfullyConnected.store(true);

    // the peer claims to be reaching us via IPv6
    in6_addr ipv6AddrLocal;
    memset(ipv6AddrLocal.s6_addr, 0, 16);
    ipv6AddrLocal.s6_addr[0] = 0xcc;
    CAddress addrLocal = CAddress(CService(ipv6AddrLocal, 7777), NODE_NETWORK);
    pnode->SetAddrLocal(addrLocal);

    // before patch, this causes undefined behavior detectable with clang's -fsanitize=memory
    AdvertiseLocal(&*pnode);

    // suppress no-checks-run warning; if this test fails, it's by triggering a sanitizer
    BOOST_CHECK(1);
}


BOOST_AUTO_TEST_CASE(LimitedAndReachable_Network)
{
    BOOST_CHECK_EQUAL(IsReachable(NET_IPV4), true);
    BOOST_CHECK_EQUAL(IsReachable(NET_IPV6), true);
    BOOST_CHECK_EQUAL(IsReachable(NET_ONION), true);

    SetReachable(NET_IPV4, false);
    SetReachable(NET_IPV6, false);
    SetReachable(NET_ONION, false);

    BOOST_CHECK_EQUAL(IsReachable(NET_IPV4), false);
    BOOST_CHECK_EQUAL(IsReachable(NET_IPV6), false);
    BOOST_CHECK_EQUAL(IsReachable(NET_ONION), false);

    SetReachable(NET_IPV4, true);
    SetReachable(NET_IPV6, true);
    SetReachable(NET_ONION, true);

    BOOST_CHECK_EQUAL(IsReachable(NET_IPV4), true);
    BOOST_CHECK_EQUAL(IsReachable(NET_IPV6), true);
    BOOST_CHECK_EQUAL(IsReachable(NET_ONION), true);
}

BOOST_AUTO_TEST_CASE(LimitedAndReachable_NetworkCaseUnroutableAndInternal)
{
    BOOST_CHECK_EQUAL(IsReachable(NET_UNROUTABLE), true);
    BOOST_CHECK_EQUAL(IsReachable(NET_INTERNAL), true);

    SetReachable(NET_UNROUTABLE, false);
    SetReachable(NET_INTERNAL, false);

    BOOST_CHECK_EQUAL(IsReachable(NET_UNROUTABLE), true); // Ignored for both networks
    BOOST_CHECK_EQUAL(IsReachable(NET_INTERNAL), true);
}

CNetAddr UtilBuildAddress(unsigned char p1, unsigned char p2, unsigned char p3, unsigned char p4)
{
    unsigned char ip[] = {p1, p2, p3, p4};

    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sockaddr_in)); // initialize the memory block
    memcpy(&(sa.sin_addr), &ip, sizeof(ip));
    return CNetAddr(sa.sin_addr);
}


BOOST_AUTO_TEST_CASE(LimitedAndReachable_CNetAddr)
{
    CNetAddr addr = UtilBuildAddress(0x001, 0x001, 0x001, 0x001); // 1.1.1.1

    SetReachable(NET_IPV4, true);
    BOOST_CHECK_EQUAL(IsReachable(addr), true);

    SetReachable(NET_IPV4, false);
    BOOST_CHECK_EQUAL(IsReachable(addr), false);

    SetReachable(NET_IPV4, true); // have to reset this, because this is stateful.
}


BOOST_AUTO_TEST_CASE(LocalAddress_BasicLifecycle)
{
    CService addr = CService(UtilBuildAddress(0x002, 0x001, 0x001, 0x001), 1000); // 2.1.1.1:1000

    SetReachable(NET_IPV4, true);

    BOOST_CHECK_EQUAL(IsLocal(addr), false);
    BOOST_CHECK_EQUAL(AddLocal(addr, 1000), true);
    BOOST_CHECK_EQUAL(IsLocal(addr), true);

    RemoveLocal(addr);
    BOOST_CHECK_EQUAL(IsLocal(addr), false);
}

size_t read_message(std::unique_ptr<TransportDeserializer>& deserializer, const std::vector<unsigned char>& serialized_header, const CSerializedNetMsg& msg) {
    size_t read_bytes = 0;
    if (serialized_header.size() > 0) read_bytes += deserializer->Read((const char *)serialized_header.data(), serialized_header.size(), false);
    //  second: read the encrypted payload (if required)
    if (msg.data.size() > 0) read_bytes += deserializer->Read((const char *)msg.data.data(), msg.data.size(), false);
    if (msg.data.size() > read_bytes && msg.data.size()-read_bytes > 0) read_bytes += deserializer->Read((const char *)msg.data.data()+read_bytes, msg.data.size()-read_bytes, false);
    return read_bytes;
}

// use 32 bytey keys with all zeros
static const CPrivKey k1(32, 0);
static const CPrivKey k2(32, 0);
static const uint256 session_id;

void message_serialize_deserialize_test(bool v2, const std::vector<CSerializedNetMsg>& test_msgs) {
    // construct the serializers
    std::unique_ptr<TransportSerializer> serializer;
    std::unique_ptr<TransportDeserializer> deserializer;

    if (v2) {
        serializer = MakeUnique<V2TransportSerializer>(V2TransportSerializer(k1, k2, session_id));
        deserializer = MakeUnique<V2TransportDeserializer>(V2TransportDeserializer(Params().MessageStart(), k1, k2, session_id));
    }
    else {
        serializer = MakeUnique<V1TransportSerializer>(V1TransportSerializer());
        deserializer = MakeUnique<V1TransportDeserializer>(V1TransportDeserializer(Params().MessageStart(), SER_NETWORK, INIT_PROTO_VERSION));
    }
    // run a couple of times through all messages with the same AEAD instance
    for (unsigned int i=0; i<100;i++) {
        for(const CSerializedNetMsg& msg_orig : test_msgs) {
            // bypass the copy protection
            CSerializedNetMsg msg;
            msg.data = msg_orig.data;
            msg.command = msg_orig.command;
            size_t raw_msg_size = msg.data.size();

            std::vector<unsigned char> serialized_header;
            serializer->prepareForTransport(msg, serialized_header);

            // read two times
            size_t read_bytes = read_message(deserializer, serialized_header, msg);
            BOOST_CHECK(deserializer->Complete());
            BOOST_CHECK_EQUAL(read_bytes, msg.data.size()+serialized_header.size());
            // message must be complete
            CNetMessage msg_deser = deserializer->GetMessage(Params().MessageStart(), GetTimeMicros());
            BOOST_CHECK_EQUAL(msg_deser.m_command, msg.command);
            BOOST_CHECK_EQUAL(raw_msg_size, msg_deser.m_message_size);
        }
    }
}

BOOST_AUTO_TEST_CASE(net_v2)
{
    // make sure we use the fast rekey rules
    gArgs.SoftSetBoolArg("-netencryptionfastrekey", true);

    // create some messages where we perform serialization and deserialization
    std::vector<CSerializedNetMsg> test_msgs;
    test_msgs.push_back(CNetMsgMaker(INIT_PROTO_VERSION).Make(NetMsgType::VERACK));
    test_msgs.push_back(CNetMsgMaker(INIT_PROTO_VERSION).Make(NetMsgType::VERSION, PROTOCOL_VERSION, (int)NODE_NETWORK, 123, CAddress(CService(), NODE_NONE), CAddress(CService(), NODE_NONE), 123, "foobar", 500000, true));
    test_msgs.push_back(CNetMsgMaker(INIT_PROTO_VERSION).Make(NetMsgType::REJECT, std::string(NetMsgType::BLOCK), '0', "foobar", uint256()));
    test_msgs.push_back(CNetMsgMaker(INIT_PROTO_VERSION).Make(NetMsgType::PING, 123456));
    CDataStream stream(ParseHex("020000000001013107ca31e1950a9b44b75ce3e8f30127e4d823ed8add1263a1cc8adcc8e49164000000001716001487835ecf51ea0351ef266d216a7e7a3e74b84b4efeffffff02082268590000000017a9144a94391b99e672b03f56d3f60800ef28bc304c4f8700ca9a3b0000000017a9146d5df9e79f752e3c53fc468db89cafda4f7d00cb87024730440220677de5b11a5617d541ba06a1fa5921ab6b4509f8028b23f18ab8c01c5eb1fcfb02202fe382e6e87653f60ff157aeb3a18fc888736720f27ced546b0b77431edabdb0012102608c772598e9645933a86bcd662a3b939e02fb3e77966c9713db5648d5ba8a0006010000"), SER_NETWORK, PROTOCOL_VERSION);
    test_msgs.push_back(CNetMsgMaker(INIT_PROTO_VERSION).Make(NetMsgType::TX, CTransaction(deserialize, stream)));
    std::vector<CInv> vInv;
    for (unsigned int i=0;i<1000;i++) { vInv.push_back(CInv(MSG_BLOCK, Params().GenesisBlock().GetHash())); }
    test_msgs.push_back(CNetMsgMaker(INIT_PROTO_VERSION).Make(NetMsgType::INV, vInv));

    // add a dummy message
    std::string dummy;
    for (unsigned int i=0;i<100;i++) { dummy += "020000000001013107ca31e1950a9b44b75ce3e8f30127e4d823ed8add1263a1cc8adcc8e49164000000001716001487835ecf51ea0351ef266d216a7e7a3e74b84b4efeffffff02082268590000000017a9144a94391b99e672b03f56d3f60800ef28bc304c4f8700ca9a3b0000000017a9146d5df9e79f752e3c53fc468db89cafda4f7d00cb87024730440220677de5b11a5617d541ba06a1fa5921ab6b4509f8028b23f18ab8c01c5eb1fcfb02202fe382e6e87653f60ff157aeb3a18fc888736720f27ced546b0b77431edabdb0012102608c772598e9645933a86bcd662a3b939e02fb3e77966c9713db5648d5ba8a0006010000"; }
    test_msgs.push_back(CNetMsgMaker(INIT_PROTO_VERSION).Make("foobar", dummy));

    message_serialize_deserialize_test(true, test_msgs);
    message_serialize_deserialize_test(false, test_msgs);
}

BOOST_AUTO_TEST_CASE(net_rekey)
{
    CSerializedNetMsg test_msg = CNetMsgMaker(INIT_PROTO_VERSION).Make(NetMsgType::VERSION, PROTOCOL_VERSION, (int)NODE_NETWORK, 123, CAddress(CService(), NODE_NONE), CAddress(CService(), NODE_NONE), 123, "foobar", 500000, true);

    // make sure we use the fast rekey rules
    std::unique_ptr<TransportSerializer> serializer = MakeUnique<V2TransportSerializer>(V2TransportSerializer(k1, k2, session_id));;
    std::unique_ptr<TransportDeserializer> deserializer = MakeUnique<V2TransportDeserializer>(V2TransportDeserializer(Params().MessageStart(), k1, k2, session_id));

    for (unsigned int i=0; i<=76;i++) {
        // encrypt the message without the fast-rekey rules
        gArgs.ForceSetArg("-netencryptionfastrekey", "0");
        std::vector<unsigned char> serialized_header;
        serializer->prepareForTransport(test_msg, serialized_header);

        // decrypt the message with the fast rekey-rules
        gArgs.ForceSetArg("-netencryptionfastrekey", "1");
        read_message(deserializer, serialized_header, test_msg);
        CNetMessage msg_deser = deserializer->GetMessage(Params().MessageStart(), GetTimeMicros());

        // make sure we detect the failed rekey
        // the 76. message (32kb) must have violated the fast rekey limits
        BOOST_CHECK(msg_deser.m_valid_header == (i!=76));
    }
}


// hack our way into CNode private members
struct Node_Hack {
  typedef std::list<CNetMessage> CNode::*type;
  friend type get(Node_Hack);
};

template<typename Tag, typename Tag::type M>
struct Rob {
  friend typename Tag::type get(Tag) {
    return M;
  }
};

template struct Rob<Node_Hack, &CNode::vRecvMsg>;

BOOST_AUTO_TEST_CASE(net_v2_handshake)
{
    SOCKET hSocket = INVALID_SOCKET;
    NodeId id = 0;
    int height = 0;

    in_addr ipv4Addr;
    ipv4Addr.s_addr = 0xa0b0c001;

    CAddress addr = CAddress(CService(ipv4Addr, 7777), NODE_NETWORK);
    std::string pszDest;
    bool fInboundIn = false;

    // create two node instances
    std::unique_ptr<CNode> pnode1 = MakeUnique<CNode>(id++, NODE_NETWORK, height, hSocket, addr, 0, 0, CAddress(), pszDest, fInboundIn);
    std::unique_ptr<CNode> pnode2 = MakeUnique<CNode>(id++, NODE_NETWORK, height, hSocket, addr, 1, 1, CAddress(), pszDest, fInboundIn);

    // generate emphemeral key on node1
    V2TransportSerializer::generateEmphemeralKey(pnode1->m_ecdh_key);

    // fake send handshake from node1 to node2
    bool complete;
    pnode2->ReceiveMsgBytes((const char *)pnode1->m_ecdh_key.GetPubKey().data()+1, 32, complete);
    {
        // fake sende handshake from node2 to node1
        LOCK(pnode2->cs_vSend);
        auto it = pnode2->vSendMsg.begin();
        const auto &data = *it;
        pnode1->ReceiveMsgBytes(reinterpret_cast<const char*>(data.data()), data.size(), complete);
    }

    // handshake done
    // now send some messages forth and back

    std::vector<CSerializedNetMsg> test_msgs;
    test_msgs.push_back(CNetMsgMaker(INIT_PROTO_VERSION).Make(NetMsgType::VERACK));
    test_msgs.push_back(CNetMsgMaker(INIT_PROTO_VERSION).Make(NetMsgType::VERSION, PROTOCOL_VERSION, (int)NODE_NETWORK, 123, CAddress(CService(), NODE_NONE), CAddress(CService(), NODE_NONE), 123, "foobar", 500000, true));
    test_msgs.push_back(CNetMsgMaker(INIT_PROTO_VERSION).Make(NetMsgType::REJECT, std::string(NetMsgType::BLOCK), '0', "foobar", uint256()));
    test_msgs.push_back(CNetMsgMaker(INIT_PROTO_VERSION).Make(NetMsgType::PING, 123456));

    CNode *n_from = pnode1.get();
    CNode *n_to = pnode2.get();

    for (unsigned int i=0; i<100;i++) {
        for(const CSerializedNetMsg& msg_orig : test_msgs) {
            // bypass the copy protection
            CSerializedNetMsg msg;
            msg.data = msg_orig.data;
            msg.command = msg_orig.command;

            std::vector<unsigned char> serializedHeader;

            // switch from/to
            n_from = n_from == pnode1.get() ? pnode2.get() : pnode1.get();
            n_to = n_to == pnode2.get() ? pnode1.get() : pnode2.get();

            n_from->m_serializer->prepareForTransport(msg, serializedHeader);
            bool suc = n_to->ReceiveMsgBytes(reinterpret_cast<const char*>(msg.data.data()), msg.data.size(), complete);
            BOOST_CHECK(suc);

            // rob access to private member vRecvMsg
            std::list<CNetMessage> test = *n_to.*get(Node_Hack());
            BOOST_CHECK_EQUAL(HexStr(test.back().m_recv.begin(), test.back().m_recv.end()), HexStr(msg_orig.data.begin(), msg_orig.data.end()));
            BOOST_CHECK_EQUAL(test.back().m_command, msg_orig.command);
        }
    }
}


BOOST_AUTO_TEST_SUITE_END()
