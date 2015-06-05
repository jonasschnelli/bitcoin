// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_ZMQPUBLISHNOTIFIER_H
#define BITCOIN_ZMQPUBLISHNOTIFIER_H

#include "zmqabstractnotifier.h"

class CZMQAbstractPublishNotifier : public CZMQAbstractNotifier
{
public:
    bool Initialize(void *pcontext);
    void Shutdown();
};

class CZMQPublishHashBlockNotifier : public CZMQAbstractPublishNotifier
{
public:
    void NotifyBlock(const uint256 &hash);
};

class CZMQPublishHashTransactionNotifier : public CZMQAbstractPublishNotifier
{
public:
    void NotifyTransaction(const CTransaction &transaction);
};

#endif // BITCOIN_ZMQPUBLISHNOTIFIER_H
