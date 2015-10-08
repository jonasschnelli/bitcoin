// Copyright (c) 2015 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_QT_RPCTEXTEDIT_H
#define BITCOIN_QT_RPCTEXTEDIT_H

#include <QWidget>
#include <QTextEdit>
#include <QKeyEvent>

namespace Ui {
    class RPCTextEdit;
}

class RPCTextEdit : public QTextEdit
{
    Q_OBJECT
public:
    RPCTextEdit(QWidget *parent = 0);
    void keyPressEvent(QKeyEvent * event);
public Q_SLOTS:
    void copy();
};

#endif // BITCOIN_QT_RPCTEXTEDIT_H
