// Copyright (c) 2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_QT_MEMPOOLSTATS_H
#define BITCOIN_QT_MEMPOOLSTATS_H

#include <QWidget>
#include <QGraphicsLineItem>
#include <QGraphicsPixmapItem>


#include <QEvent>

class ClientModel;

class ClickableTextItem : public QGraphicsTextItem
{
    Q_OBJECT
public:
    void setEnabled(bool state);
protected:
    void mousePressEvent(QGraphicsSceneMouseEvent *event);
Q_SIGNALS:
    void objectClicked(QGraphicsItem*);
};

class ClickableSwitchItem : public QObject, public QGraphicsPixmapItem
{
    Q_OBJECT
public:
    std::string iconPrefix;
    void setState(bool state);
protected:
    void mousePressEvent(QGraphicsSceneMouseEvent *event);
Q_SIGNALS:
    void objectClicked(QGraphicsItem*);
};

namespace Ui {
    class MempoolStats;
}

class MempoolStats : public QWidget
{
    Q_OBJECT

public:
    MempoolStats(QWidget *parent = 0);
    ~MempoolStats();

    void setClientModel(ClientModel *model);

public Q_SLOTS:
    void drawChart();
    void objectClicked(QGraphicsItem *);

private:
    ClientModel *clientModel;

    virtual void resizeEvent(QResizeEvent *event);
    virtual void showEvent(QShowEvent *event);

    QGraphicsTextItem *titleItem;
    QGraphicsLineItem *titleLine;
    QGraphicsTextItem *noDataItem;

    QGraphicsTextItem *dynMemUsageItem;
    QGraphicsTextItem *dynMemUsageValueItem;
    QGraphicsTextItem *txCountItem;
    QGraphicsTextItem *txCountValueItem;
    QGraphicsTextItem *minFeeItem;
    QGraphicsTextItem *minFeeValueItem;

    ClickableTextItem *last10MinLabel;
    ClickableTextItem *lastHourLabel;
    ClickableTextItem *lastDayLabel;
    ClickableTextItem *allDataLabel;

    ClickableSwitchItem *txCountSwitch;
    ClickableSwitchItem *minFeeSwitch;
    ClickableSwitchItem *dynMemUsageSwitch;

    QGraphicsScene *scene;
    QVector<QGraphicsItem*> redrawItems;

    bool drawTxCount;
    bool drawMinFee;
    bool drawDynMemUsage;

    int64_t timeFilter;

    Ui::MempoolStats *ui;
};

#endif // BITCOIN_QT_MEMPOOLSTATS_H
