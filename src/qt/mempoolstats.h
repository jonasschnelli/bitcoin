// Copyright (c) 2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_QT_MEMPOOLSTATS_H
#define BITCOIN_QT_MEMPOOLSTATS_H

#include <QEvent>
#include <QWidget>
#include <QGraphicsItem>
#include <QGraphicsRectItem>
#include <QGraphicsScene>
#include <QGraphicsSimpleTextItem>
#include <QGraphicsView>

class ClientModel;

class ClickableTextItem : public QObject, public QGraphicsSimpleTextItem
{
    Q_OBJECT
protected:
    void mousePressEvent(QGraphicsSceneMouseEvent *event);
Q_SIGNALS:
    void objectClicked(QGraphicsItem*);
};

class ClickableRectItem : public QObject, public QGraphicsRectItem
{
    Q_OBJECT
protected:
    void mousePressEvent(QGraphicsSceneMouseEvent *event);
Q_SIGNALS:
    void objectClicked(QGraphicsItem*);
};



//namespace Ui {
//    class MempoolStats;
//}

class MempoolStats : public QWidget
{
    Q_OBJECT

public:
    explicit MempoolStats(QWidget *parent = nullptr);
    void setClientModel(ClientModel *model);

public Q_SLOTS:
    void drawChart();

private:
    ClientModel* m_clientmodel = nullptr;
//    Ui::MempoolStats* m_ui = nullptr;

    QGraphicsView *m_gfx_view;
    QGraphicsScene *m_scene;

    virtual void resizeEvent(QResizeEvent* event);
    virtual void showEvent(QShowEvent* event);

    int m_selected_range = -1;
};

#endif // BITCOIN_QT_MEMPOOLSTATS_H
