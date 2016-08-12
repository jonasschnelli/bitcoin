// Copyright (c) 2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "mempoolstats.h"
#include "ui_mempoolstats.h"

#include "clientmodel.h"
#include "guiutil.h"
#include "stats/stats.h"

static const char *LABEL_FONT = "Arial";
static int LABEL_TITLE_SIZE = 22;
static int LABEL_KV_SIZE = 12;

static const int TEN_MINS = 600;
static const int ONE_HOUR = 3600;
static const int ONE_DAY = ONE_HOUR*24;

static const int LABEL_LEFT_SIZE = 30;
static const int LABEL_RIGHT_SIZE = 30;
static const int GRAPH_PADDING_LEFT = 30+LABEL_LEFT_SIZE;
static const int GRAPH_PADDING_RIGHT = 30+LABEL_RIGHT_SIZE;
static const int GRAPH_PADDING_TOP = 10;
static const int GRAPH_PADDING_TOP_LABEL = 150;
static const int GRAPH_PADDING_BOTTOM = 50;
static const int LABEL_HEIGHT = 15;

static QSize buttonSize(30,14);

void ClickableTextItem::mousePressEvent(QGraphicsSceneMouseEvent *event)
{
    Q_EMIT objectClicked(this);
}

void ClickableTextItem::setEnabled(bool state)
{
    if (state)
        setDefaultTextColor(QColor(15,68,113, 250));
    else
        setDefaultTextColor(QColor(100,100,100, 200));
}

void ClickableSwitchItem::mousePressEvent(QGraphicsSceneMouseEvent *event)
{
    Q_EMIT objectClicked(this);
}

void ClickableSwitchItem::setState(bool state)
{
    if (state)
        setPixmap(QIcon(QString::fromStdString(":/icons/button_on_"+iconPrefix)).pixmap(buttonSize));
    else
        setPixmap(QIcon(":/icons/button_off").pixmap(buttonSize));
}

MempoolStats::MempoolStats(QWidget *parent) :
QWidget(parent, Qt::Window),
clientModel(0),
titleItem(0),
scene(0),
drawTxCount(true),
drawMinFee(false),
drawDynMemUsage(true),
timeFilter(TEN_MINS),
ui(new Ui::MempoolStats)
{
    ui->setupUi(this);
    if (parent) {
        parent->installEventFilter(this);
        raise();
    }

    // autoadjust font size
    QGraphicsTextItem testText("jY"); //screendesign expected 27.5 pixel in width for this string
    testText.setFont(QFont(LABEL_FONT, LABEL_TITLE_SIZE, QFont::Light));
    LABEL_TITLE_SIZE *= 27.5/testText.boundingRect().width();
    LABEL_KV_SIZE *= 27.5/testText.boundingRect().width();

    scene = new QGraphicsScene();
    ui->graphicsView->setScene(scene);
    ui->graphicsView->setRenderHints(QPainter::Antialiasing | QPainter::SmoothPixmapTransform);

    if (clientModel)
        drawChart();
}

void MempoolStats::setClientModel(ClientModel *model)
{
    clientModel = model;

    if (model)
        connect(model, SIGNAL(mempoolStatsDidUpdate()), this, SLOT(drawChart()));
}

void MempoolStats::drawChart()
{
    if (!isVisible())
        return;

    if (!titleItem)
    {
        // create labels (only once)
        titleItem = scene->addText(tr("Mempool Statistics"));
        titleItem->setFont(QFont(LABEL_FONT, LABEL_TITLE_SIZE, QFont::Light));
        titleLine = scene->addLine(0,0,100,100);
        titleLine->setPen(QPen(QColor(100,100,100, 200), 2, Qt::SolidLine, Qt::RoundCap, Qt::RoundJoin));
        dynMemUsageSwitch = new ClickableSwitchItem();
        scene->addItem(dynMemUsageSwitch);
        dynMemUsageSwitch->iconPrefix = "blue";
        connect(dynMemUsageSwitch, SIGNAL(objectClicked(QGraphicsItem*)), this, SLOT(objectClicked(QGraphicsItem*)));
        dynMemUsageItem = scene->addText(tr("Dynamic Memory Usage"));
        dynMemUsageItem->setFont(QFont(LABEL_FONT, LABEL_KV_SIZE, QFont::Light));
        dynMemUsageValueItem = scene->addText("N/A");
        dynMemUsageValueItem->setFont(QFont(LABEL_FONT, LABEL_KV_SIZE, QFont::Bold));

        txCountSwitch = new ClickableSwitchItem();
        scene->addItem(txCountSwitch);
        txCountSwitch->iconPrefix = "red";
        connect(txCountSwitch, SIGNAL(objectClicked(QGraphicsItem*)), this, SLOT(objectClicked(QGraphicsItem*)));
        txCountItem = scene->addText("Amount of Transactions");
        txCountItem->setFont(QFont(LABEL_FONT, LABEL_KV_SIZE, QFont::Light));
        txCountValueItem = scene->addText("N/A");
        txCountValueItem->setFont(QFont(LABEL_FONT, LABEL_KV_SIZE, QFont::Bold));

        minFeeSwitch = new ClickableSwitchItem();
        minFeeSwitch->iconPrefix = "green";
        scene->addItem(minFeeSwitch);
        connect(minFeeSwitch, SIGNAL(objectClicked(QGraphicsItem*)), this, SLOT(objectClicked(QGraphicsItem*)));
        minFeeItem = scene->addText(tr("MinRelayFee per KB"));
        minFeeItem->setFont(QFont(LABEL_FONT, LABEL_KV_SIZE, QFont::Light));
        minFeeValueItem = scene->addText(tr("N/A"));
        minFeeValueItem->setFont(QFont(LABEL_FONT, LABEL_KV_SIZE, QFont::Bold));

        noDataItem = scene->addText(tr("No Data available"));
        noDataItem->setFont(QFont(LABEL_FONT, LABEL_TITLE_SIZE, QFont::Light));
        noDataItem->setDefaultTextColor(QColor(100,100,100, 200));

        last10MinLabel = new ClickableTextItem(); last10MinLabel->setPlainText(tr("Last 10 min"));
        scene->addItem(last10MinLabel);
        connect(last10MinLabel, SIGNAL(objectClicked(QGraphicsItem*)), this, SLOT(objectClicked(QGraphicsItem*)));
        last10MinLabel->setFont(QFont(LABEL_FONT, LABEL_KV_SIZE, QFont::Light));
        lastHourLabel = new ClickableTextItem(); lastHourLabel->setPlainText(tr("Last Hour"));
        scene->addItem(lastHourLabel);
        connect(lastHourLabel, SIGNAL(objectClicked(QGraphicsItem*)), this, SLOT(objectClicked(QGraphicsItem*)));
        lastHourLabel->setFont(QFont(LABEL_FONT, LABEL_KV_SIZE, QFont::Light));
        lastDayLabel = new ClickableTextItem(); lastDayLabel->setPlainText(tr("Last Day"));
        scene->addItem(lastDayLabel);
        connect(lastDayLabel, SIGNAL(objectClicked(QGraphicsItem*)), this, SLOT(objectClicked(QGraphicsItem*)));
        lastDayLabel->setFont(QFont(LABEL_FONT, LABEL_KV_SIZE, QFont::Light));
        allDataLabel = new ClickableTextItem(); allDataLabel->setPlainText(tr("All Data"));
        scene->addItem(allDataLabel);
        connect(allDataLabel, SIGNAL(objectClicked(QGraphicsItem*)), this, SLOT(objectClicked(QGraphicsItem*)));
        allDataLabel->setFont(QFont(LABEL_FONT, LABEL_KV_SIZE, QFont::Light));
    }

    // set button states
    dynMemUsageSwitch->setState(drawDynMemUsage);
    txCountSwitch->setState(drawTxCount);
    minFeeSwitch->setState(drawMinFee);

    last10MinLabel->setEnabled((timeFilter == TEN_MINS));
    lastHourLabel->setEnabled((timeFilter == ONE_HOUR));
    lastDayLabel->setEnabled((timeFilter == ONE_DAY));
    allDataLabel->setEnabled((timeFilter == 0));

    // remove the items which needs to be redrawn
    for (QGraphicsItem * item : redrawItems)
    {
        scene->removeItem(item);
        delete item;
    }
    redrawItems.clear();

    // get the samples
    QDateTime toDateTime = QDateTime::currentDateTime();
    QDateTime fromDateTime = toDateTime.addSecs(-timeFilter); //-1h
    if (timeFilter == 0)
    {
        // disable filter if timeFilter == 0
        toDateTime.setTime_t(0);
        fromDateTime.setTime_t(0);
    }

    mempoolSamples_t vSamples = clientModel->getMempoolStatsInRange(fromDateTime, toDateTime);

    // set the values into the overview labels
    if (vSamples.size())
    {
        dynMemUsageValueItem->setPlainText(GUIUtil::formatBytes(vSamples.back().dynMemUsage));
        txCountValueItem->setPlainText(QString::number(vSamples.back().txCount));
        minFeeValueItem->setPlainText(QString::number(vSamples.back().minFeePerK));
    }

    // set dynamic label positions
    int maxValueSize = std::max(std::max(txCountValueItem->boundingRect().width(), dynMemUsageValueItem->boundingRect().width()), minFeeValueItem->boundingRect().width());
    maxValueSize = ceil(maxValueSize*0.13)*10; //use size steps of 10dip

    int rightPaddingLabels = std::max(std::max(dynMemUsageItem->boundingRect().width(), txCountItem->boundingRect().width()), minFeeItem->boundingRect().width())+maxValueSize;
    int rightPadding = 10;
    dynMemUsageItem->setPos(width()-rightPaddingLabels-rightPadding, dynMemUsageItem->pos().y());
    dynMemUsageSwitch->setPos(dynMemUsageItem->pos().x()-buttonSize.width(), dynMemUsageItem->pos().y()+dynMemUsageSwitch->boundingRect().height()/3.0);

    txCountItem->setPos(width()-rightPaddingLabels-rightPadding, dynMemUsageItem->pos().y()+dynMemUsageItem->boundingRect().height());
    txCountSwitch->setPos(txCountItem->pos().x()-buttonSize.width(), txCountItem->pos().y()+txCountSwitch->boundingRect().height()/3.0);

    minFeeItem->setPos(width()-rightPaddingLabels-rightPadding, dynMemUsageItem->pos().y()+dynMemUsageItem->boundingRect().height()+txCountItem->boundingRect().height());
    minFeeSwitch->setPos(minFeeItem->pos().x()-buttonSize.width(), minFeeItem->pos().y()+minFeeSwitch->boundingRect().height()/3.0);

    dynMemUsageValueItem->setPos(width()-dynMemUsageValueItem->boundingRect().width()-rightPadding, dynMemUsageItem->pos().y());
    txCountValueItem->setPos(width()-txCountValueItem->boundingRect().width()-rightPadding, txCountItem->pos().y());
    minFeeValueItem->setPos(width()-minFeeValueItem->boundingRect().width()-rightPadding, minFeeItem->pos().y());

    titleItem->setPos(5,minFeeSwitch->pos().y()+minFeeSwitch->boundingRect().height()-titleItem->boundingRect().height()+10);
    titleLine->setLine(10, titleItem->pos().y()+titleItem->boundingRect().height(), width()-10, titleItem->pos().y()+titleItem->boundingRect().height());

    // center the optional "no data" label
    noDataItem->setPos(width()/2.0-noDataItem->boundingRect().width()/2.0, height()/2.0);

    // set the position of the filter icons
    static const int filterBottomPadding = 30;
    int totalWidth = last10MinLabel->boundingRect().width()+lastHourLabel->boundingRect().width()+lastDayLabel->boundingRect().width()+allDataLabel->boundingRect().width()+30;
    last10MinLabel->setPos((width()-totalWidth)/2.0,height()-filterBottomPadding);
    lastHourLabel->setPos((width()-totalWidth)/2.0+last10MinLabel->boundingRect().width()+10,height()-filterBottomPadding);
    lastDayLabel->setPos((width()-totalWidth)/2.0+last10MinLabel->boundingRect().width()+lastHourLabel->boundingRect().width()+20,height()-filterBottomPadding);
    allDataLabel->setPos((width()-totalWidth)/2.0+last10MinLabel->boundingRect().width()+lastHourLabel->boundingRect().width()+lastDayLabel->boundingRect().width()+30,height()-filterBottomPadding);

    // don't paint the grind/graph if there are no or only a signle sample
    if (vSamples.size() < 2)
    {
        noDataItem->setVisible(true);
        return;
    }
    noDataItem->setVisible(false);

    int bottom = ui->graphicsView->size().height()-GRAPH_PADDING_BOTTOM;
    qreal maxwidth = ui->graphicsView->size().width()-GRAPH_PADDING_LEFT-GRAPH_PADDING_RIGHT;
    qreal maxheightG = ui->graphicsView->size().height()-GRAPH_PADDING_TOP-GRAPH_PADDING_TOP_LABEL-LABEL_HEIGHT;
    float paddingTopSizeFactor = 1.2;
    qreal step = maxwidth/(double)vSamples.size();

    // make sure we skip samples that would be drawn narrower then 1px
    // larger window can result in drawing more samples
    int samplesStep = 1;
    if (step < 1)
        samplesStep = ceil(1/samplesStep);

    // find maximum values
    int64_t maxDynMemUsage = 0;
    int64_t minDynMemUsage = std::numeric_limits<int64_t>::max();
    int64_t maxTxCount = 0;
    int64_t minTxCount = std::numeric_limits<int64_t>::max();
    int64_t maxMinFee = 0;
    uint32_t maxTimeDetla = vSamples.back().timeDelta-vSamples.front().timeDelta;
    for(const struct CStatsMempoolSample &sample : vSamples)
    {
        if (sample.dynMemUsage > maxDynMemUsage)
            maxDynMemUsage = sample.dynMemUsage;

        if (sample.dynMemUsage < minDynMemUsage)
            minDynMemUsage = sample.dynMemUsage;

        if (sample.txCount > maxTxCount)
            maxTxCount = sample.txCount;

        if (sample.txCount < minTxCount)
            minTxCount = sample.txCount;

        if (sample.minFeePerK > maxMinFee)
            maxMinFee = sample.minFeePerK;
    }

    int64_t dynMemUsagelog10Val = pow(10.0f, floor(log10(maxDynMemUsage*paddingTopSizeFactor-minDynMemUsage)));
    int64_t topDynMemUsage = ceil((double)maxDynMemUsage*paddingTopSizeFactor/dynMemUsagelog10Val)*dynMemUsagelog10Val;
    int64_t bottomDynMemUsage = floor((double)minDynMemUsage/dynMemUsagelog10Val)*dynMemUsagelog10Val;

    int64_t txCountLog10Val = pow(10.0f, floor(log10(maxTxCount*paddingTopSizeFactor-minTxCount)));
    int64_t topTxCount = ceil((double)maxTxCount*paddingTopSizeFactor/txCountLog10Val)*txCountLog10Val;
    int64_t bottomTxCount = floor((double)minTxCount/txCountLog10Val)*txCountLog10Val;
    
    qreal currentX = GRAPH_PADDING_LEFT;
    QPainterPath dynMemUsagePath(QPointF(currentX, bottom));
    QPainterPath txCountPath(QPointF(currentX, bottom));
    QPainterPath minFeePath(QPointF(currentX, bottom));

    // draw the three possible paths
    for (mempoolSamples_t::iterator it = vSamples.begin(); it != vSamples.end(); it+=samplesStep)
    {
        const struct CStatsMempoolSample &sample = (*it);
        qreal xPos = maxTimeDetla > 0 ? maxwidth/maxTimeDetla*(sample.timeDelta-vSamples.front().timeDelta) : maxwidth/(double)vSamples.size();
        if (sample.timeDelta == vSamples.front().timeDelta)
        {
            dynMemUsagePath.moveTo(GRAPH_PADDING_LEFT+xPos, bottom-maxheightG/(topDynMemUsage-bottomDynMemUsage)*(sample.dynMemUsage-bottomDynMemUsage));
            txCountPath.moveTo(GRAPH_PADDING_LEFT+xPos, bottom-maxheightG/(topTxCount-bottomTxCount)*(sample.txCount-bottomTxCount));
            minFeePath.moveTo(GRAPH_PADDING_LEFT+xPos, bottom-maxheightG/maxMinFee*sample.minFeePerK);
        }
        else
        {
            dynMemUsagePath.lineTo(GRAPH_PADDING_LEFT+xPos, bottom-maxheightG/(topDynMemUsage-bottomDynMemUsage)*(sample.dynMemUsage-bottomDynMemUsage));
            txCountPath.lineTo(GRAPH_PADDING_LEFT+xPos, bottom-maxheightG/(topTxCount-bottomTxCount)*(sample.txCount-bottomTxCount));
            minFeePath.lineTo(GRAPH_PADDING_LEFT+xPos, bottom-maxheightG/maxMinFee*sample.minFeePerK);
        }
    }

    // copy the path for the fill
    QPainterPath dynMemUsagePathFill(dynMemUsagePath);

    // close the path for the fill
    dynMemUsagePathFill.lineTo(GRAPH_PADDING_LEFT+maxwidth, bottom);
    dynMemUsagePathFill.lineTo(GRAPH_PADDING_LEFT, bottom);

    QPainterPath dynMemUsageGridPath(QPointF(currentX, bottom));

    // draw horizontal grid
    int amountOfLinesH = 5;
    QFont gridFont;
    gridFont.setPointSize(8);
    for (int i=0; i < amountOfLinesH; i++)
    {
        qreal lY = bottom-i*(maxheightG/(amountOfLinesH-1));
        dynMemUsageGridPath.moveTo(GRAPH_PADDING_LEFT, lY);
        dynMemUsageGridPath.lineTo(GRAPH_PADDING_LEFT+maxwidth, lY);

        size_t gridDynSize = (float)i*(topDynMemUsage-bottomDynMemUsage)/(amountOfLinesH-1) + bottomDynMemUsage;
        size_t gridTxCount = (float)i*(topTxCount-bottomTxCount)/(amountOfLinesH-1) + bottomTxCount;

        QGraphicsTextItem *itemDynSize = scene->addText(GUIUtil::formatBytes(gridDynSize), gridFont);
        QGraphicsTextItem *itemTxCount = scene->addText(QString::number(gridTxCount), gridFont);

        itemDynSize->setPos(GRAPH_PADDING_LEFT-itemDynSize->boundingRect().width(), lY-(itemDynSize->boundingRect().height()/2));
        itemTxCount->setPos(GRAPH_PADDING_LEFT+maxwidth, lY-(itemDynSize->boundingRect().height()/2));
        redrawItems.append(itemDynSize);
        redrawItems.append(itemTxCount);
    }

    // draw vertical grid
    int amountOfLinesV = 4;
    QDateTime drawTime(fromDateTime);
    std::string fromS = fromDateTime.toString().toStdString();
    std::string toS = toDateTime.toString().toStdString();
    qint64 secsTotal = fromDateTime.secsTo(toDateTime);
    for (int i=0; i <= amountOfLinesV; i++)
    {
        qreal lX = i*(maxwidth/(amountOfLinesV));
        dynMemUsageGridPath.moveTo(GRAPH_PADDING_LEFT+lX, bottom);
        dynMemUsageGridPath.lineTo(GRAPH_PADDING_LEFT+lX, bottom-maxheightG);

        QGraphicsTextItem *item = scene->addText(drawTime.toString("HH:mm"), gridFont);
        item->setPos(GRAPH_PADDING_LEFT+lX-(item->boundingRect().width()/2), bottom);
        redrawItems.append(item);
        qint64 step = secsTotal/amountOfLinesV;
        drawTime = drawTime.addSecs(step);
    }

    // materialize path
    QPen gridPen(QColor(100,100,100, 200), 1, Qt::SolidLine, Qt::RoundCap, Qt::RoundJoin);
    redrawItems.append(scene->addPath(dynMemUsageGridPath, gridPen));

    // draw semi-transparent gradient for the dynamic memory size fill
    QLinearGradient gradient(currentX, bottom, currentX, 0);
    gradient.setColorAt(1.0,	QColor(15,68,113, 250));
    gradient.setColorAt(0,QColor(255,255,255,0));
    QBrush graBru(gradient);

    QPen linePenBlue(QColor(15,68,113, 250), 2, Qt::SolidLine, Qt::RoundCap, Qt::RoundJoin);
    QPen linePenRed(QColor(188,49,62, 250), 2, Qt::SolidLine, Qt::RoundCap, Qt::RoundJoin);
    QPen linePenGreen(QColor(49,188,62, 250), 2, Qt::SolidLine, Qt::RoundCap, Qt::RoundJoin);

    if (drawTxCount)
        redrawItems.append(scene->addPath(txCountPath, linePenRed));
    if (drawMinFee)
        redrawItems.append(scene->addPath(minFeePath, linePenGreen));
    if (drawDynMemUsage)
    {
        redrawItems.append(scene->addPath(dynMemUsagePath, linePenBlue));
        redrawItems.append(scene->addPath(dynMemUsagePathFill, QPen(Qt::NoPen), graBru));
    }
}

// We override the virtual resizeEvent of the QWidget to adjust tables column
// sizes as the tables width is proportional to the dialogs width.
void MempoolStats::resizeEvent(QResizeEvent *event)
{
    QWidget::resizeEvent(event);
    ui->graphicsView->resize(size());
    ui->graphicsView->scene()->setSceneRect(rect());
    drawChart();
}

void MempoolStats::showEvent(QShowEvent *event)
{
    QWidget::showEvent(event);
    if (clientModel)
        drawChart();
}

void MempoolStats::objectClicked(QGraphicsItem *item)
{
    if (item == dynMemUsageSwitch)
        drawDynMemUsage = !drawDynMemUsage;

    if (item == txCountSwitch)
        drawTxCount = !drawTxCount;

    if (item == minFeeSwitch)
        drawMinFee = !drawMinFee;

    if (item == last10MinLabel)
        timeFilter = 600;

    if (item == lastHourLabel)
        timeFilter = 3600;

    if (item == lastDayLabel)
        timeFilter = 24*3600;

    if (item == allDataLabel)
        timeFilter = 0;
    
    drawChart();
}

MempoolStats::~MempoolStats()
{
    if (titleItem)
    {
        for (QGraphicsItem * item : redrawItems)
        {
            scene->removeItem(item);
            delete item;
        }
        redrawItems.clear();

        delete titleItem;
        delete titleLine;
        delete noDataItem;
        delete dynMemUsageItem;
        delete dynMemUsageValueItem;
        delete txCountItem;
        delete txCountValueItem;
        delete minFeeItem;
        delete minFeeValueItem;
        delete last10MinLabel;
        delete lastHourLabel;
        delete lastDayLabel;
        delete allDataLabel;
        delete txCountSwitch;
        delete minFeeSwitch;
        delete dynMemUsageSwitch;
        delete scene;
    }
}