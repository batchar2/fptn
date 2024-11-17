
#include "speedwidget.h" 

using namespace fptn::gui;

static QString formatSpeed(std::size_t bytesPerSec);
static QString formatSpeedLabel(const QString &text, std::size_t speed);


SpeedWidget::SpeedWidget(QWidget *parent)
    :
        QWidget(parent),
        uploadSpeedLabel_(new QLabel(formatSpeedLabel(QObject::tr("Upload speed"), 0), this)),
        downloadSpeedLabel_(new QLabel(formatSpeedLabel(QObject::tr("Download speed"), 0), this))
{
    QVBoxLayout *layout = new QVBoxLayout();
    layout->setContentsMargins(4, 4, 4, 4);
    layout->addWidget(downloadSpeedLabel_);
    layout->addWidget(uploadSpeedLabel_);
    setLayout(layout);
}

void SpeedWidget::updateSpeed(std::size_t uploadSpeed, std::size_t downloadSpeed) {
    uploadSpeedLabel_->setText(formatSpeedLabel(QObject::tr("Upload speed"), uploadSpeed));
    downloadSpeedLabel_->setText(formatSpeedLabel(QObject::tr("Download speed"), downloadSpeed));
}

static QString formatSpeedLabel(const QString &text, std::size_t speed)
{
    return "    " + text + ": " + formatSpeed(speed);
}

static QString formatSpeed(std::size_t bytesPerSec)
{
    QString speedStr;
    double bitsPerSec = bytesPerSec * 8.0;
    if (bitsPerSec >= 1e9) {
        speedStr = QString::asprintf("%.2f Gbps", bitsPerSec / 1e9);
    } else if (bitsPerSec >= 1e6) {
        speedStr = QString::asprintf("%.2f Mbps", bitsPerSec / 1e6);
    } else if (bitsPerSec >= 1e3) {
        speedStr = QString::asprintf("%.2f Kbps", bitsPerSec / 1e3);
    } else {
        speedStr = QString::asprintf("%.2f bps", bitsPerSec);
    }
    if (speedStr.size() >= 20) {
        return speedStr;
    }
    return speedStr.leftJustified(25);
}
