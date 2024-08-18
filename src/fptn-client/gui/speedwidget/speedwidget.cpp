
#include "speedwidget.h" 

using namespace fptn::gui;

static QString formatSpeed(std::size_t bytesPerSec);


SpeedWidget::SpeedWidget(QWidget *parent)
        : QWidget(parent),
          uploadSpeedLabel_(new QLabel("Upload Speed: 0 MB/s", this)),
          downloadSpeedLabel_(new QLabel("Download Speed: 0 MB/s", this))
{
    QVBoxLayout *layout = new QVBoxLayout();
    layout->setContentsMargins(30, 4, 20, 4);
    layout->addWidget(downloadSpeedLabel_);
    layout->addWidget(uploadSpeedLabel_);
    setLayout(layout);
}

void SpeedWidget::updateSpeed(std::size_t uploadSpeed, std::size_t downloadSpeed) {
    uploadSpeedLabel_->setText("Upload Speed: " + formatSpeed(uploadSpeed));
    downloadSpeedLabel_->setText("Download Speed: " + formatSpeed(downloadSpeed));
}

static QString formatSpeed(std::size_t bytesPerSec)
{
    QString speedStr;
    double bitsPerSec = bytesPerSec * 8.0;
    if (bitsPerSec >= 1e9) {
        speedStr =  QString::asprintf("%.2f Gbps", bitsPerSec / 1e9);
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
    return speedStr.leftJustified(20);
}
