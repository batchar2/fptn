
#include "speedwidget.h" 

using namespace fptn::gui; 


SpeedWidget::SpeedWidget()
{
    QVBoxLayout *mainLayout = new QVBoxLayout(this);
    mainLayout->setContentsMargins(20, 4, 20, 4);

    QHBoxLayout *downloadLayout = new QHBoxLayout();
    {
        QLabel *downloadLabel = new QLabel("Download:");
        downloadLabel->setStyleSheet("font-weight: bold;");

        downloadSpeedLabel = new QLabel("0.0 KB/s");
        downloadLayout->addWidget(downloadLabel);
        downloadLayout->addWidget(downloadSpeedLabel);
    }
    QHBoxLayout *uploadLayout = new QHBoxLayout();
    {
        QLabel *uploadLabel = new QLabel("Upload:");
        uploadLabel->setStyleSheet("font-weight: bold;");

        uploadSpeedLabel = new QLabel("0.0 KB/s");
        uploadLayout->addWidget(uploadLabel);
        uploadLayout->addWidget(uploadSpeedLabel);
    }
    mainLayout->addLayout(downloadLayout);
    mainLayout->addLayout(uploadLayout);
    setLayout(mainLayout);
}

void SpeedWidget::updateSpeeds(const QString &uploadSpeed, const QString &downloadSpeed) noexcept
{
    uploadSpeedLabel->setText(uploadSpeed);
    downloadSpeedLabel->setText(downloadSpeed);
}
