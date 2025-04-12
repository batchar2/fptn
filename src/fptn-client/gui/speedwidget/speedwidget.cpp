/*=============================================================================
Copyright (c) 2024-2025 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#include "gui/speedwidget/speedwidget.h"

using fptn::gui::SpeedWidget;

static QString FormatSpeed(std::size_t bytes_per_sec);
static QString FormatSpeedLabel(const QString& text, std::size_t speed);

SpeedWidget::SpeedWidget(QWidget* parent)
    : QWidget(parent),
      upload_speed_label_(
          new QLabel(FormatSpeedLabel(QObject::tr("Upload speed"), 0), this)),
      download_speed_label_(new QLabel(
          FormatSpeedLabel(QObject::tr("Download speed"), 0), this)) {
  auto layout = new QVBoxLayout();
  layout->setContentsMargins(4, 4, 4, 4);
  layout->addWidget(download_speed_label_);
  layout->addWidget(upload_speed_label_);
  setLayout(layout);
}

void SpeedWidget::UpdateSpeed(
    std::size_t upload_speed, std::size_t download_speed) {
  upload_speed_label_->setText(
      FormatSpeedLabel(QObject::tr("Upload speed"), upload_speed));
  download_speed_label_->setText(
      FormatSpeedLabel(QObject::tr("Download speed"), download_speed));
}

static QString FormatSpeedLabel(const QString& text, std::size_t speed) {
  return "    " + text + ": " + FormatSpeed(speed);
}

static QString FormatSpeed(std::size_t bytes_per_sec) {
  QString speedStr;
  double bits_per_sec = bytes_per_sec * 8.0;
  if (bits_per_sec >= 1e9) {
    speedStr = QString::asprintf("%.2f Gbps", bits_per_sec / 1e9);
  } else if (bits_per_sec >= 1e6) {
    speedStr = QString::asprintf("%.2f Mbps", bits_per_sec / 1e6);
  } else if (bits_per_sec >= 1e3) {
    speedStr = QString::asprintf("%.2f Kbps", bits_per_sec / 1e3);
  } else {
    speedStr = QString::asprintf("%.2f bps", bits_per_sec);
  }
  if (speedStr.size() >= 20) {
    return speedStr;
  }
  return speedStr.leftJustified(25);
}
