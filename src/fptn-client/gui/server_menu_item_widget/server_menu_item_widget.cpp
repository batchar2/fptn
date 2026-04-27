/*=============================================================================
Copyright (c) 2024-2025 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#include "gui/server_menu_item_widget/server_menu_item_widget.h"

#include <QHBoxLayout>  // NOLINT(build/include_order)

namespace {

QPixmap GetPingIcon(int ping_ms) {
  if (ping_ms == -1) {
    return QPixmap(":/icons/ping_red_circle.png");
  }
  if (ping_ms < 200) {
    return QPixmap(":/icons/ping_green_circle.png");
  }
  if (ping_ms < 300) {
    return QPixmap(":/icons/ping_yellow_circle.png");
  }
  if (ping_ms < 500) {
    return QPixmap(":/icons/ping_orange_circle.png");
  }
  return QPixmap(":/icons/ping_red_circle.png");
}
}  // namespace

namespace fptn::gui {

ServerMenuItemWidget::ServerMenuItemWidget(
    const QString& name, int ping_ms, QWidget* parent)
    : QWidget(parent), name_(name) {
  setAttribute(Qt::WA_TransparentForMouseEvents, false);

  setAttribute(Qt::WA_Hover);
  setAttribute(Qt::WA_TranslucentBackground);
  setFocusPolicy(Qt::NoFocus);
  setMouseTracking(true);

  setStyleSheet(R"(
        ServerMenuItemWidget:hover {
            background-color: palette(highlight);
            color: palette(highlighted-text);
        }
        ServerMenuItemWidget:hover QLabel {
            color: palette(highlighted-text);
        }
    )");

  auto* layout = new QHBoxLayout(this);
  layout->setContentsMargins(15, 2, 5, 2);
  layout->setSpacing(4);

  icon_label_ = new QLabel(this);
  ping_label_ = new QLabel(this);
  name_label_ = new QLabel(name, this);

  ping_label_->setMinimumWidth(40);
  ping_label_->setStyleSheet("font-size: 10px;");
  name_label_->setStyleSheet("font-weight: normal;");

  layout->addWidget(icon_label_);
  layout->addWidget(ping_label_);
  layout->addWidget(name_label_);
  layout->addStretch();

  UpdatePing(ping_ms);
  setLayout(layout);
}

void ServerMenuItemWidget::UpdatePing(int ping_ms) {
  auto icon = GetPingIcon(ping_ms);
  icon_label_->setPixmap(icon);
  if (ping_ms == -1) {
    ping_label_->setText("  ---  ");
  } else {
    ping_label_->setText(QString("%1ms").arg(ping_ms));
  }
}

void ServerMenuItemWidget::enterEvent(QEnterEvent* event) {
  QWidget::enterEvent(event);
  update();
}

void ServerMenuItemWidget::leaveEvent(QEvent* event) {
  QWidget::leaveEvent(event);
  update();
}

void ServerMenuItemWidget::mouseReleaseEvent(QMouseEvent* event) {
  if (event->button() == Qt::LeftButton) {
    event->accept();
    emit clicked();
  }
  QWidget::mouseReleaseEvent(event);
}

}  // namespace fptn::gui
