/*=============================================================================
Copyright (c) 2024-2026 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#include "gui/server_menu_item_widget/server_menu_item_widget.h"

#include <utility>

#include <QHBoxLayout>  // NOLINT(build/include_order)

namespace {

const QPixmap& GetPingIcon(const int ping_ms) {
  static const QPixmap kRedCircle(":/icons/ping_red_circle.png");
  static const QPixmap kGreenCircle(":/icons/ping_green_circle.png");
  static const QPixmap kYellowCircle(":/icons/ping_yellow_circle.png");
  static const QPixmap kOrangeCircle(":/icons/ping_orange_circle.png");
  if (ping_ms == -1) {
    return kRedCircle;
  }
  if (ping_ms < 200) {
    return kGreenCircle;
  }
  if (ping_ms < 300) {
    return kYellowCircle;
  }
  if (ping_ms < 500) {
    return kOrangeCircle;
  }
  return kRedCircle;
}
}  // namespace

namespace fptn::gui {

#ifdef __APPLE__
ServerMenuItemWidget::ServerMenuItemWidget(
    QString name, int ping_ms, QObject* parent)
    : QAction(parent), name_(std::move(name)) {
  setIconVisibleInMenu(true);
  UpdatePing(ping_ms);
}

// macos
void ServerMenuItemWidget::UpdatePing(int ping_ms) {
  const QString ping = (ping_ms == -1) ? " " : QString("%1ms").arg(ping_ms);

  QString result = name_;

  const QFontMetrics kfm(this->font());
  const int target_width = kfm.horizontalAdvance("A") * 25;
  int current_width = kfm.horizontalAdvance(name_);
  while (current_width < target_width) {
    result.append(' ');
    current_width = kfm.horizontalAdvance(result);
  }

  result.append(ping);

  setText(result);
  setIcon(GetPingIcon(ping_ms));
}
#else

ServerMenuItemWidget::ServerMenuItemWidget(
    QString name, int ping_ms, QObject* parent)
    : QWidgetAction(parent), name_(std::move(name)) {
  auto* widget = new QWidget();
  widget->setAttribute(Qt::WA_Hover);
  widget->setMouseTracking(true);
  widget->setStyleSheet(R"(
    QWidget:hover {
      background-color: palette(highlight);
    }
  )");

  auto* layout = new QHBoxLayout(widget);
  layout->setContentsMargins(2, 2, 2, 2);
  // layout->setSpacing(8);

  icon_label_ = new QLabel();
  icon_label_->setFixedSize(16, 16);
  icon_label_->setScaledContents(false);
  icon_label_->setAlignment(Qt::AlignCenter);
  icon_label_->setStyleSheet("background-color: transparent;");

  name_label_ = new QLabel(name_);
  name_label_->setStyleSheet(
      "background-color: transparent;padding-right: 10px;");
  name_label_->setSizePolicy(
      QSizePolicy::MinimumExpanding, QSizePolicy::Preferred);
  name_label_->setMinimumWidth(
      QFontMetrics(name_label_->font()).horizontalAdvance(name_) + 30);

  ping_label_ = new QLabel();
  ping_label_->setSizePolicy(QSizePolicy::Minimum, QSizePolicy::Preferred);
  ping_label_->setAlignment(Qt::AlignRight);
  ping_label_->setStyleSheet("background-color: transparent;");

  layout->addWidget(icon_label_);
  layout->addWidget(name_label_);
  layout->addWidget(ping_label_);

  widget->setLayout(layout);
  setDefaultWidget(widget);

  UpdatePing(ping_ms);
}

void ServerMenuItemWidget::UpdatePing(int ping_ms) {
  const QString ping = (ping_ms == -1) ? "" : QString("%1ms").arg(ping_ms);
  ping_label_->setText(ping);
  icon_label_->setPixmap(GetPingIcon(ping_ms));
}

#endif

QString ServerMenuItemWidget::ServerName() const { return name_; }

}  // namespace fptn::gui
