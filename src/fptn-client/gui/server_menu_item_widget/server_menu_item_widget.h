/*=============================================================================
Copyright (c) 2024-2025 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#pragma once

#include <QEnterEvent>    // NOLINT(build/include_order)
#include <QLabel>         // NOLINT(build/include_order)
#include <QMouseEvent>    // NOLINT(build/include_order)
#include <QWidget>        // NOLINT(build/include_order)
#include <QWidgetAction>  // NOLINT(build/include_order)

namespace fptn::gui {
class ServerMenuItemWidget : public QWidget {
  Q_OBJECT
 public:
  explicit ServerMenuItemWidget(
      const QString& name, int ping_ms = -1, QWidget* parent = nullptr);

  void UpdatePing(int ping_ms);
  QString ServerName() const { return name_; }

 signals:
  void clicked();

 protected:
  void enterEvent(QEnterEvent* event) override;
  void leaveEvent(QEvent* event) override;
  void mouseReleaseEvent(QMouseEvent* event) override;

 private:
  QLabel* icon_label_;
  QLabel* ping_label_;
  QLabel* name_label_;
  QString name_;
};
}  // namespace fptn::gui
