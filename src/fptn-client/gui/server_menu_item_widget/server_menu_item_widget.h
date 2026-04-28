/*=============================================================================
Copyright (c) 2024-2026 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#pragma once

#include <QAction>        // NOLINT(build/include_order)
#include <QLabel>         // NOLINT(build/include_order)
#include <QMouseEvent>    // NOLINT(build/include_order)
#include <QWidgetAction>  // NOLINT(build/include_order)

namespace fptn::gui {

#ifdef __APPLE__
// QWidgetAction doesn't work fopr macos
class ServerMenuItemWidget : public QAction {
#else
class ServerMenuItemWidget : public QWidgetAction {
#endif
  Q_OBJECT
 public:
  explicit ServerMenuItemWidget(
      QString name, int ping_ms, QObject* parent = nullptr);
  void UpdatePing(int ping_ms);
  QString ServerName() const;

 private:
  QString name_;

  QLabel* icon_label_{nullptr};
  QLabel* name_label_{nullptr};
  QLabel* ping_label_{nullptr};
};

}  // namespace fptn::gui
