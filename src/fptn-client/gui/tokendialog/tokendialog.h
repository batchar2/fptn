/*=============================================================================
Copyright (c) 2024-2025 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#pragma once

#include <QDialog>      // NOLINT(build/include_order)
#include <QHBoxLayout>  // NOLINT(build/include_order)
#include <QLabel>       // NOLINT(build/include_order)
#include <QLineEdit>    // NOLINT(build/include_order)
#include <QMessageBox>  // NOLINT(build/include_order)
#include <QPushButton>  // NOLINT(build/include_order)
#include <QVBoxLayout>  // NOLINT(build/include_order)

namespace fptn::gui {
class TokenDialog final : public QDialog {
  Q_OBJECT
 public:
  explicit TokenDialog(QWidget* parent = nullptr);
  const QString& Token() const;

  // cppcheck-suppress unknownMacro
 private slots:
  void onOkClicked();

 private:
  QLabel* label_;
  QLineEdit* token_field_;
  QHBoxLayout* token_layout_;

  QPushButton* save_button_;
  QPushButton* cancel_button_;
  QHBoxLayout* button_layout_;

  QVBoxLayout* main_layout_;

  QString token_;
};
}  // namespace fptn::gui
