/*=============================================================================
Copyright (c) 2024-2025 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#include "gui/tokendialog/tokendialog.h"

#include <iostream>
#include <string>

#include <spdlog/spdlog.h>  // NOLINT(build/include_order)

#include "common/utils/base64.h"
#include "common/utils/utils.h"

#include "utils/brotli/brotli.h"
#include "utils/utils.h"

using fptn::gui::TokenDialog;

TokenDialog::TokenDialog(QWidget* parent) : QDialog(parent) {
  setWindowTitle("Token");
  label_ = new QLabel(QObject::tr("Paste your token") + ": ", this);
  token_field_ = new QLineEdit(this);
  token_field_->setPlaceholderText(QObject::tr("Token") + "...");
  token_field_->setMinimumWidth(350);

  token_layout_ = new QHBoxLayout();
  token_layout_->addWidget(label_);
  token_layout_->addWidget(token_field_);

  save_button_ = new QPushButton(QObject::tr("Save"), this);
  cancel_button_ = new QPushButton(QObject::tr("Cancel"), this);

  // Layout for buttons
  button_layout_ = new QHBoxLayout();
  button_layout_->addStretch();
  button_layout_->addWidget(save_button_);
  button_layout_->addWidget(cancel_button_);

  // Main layout
  main_layout_ = new QVBoxLayout(this);
  main_layout_->addLayout(token_layout_);
  main_layout_->addLayout(button_layout_);

  setLayout(main_layout_);

  connect(cancel_button_, &QPushButton::clicked, this, &QDialog::reject);
  connect(save_button_, &QPushButton::clicked, this, &TokenDialog::onOkClicked);

  // show on top
  setWindowFlags(Qt::Window | Qt::WindowStaysOnTopHint);
  setModal(true);
  show();
  activateWindow();
  raise();
  setWindowModality(Qt::ApplicationModal);
}

const QString& TokenDialog::Token() const { return token_; }

void TokenDialog::onOkClicked() {
  try {
    const std::string entered_token =
        token_field_->text().trimmed().toStdString();
    const std::string token = fptn::common::utils::RemoveSubstring(
        entered_token, {" ", "\n", "\r", "\t"});

    std::string decoded_token;
    if (token.starts_with("fptnb:") || token.starts_with("fptnb//")) {
      const std::string clean_token =
          common::utils::RemoveSubstring(token, {"fptnb:", "fptnb//"});
      decoded_token = fptn::utils::brotli::Decompress(
          fptn::common::utils::base64::decode(clean_token));
    } else {
      const std::string clean_token = fptn::common::utils::RemoveSubstring(
          entered_token, {"fptn:", "fptn://"});
      decoded_token = fptn::common::utils::base64::decode(clean_token);
    }

    const QString t = QString::fromStdString(decoded_token);
    if (t.isEmpty()) {
      QMessageBox::warning(this, QObject::tr("Validation Error"),
          QObject::tr("Token cannot be empty") + "!");
    } else {
      token_ = t;
      accept();
    }
  } catch (const std::runtime_error& err) {
    SPDLOG_WARN("Wrong token: {}", err.what());
    QMessageBox::warning(this, QObject::tr("Wrong token"),
        QObject::tr("Wrong token") + ": " + err.what());
  }
}
