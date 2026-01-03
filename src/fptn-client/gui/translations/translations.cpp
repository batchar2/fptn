/*=============================================================================
Copyright (c) 2024-2025 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#include "gui/translations/translations.h"

#include <spdlog/spdlog.h>  // NOLINT(build/include_order)

#include <QApplication>  // NOLINT(build/include_order)
#include <QTranslator>   // NOLINT(build/include_order)

#include "common/logger/logger.h"

namespace {
QTranslator translator;
}

bool fptn::gui::SetTranslation(const QString& language_code) {
  const QString translation_file = QString("fptn_%1.qm").arg(language_code);
  qApp->removeTranslator(&translator);
  if (translator.load(translation_file, ":/translations")) {
    if (!qApp->installTranslator(&translator)) {
      SPDLOG_WARN("Failed to install translator for language: {}",
          language_code.toStdString());
    } else {
      return true;
    }
  } else {
    SPDLOG_WARN(
        "Translation file not found: {}", translation_file.toStdString());
  }
  return false;
}
