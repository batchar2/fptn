/*=============================================================================
Copyright (c) 2024-2025 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#if defined(__linux__) || defined(__APPLE__)
#include <unistd.h>
#endif

#include <iostream>
#include <memory>

#include <QApplication>   // NOLINT(build/include_order)
#include <QStyleFactory>  // NOLINT(build/include_order)

#include "common/logger/logger.h"

#include "gui/tray/tray.h"

#if defined(__linux__) || defined(__APPLE__)
static void signalHandler(int) { QApplication::quit(); }
#elif defined(_WIN32)
static BOOL WINAPI signalHandler(DWORD ctrlType) {
  if (ctrlType == CTRL_C_EVENT || ctrlType == CTRL_BREAK_EVENT) {
    qApp->quit();
    return TRUE;
  }
  return FALSE;
}
#else
#error "Unsupported platform"
#endif

int main(int argc, char* argv[]) {
#if defined(__linux__) || defined(__APPLE__)
  if (geteuid() != 0) {
    std::cerr << "You must be root to run this program." << std::endl;
    return EXIT_FAILURE;
  }
#endif
  // Initialize logger
  if (fptn::logger::init("fptn-client-gui")) {
    SPDLOG_INFO("Application started successfully.");
  } else {
    std::cerr << "Logger initialization failed. Exiting application."
              << std::endl;
    return EXIT_FAILURE;
  }

  // Setup signal handler
#if defined(__APPLE__) || defined(__linux__)
  std::signal(SIGINT, signalHandler);
  std::signal(SIGHUP, signalHandler);
  std::signal(SIGTERM, signalHandler);
  std::signal(SIGQUIT, signalHandler);
#if __linux__
  std::signal(SIGPWR, signalHandler);
#endif
#elif defined(_WIN32)
  SetConsoleCtrlHandler(signalHandler, TRUE);
#endif

  // Initialize GUI app
  QApplication::setDesktopSettingsAware(true);
  QApplication::setQuitOnLastWindowClosed(false);
#if __APPLE__
  QApplication::setAttribute(Qt::AA_MacDontSwapCtrlAndMeta, false);
#elif defined(_WIN32)
  QApplication::setStyle(QStyleFactory::create("windowsvista"));
#endif
  QApplication app(argc, argv);
  const auto settings = std::make_shared<fptn::gui::SettingsModel>(
      QMap<QString, QString>{{"en", "English"}, {"ru", "Русский"}});

  // Start GUI app
  fptn::gui::TrayApp tray(settings);
  const int code = app.exec();

  // Clean resources
  tray.stop();
  spdlog::shutdown();

  return code;
}
