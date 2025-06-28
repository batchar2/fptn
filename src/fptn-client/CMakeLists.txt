project(fptn-client)

include_directories(${CMAKE_CURRENT_SOURCE_DIR})

if(APPLE OR UNIX)
  set(TUNTAP_LIB tuntap++)
else()
  set(TUNTAP_LIB Wintun rpcrt4 iphlpapi Kernel32.lib)
endif()

find_package(OpenSSL REQUIRED)
find_package(argparse REQUIRED)
find_package(spdlog REQUIRED)
find_package(fmt REQUIRED)
find_package(PcapPlusPlus REQUIRED)
find_package(Boost REQUIRED COMPONENTS random filesystem)
find_package(ZLIB REQUIRED)
find_package(httplib REQUIRED)

find_package(nlohmann_json REQUIRED)

include_directories(${nlohmann_json_INCLUDE_DIRS})

# fptn-client-cli
add_executable(
  "${PROJECT_NAME}-cli"
  fptn-client-cli.cpp
  vpn/vpn_client.h
  vpn/vpn_client.cpp
  http/client.h
  http/client.cpp
  routing/iptables.h
  routing/iptables.cpp
  config/config_file.cpp
  config/config_file.h)

target_link_libraries(
  "${PROJECT_NAME}-cli"
  PRIVATE ZLIB::ZLIB
          Boost::boost
          Boost::random
          Boost::filesystem
          OpenSSL::SSL
          OpenSSL::Crypto
          argparse::argparse
          nlohmann_json::nlohmann_json
          spdlog::spdlog
          fmt::fmt
          PcapPlusPlus::PcapPlusPlus
          fptn-protocol-lib_static
          ${TUNTAP_LIB})

# fptn-client-gui
if("${FPTN_BUILD_WITH_GUI_CLIENT}")
  # --- disable clang-tidy for QT generated code ---
  set_source_files_properties($<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}/qrc_resources.cpp> PROPERTIES SKIP_CLANG_TIDY ON)
  set(DISABLE_TIDY_DIR "${CMAKE_BINARY_DIR}/src/fptn-client")
  file(MAKE_DIRECTORY "${DISABLE_TIDY_DIR}")
  file(
    WRITE "${DISABLE_TIDY_DIR}/.clang-tidy"
    "Checks: '-*,readability-inconsistent-declaration-parameter-name'
WarningsAsErrors: ''
    ")

  find_package(
    Qt6 REQUIRED
    COMPONENTS Core
               Gui
               Widgets
               Network
               LinguistTools
               Concurrent
               CONFIG
    REQUIRED)
  set(CMAKE_AUTOMOC ON)
  set(CMAKE_AUTORCC ON)
  set(CMAKE_AUTOUIC ON)
  set(CMAKE_INCLUDE_CURRENT_DIR ON)

  qt_standard_project_setup()

  set(QRC_FILES gui/resources/resources.qrc)
  qt6_add_resources(PROJECT_RESOURCES ${QRC_FILES})

  set(QT_ADDITIONAL_PARAMS "")
  if(WIN32)
    set(QT_ADDITIONAL_PARAMS WIN32)
  endif()

  # translations
  file(GLOB TRANSLATIONS gui/resources/translations/*.ts)
  set_source_files_properties(${TRANSLATIONS} PROPERTIES OUTPUT_LOCATION "${CMAKE_CURRENT_SOURCE_DIR}/gui/resources/translations/")
  qt6_add_translation(TRANSLATIONS_OUT ${TRANSLATIONS})

  add_executable(
    "${PROJECT_NAME}-gui"
    ${QT_ADDITIONAL_PARAMS}
    fptn-client-gui.cpp
    vpn/vpn_client.h
    vpn/vpn_client.cpp
    http/client.h
    http/client.cpp
    routing/iptables.h
    routing/iptables.cpp
    config/config_file.cpp
    config/config_file.h
    gui/tray/tray.h
    gui/tray/tray.cpp
    gui/speedwidget/speedwidget.h
    gui/speedwidget/speedwidget.cpp
    gui/settingswidget/settings.h
    gui/settingswidget/settings.cpp
    gui/settingsmodel/settingsmodel.h
    gui/settingsmodel/settingsmodel.cpp
    gui/tokendialog/tokendialog.h
    gui/tokendialog/tokendialog.cpp
    gui/translations/translations.h
    gui/translations/translations.cpp
    gui/style/style.h
    gui/style/style.cpp
    gui/autostart/autostart.h
    gui/autoupdate/autoupdate.h
    gui/utils/windows/vpn_conflict.h
    ${PROJECT_RESOURCES}
    ${TRANSLATIONS_OUT})
  target_link_libraries(
    "${PROJECT_NAME}-gui"
    PRIVATE ZLIB::ZLIB
            Boost::boost
            Boost::random
            Boost::filesystem
            OpenSSL::SSL
            OpenSSL::Crypto
            argparse::argparse
            spdlog::spdlog
            fmt::fmt
            PcapPlusPlus::PcapPlusPlus
            Qt6::Core
            Qt6::Gui
            Qt6::Widgets
            Qt6::Network
            Qt6::Concurrent
            fptn-protocol-lib_static
            httplib::httplib
            "${TUNTAP_LIB}"
            "${PLATFORM_SPECIFIC_LIBS}")

  set_target_properties("${PROJECT_NAME}-gui" PROPERTIES AUTOMOC ON)
endif()
