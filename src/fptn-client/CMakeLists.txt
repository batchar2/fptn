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

find_package(httplib REQUIRED)
find_package(websocketpp REQUIRED)
find_package(nlohmann_json REQUIRED)

include_directories(${httplib_INCLUDE_DIRS})
include_directories(${websocketpp_INCLUDE_DIRS})
include_directories(${nlohmann_json_INCLUDE_DIRS})

#### fptn-client-cli
add_executable(
    "${PROJECT_NAME}-cli"
    fptn-client-cli.cpp
    vpn/vpn_client.h vpn/vpn_client.cpp
    http/websocket_client.h http/websocket_client.cpp
    system/iptables.h system/iptables.cpp
    config/config_file.cpp config/config_file.h
)
target_link_libraries(
    "${PROJECT_NAME}-cli"
    Boost::boost
    Boost::random
    Boost::filesystem

    OpenSSL::SSL
    OpenSSL::Crypto
    argparse::argparse
    websocketpp::websocketpp
    httplib::httplib
    nlohmann_json::nlohmann_json

    spdlog::spdlog
    fmt::fmt
    PcapPlusPlus::PcapPlusPlus
    hv_static
    fptn_protocol

    ${TUNTAP_LIB}
)


#### fptn-client-gui
if("${FPTN_BUILD_WITH_GUI_CLIENT}")
    find_package(Qt6 REQUIRED COMPONENTS Core Gui Widgets Network LinguistTools CONFIG REQUIRED)
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

    add_executable("${PROJECT_NAME}-gui" ${QT_ADDITIONAL_PARAMS}
        fptn-client-gui.cpp
        vpn/vpn_client.h vpn/vpn_client.cpp
        http/websocket_client.h http/websocket_client.cpp
        system/iptables.h system/iptables.cpp
        config/config_file.cpp config/config_file.h

        gui/tray/tray.h gui/tray/tray.cpp
        gui/speedwidget/speedwidget.h gui/speedwidget/speedwidget.cpp
        gui/settingswidget/settings.h gui/settingswidget/settings.cpp

        gui/settingsmodel/settingsmodel.h gui/settingsmodel/settingsmodel.cpp

        gui/style/style.h gui/style/style.cpp
        ${PROJECT_RESOURCES}
        ${TRANSLATIONS_OUT}
    )
    target_link_libraries(
        "${PROJECT_NAME}-gui"
        Boost::boost
        Boost::random
        Boost::filesystem

        OpenSSL::SSL
        OpenSSL::Crypto
        argparse::argparse
        websocketpp::websocketpp
        httplib::httplib

        spdlog::spdlog
        fmt::fmt
        PcapPlusPlus::PcapPlusPlus

        hv_static
        fptn_protocol

        Qt6::Core Qt6::Gui Qt6::Widgets Qt6::Network

        ${TUNTAP_LIB}
    )
    set_target_properties("${PROJECT_NAME}-gui" PROPERTIES AUTOMOC ON)
endif()
