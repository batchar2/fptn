project(fptn-client)

include_directories(${CMAKE_CURRENT_SOURCE_DIR})

find_package(Boost REQUIRED)
find_package(OpenSSL REQUIRED)
find_package(argparse REQUIRED)
find_package(glog REQUIRED)
find_package(fmt REQUIRED)
find_package(PcapPlusPlus REQUIRED)

add_executable(
    "${PROJECT_NAME}-cli"
    fptn-client-cli.cpp
    vpn/vpn_client.h vpn/vpn_client.cpp
    http/websocket_client.h http/websocket_client.cpp
    system/iptables.h system/iptables.cpp
)

target_link_libraries(
    "${PROJECT_NAME}-cli"
    Boost::boost
    OpenSSL::SSL 
    OpenSSL::Crypto
    argparse::argparse

    glog::glog
    fmt::fmt
    PcapPlusPlus::PcapPlusPlus
    
    tuntap++
    hv_static
    fptn_protocol
)

#### part 2
if("${FPTN_BUILD_WITH_GUI_CLIENT}")
    find_package(Qt6 COMPONENTS Core Gui Widgets  CONFIG REQUIRED)
    # Svg
    set(CMAKE_AUTOMOC ON)
    set(CMAKE_AUTORCC ON)
    set(CMAKE_AUTOUIC ON)
    set(CMAKE_INCLUDE_CURRENT_DIR ON)

    set(QRC_FILES gui/resources/resources.qrc)
    qt6_add_resources(RESOURCES ${QRC_FILES})

    add_executable("${PROJECT_NAME}-gui"
        fptn-client-gui.cpp

        vpn/vpn_client.h vpn/vpn_client.cpp
        http/websocket_client.h http/websocket_client.cpp
        system/iptables.h system/iptables.cpp
        
        gui/tray/tray.h gui/tray/tray.cpp
        gui/speedwidget/speedwidget.h gui/speedwidget/speedwidget.cpp
        ${QRC_FILES}
    )

    target_link_libraries(
        "${PROJECT_NAME}-gui"
        Boost::boost
        OpenSSL::SSL 
        OpenSSL::Crypto
        argparse::argparse

        glog::glog
        websocketpp::websocketpp
        fmt::fmt
        PcapPlusPlus::PcapPlusPlus
        
        tuntap++
        hv_static
        fptn_protocol

        Qt6::Core Qt6::Gui Qt6::Widgets 
        #Qt6::Svg
    )
endif()
