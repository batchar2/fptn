project(fptn-server)

include_directories(${CMAKE_CURRENT_SOURCE_DIR})
include_directories("${CMAKE_CURRENT_BINARY_DIR}/depends/protobuf/fptn_protocol/")

find_package(Boost REQUIRED)
find_package(OpenSSL REQUIRED)
find_package(argparse REQUIRED)
find_package(spdlog REQUIRED)
find_package(fmt REQUIRED)
find_package(PcapPlusPlus REQUIRED)
find_package(nlohmann_json REQUIRED)
find_package(jwt-cpp REQUIRED)
find_package(prometheus-cpp REQUIRED)
find_package(httplib REQUIRED)

add_executable("${PROJECT_NAME}"
    fptn-server.cpp
    nat/table.h nat/table.cpp
    client/session.h client/session.cpp
    network/virtual_interface.h network/virtual_interface.cpp
    traffic_shaper/leaky_bucket.h traffic_shaper/leaky_bucket.cpp
    system/iptables.h system/iptables.cpp

    web/listener/listener.h web/listener/listener.cpp
    web/session/session.h web/session/session.cpp
    web/server.h web/server.cpp

    filter/manager.h filter/manager.cpp
    filter/packets/base.h
    filter/packets/antiscan/antiscan.h filter/packets/antiscan/antiscan.cpp
    filter/packets/bittorrent/bittorrent.h filter/packets/bittorrent/bittorrent.cpp
    vpn/manager.h vpn/manager.cpp

    statistic/metrics.h statistic/metrics.cpp
    cmd/cmd_option.cpp cmd/cmd_option.h
    user/user_manager.cpp user/user_manager.h
)

target_link_libraries(
    "${PROJECT_NAME}"
    Boost::boost
    OpenSSL::SSL 
    OpenSSL::Crypto
    argparse::argparse

    nlohmann_json::nlohmann_json
    jwt-cpp::jwt-cpp

    spdlog::spdlog
    fmt::fmt
    PcapPlusPlus::PcapPlusPlus
    httplib::httplib

    tuntap++
    hv_static

    fptn_protocol
    prometheus-cpp::prometheus-cpp
)
