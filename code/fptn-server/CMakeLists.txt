project(fptn-server)

include_directories(${CMAKE_CURRENT_SOURCE_DIR})

find_package(Boost REQUIRED)
find_package(OpenSSL REQUIRED)
find_package(argparse REQUIRED)
find_package(glog REQUIRED)
find_package(fmt REQUIRED)
find_package(PcapPlusPlus REQUIRED)
find_package(nlohmann_json REQUIRED)
find_package(jwt-cpp REQUIRED)

add_executable("${PROJECT_NAME}"
    fptn-server.cpp
    nat/table.h nat/table.cpp
    client/session.h client/session.cpp
    network/virtual_interface.h network/virtual_interface.cpp
    traffic_shaper/leaky_bucket.h traffic_shaper/leaky_bucket.cpp
    system/iptables.h system/iptables.cpp
    web/server.h web/server.cpp 
    web/http/http_server.h web/http/http_server.cpp
    web/websocket/websocket_server.h web/websocket/websocket_server.cpp

    vpn/manager.h vpn/manager.cpp
)

target_link_libraries(
    "${PROJECT_NAME}"
    Boost::boost
    OpenSSL::SSL 
    OpenSSL::Crypto
    argparse::argparse

    nlohmann_json::nlohmann_json
    jwt-cpp::jwt-cpp

    glog::glog
    fmt::fmt
    PcapPlusPlus::PcapPlusPlus

    tuntap++
    hv_static

    fptn_protocol
)
