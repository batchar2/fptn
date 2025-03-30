project(fptn-server)

include_directories(${CMAKE_CURRENT_SOURCE_DIR})
include_directories("${CMAKE_CURRENT_BINARY_DIR}/depends/protobuf/fptn_protocol/")

if(APPLE)
    set(CMAKE_CXX_STANDARD 20)
else()
    add_definitions(-DBOOST_ASIO_HAS_CO_AWAIT)
    add_definitions(-DBOOST_ASIO_HAS_CO_SPAWN)
    add_definitions(-DBOOST_ASIO_HAS_COROUTINES)
    set(CMAKE_CXX_STANDARD 20)
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fcoroutines")
endif()

find_package(Boost 1.83 REQUIRED COMPONENTS asio coroutines future)
find_package(ZLIB REQUIRED)
find_package(OpenSSL REQUIRED)
find_package(argparse REQUIRED)
find_package(spdlog REQUIRED)
find_package(fmt REQUIRED)
find_package(PcapPlusPlus REQUIRED)
find_package(nlohmann_json REQUIRED)
find_package(jwt-cpp REQUIRED)
find_package(prometheus-cpp REQUIRED)

# Include Boost directory
include_directories(${Boost_INCLUDE_DIRS})

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
    ZLIB::ZLIB
    Boost::boost
    OpenSSL::SSL 
    OpenSSL::Crypto
    argparse::argparse

    nlohmann_json::nlohmann_json
    jwt-cpp::jwt-cpp

    spdlog::spdlog
    fmt::fmt
    PcapPlusPlus::PcapPlusPlus

    tuntap++

    fptn_protocol
    prometheus-cpp::prometheus-cpp
)