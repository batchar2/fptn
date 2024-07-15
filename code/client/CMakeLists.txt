project(fptn-client)

include_directories(${CMAKE_CURRENT_SOURCE_DIR})

find_package(Boost REQUIRED)
find_package(OpenSSL REQUIRED)
find_package(argparse REQUIRED)
find_package(glog REQUIRED)
find_package(websocketpp REQUIRED)
find_package(fmt REQUIRED)
find_package(PcapPlusPlus REQUIRED)

add_executable("${PROJECT_NAME}"
        fptn-client.cpp
        websocket/client.h websocket/client.cpp
)

target_link_libraries(
    "${PROJECT_NAME}"
    Boost::boost
    OpenSSL::SSL 
    OpenSSL::Crypto
    argparse::argparse

    glog::glog
    websocketpp::websocketpp
    fmt::fmt
    PcapPlusPlus::PcapPlusPlus
    
    tuntap
    tuntap++
    hv_static
)
