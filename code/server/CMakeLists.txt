project(fptn-server)

include_directories(${CMAKE_CURRENT_SOURCE_DIR})

find_package(Boost REQUIRED)
find_package(OpenSSL REQUIRED)
find_package(argparse REQUIRED)
find_package(glog REQUIRED)
find_package(websocketpp REQUIRED)
find_package(fmt REQUIRED)
find_package(PcapPlusPlus REQUIRED)

add_executable("${PROJECT_NAME}"
        fptn-server.cpp
        web/server.h web/server.cpp
        web/http/http.h web/http/http.cpp
        web/websocket/websocket.h web/websocket/websocket.cpp
        nat/nat.h nat/nat.cpp
        nat/client_session/client_session.h nat/client_session/client_session.cpp
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
