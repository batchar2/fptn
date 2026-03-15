cmake_minimum_required(VERSION 3.22.1)
project("fptn-proxy")

add_executable(${CMAKE_PROJECT_NAME} src/proxy-server.cpp)

set_target_properties(
        ${CMAKE_PROJECT_NAME}
        PROPERTIES
        CXX_STANDARD 20
        CXX_STANDARD_REQUIRED ON
        CXX_EXTENSIONS OFF
)

# Rest of your CMake code...
add_definitions(-DBOOST_PROCESS_V2_HEADER_ONLY)
add_definitions(-DBOOST_ASIO_HAS_CO_AWAIT)
add_definitions(-DBOOST_ASIO_HAS_CO_SPAWN)
add_definitions(-DBOOST_ASIO_HAS_COROUTINES)

set(CMAKE_INCLUDE_CURRENT_DIR ON)

if (CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wno-unused-command-line-argument")
endif ()

find_package(fptn REQUIRED)
find_package(nlohmann_json REQUIRED)
find_package(fmt REQUIRED)
find_package(httplib REQUIRED)
find_package(argparse REQUIRED)
find_package(protobuf REQUIRED)
find_package(absl REQUIRED)
find_package(re2 REQUIRED)
find_package(spdlog REQUIRED)
find_package(OpenSSL REQUIRED)

message(STATUS "fptn_FOUND: ${fptn_FOUND}")
message(STATUS "fptn_INCLUDE_DIRS: ${fptn_INCLUDE_DIRS}")
message(STATUS "fptn_LIBRARIES: ${fptn_LIBRARIES}")

# disable pcap++
target_compile_definitions(${CMAKE_PROJECT_NAME} PRIVATE
        FPTN_IP_ADDRESS_WITHOUT_PCAP
)

target_include_directories(${CMAKE_PROJECT_NAME} PRIVATE
        src/
        "${CMAKE_CURRENT_SOURCE_DIR}/libs/fptn/src/"
        "${CMAKE_CURRENT_SOURCE_DIR}/libs/fptn/src/fptn-protocol-lib/"
)
target_include_directories(${CMAKE_PROJECT_NAME} PRIVATE
        ${fptn_INCLUDE_DIRS}
        ${CMAKE_CURRENT_SOURCE_DIR}/src
)

target_link_libraries(${CMAKE_PROJECT_NAME} PRIVATE
        fptn::fptn
        argparse::argparse
        httplib::httplib
        nlohmann_json::nlohmann_json
        fmt::fmt
        protobuf::libprotobuf
        re2::re2
        spdlog::spdlog
        OpenSSL::SSL
        OpenSSL::Crypto
        pthread
        dl
        rt
)

if(APPLE)
  target_link_options(${CMAKE_PROJECT_NAME} PRIVATE
          -framework CoreFoundation
          -framework Security
          -framework SystemConfiguration
  )
endif()
