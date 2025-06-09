cmake_minimum_required(VERSION 3.22.1)

project("fptn-proxy")

find_package(ZLIB CONFIG)
find_package(absl REQUIRED)
find_package(Protobuf REQUIRED)
find_package(OpenSSL REQUIRED)
find_package(argparse REQUIRED)
find_package(spdlog REQUIRED)
find_package(nlohmann_json REQUIRED)
find_package(fmt REQUIRED)
find_package(httplib REQUIRED)
find_package(PcapPlusPlus REQUIRED)
find_package(Boost REQUIRED COMPONENTS random filesystem)
find_package(ZLIB REQUIRED)
find_package(nlohmann_json REQUIRED)

message(STATUS "OpenSSL_FOUND: ${OpenSSL_FOUND}")
message(STATUS "OpenSSL_INCLUDE_DIR: ${OPENSSL_INCLUDE_DIR}")
message(STATUS "OpenSSL_LIBRARIES: ${OPENSSL_LIBRARIES}")
message(STATUS "OpenSSL_VERSION: ${OPENSSL_VERSION}")

#exit
#find_package(fptn CONFIG)
include_directories(src/)
include_directories(${OpenSSL_INCLUDE_DIR})

include_directories(fptn-project/src/)
include_directories(fptn-project/src/fptn-protocol-lib)
set(FPTN_BUILD_ONLY_FPTN_LIB ON CACHE INTERNAL "Build only FPTN lib")

add_subdirectory(fptn-project)   # FOR DOCKER

if(Protobuf_INCLUDE_DIRS)
  include_directories(${Protobuf_INCLUDE_DIRS})
endif()

add_executable(${CMAKE_PROJECT_NAME} src/proxy-server.cpp)

target_link_libraries(${CMAKE_PROJECT_NAME}
  ZLIB::ZLIB
  argparse::argparse
  httplib::httplib
  fptn-protocol-lib_static
)
