project(fptn-protocol-lib LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_INCLUDE_CURRENT_DIR ON)

include_directories(${CMAKE_CURRENT_SOURCE_DIR})

if(__ANDROID__)
  add_compile_definitions(FPTN_USER_OS=\"Android\")
elseif(APPLE)
  add_compile_definitions(FPTN_USER_OS=\"MacOS\")
elseif(WIN32)
  add_compile_definitions(FPTN_USER_OS=\"Windows\")
elseif(UNIX)
  add_compile_definitions(FPTN_USER_OS=\"Linux\")
else()
  message(FATAL_ERROR "Unsupported platform")
endif()

find_package(absl REQUIRED)
find_package(Protobuf REQUIRED)
find_package(OpenSSL REQUIRED)
find_package(argparse REQUIRED)
find_package(spdlog REQUIRED)
find_package(fmt REQUIRED)

find_package(Boost REQUIRED COMPONENTS random filesystem)
find_package(ZLIB REQUIRED)
find_package(nlohmann_json REQUIRED)

if(NOT FPTN_IP_ADDRESS_WITHOUT_PCAP)
  find_package(PcapPlusPlus REQUIRED)
endif()

include_directories(${nlohmann_json_INCLUDE_DIRS})

# include
if(ABSL_INCLUDE_DIRS)
  include_directories(${ABSL_INCLUDE_DIRS})
endif()
if(absl_INCLUDE_DIRS)
  include_directories(${absl_INCLUDE_DIRS})
endif()

if(PROTOBUF_INCLUDE_DIR)
  include_directories(${PROTOBUF_INCLUDE_DIR})
endif()
if(protobuf_INCLUDE_DIRS)
  include_directories(${protobuf_INCLUDE_DIRS})
endif()
if(Protobuf_INCLUDE_DIRS)
  include_directories(${Protobuf_INCLUDE_DIRS})
endif()
if(CONAN_INCLUDE_DIRS_PROTOBUF)
  include_directories(${CONAN_INCLUDE_DIRS_PROTOBUF})
endif()
include_directories(${SOURCE_DIR} ${INCLUDE_DIR} ${CMAKE_CURRENT_BINARY_DIR} ${CMAKE_CURRENT_BINARY_DIR}/fptn_protocol)
include_directories(${CMAKE_BINARY_DIR}/src/fptn-protocol-lib/protobuf)
include_directories("${CMAKE_CURRENT_BINARY_DIR}/protobuf")

# Generate C++ source and header files from the .proto files
set(protobuf_files protobuf/protocol.proto)
protobuf_generate_cpp(PROTO_SRCS PROTO_HDRS ${protobuf_files})

# --- disable clang-tidy for protobuf generated code ---
set_source_files_properties($<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}/protocol.pb.h> PROPERTIES SKIP_CLANG_TIDY ON)
set_source_files_properties($<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}/protocol.pb.сс> PROPERTIES SKIP_CLANG_TIDY ON)
set(DISABLE_TIDY_DIR "${CMAKE_BINARY_DIR}/src/fptn-protocol-lib/protobuf/")
file(MAKE_DIRECTORY "${DISABLE_TIDY_DIR}")
file(
  WRITE "${DISABLE_TIDY_DIR}/.clang-tidy"
  "Checks: '-*,readability-inconsistent-declaration-parameter-name'
WarningsAsErrors: ''
    ")

set(FPTN_CLIENT_PROTOCOL_SOURCES
    ${PROTO_SRCS}
    ${PROTO_HDRS}
    tls/tls.h
    tls/tls.cpp
    https/https_client.h
    https/https_client.cpp
    protobuf/protocol.h
    protobuf/protocol.cpp
    server/server_info.h
    server/speed_estimator.h
    server/speed_estimator.cpp
    websocket/websocket_client.h
    websocket/websocket_client.cpp
    time/time_provider.h
    time/time_provider.cpp)

add_library("${PROJECT_NAME}_static" STATIC ${FPTN_CLIENT_PROTOCOL_SOURCES})

foreach(target "${PROJECT_NAME}_static")
  if(FPTN_IP_ADDRESS_WITHOUT_PCAP)
    set(PCAP_LIB "")
  else()
    set(PCAP_LIB PcapPlusPlus::PcapPlusPlus)
  endif()
  if(MSVC)
    target_compile_options(${target} PRIVATE /wd4100 /wd4702) # disable warning C4100
  endif()
  target_include_directories(${target} INTERFACE ${CMAKE_CURRENT_BINARY_DIR} protobuf::protobuf)
  target_link_libraries(
    ${target}
    ${Protobuf_LIBRARIES}
    ${protobuf_LIBRARIES}
    protobuf::protobuf
    ZLIB::ZLIB
    Boost::boost
    Boost::random
    Boost::filesystem
    OpenSSL::SSL
    OpenSSL::Crypto
    nlohmann_json::nlohmann_json
    spdlog::spdlog
    fmt::fmt
    ntp_client
    ${PCAP_LIB}
  )
endforeach()
