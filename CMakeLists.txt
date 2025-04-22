cmake_minimum_required(VERSION 3.16)
project(
  fptn
  VERSION "${FPTN_VERSION}"
  LANGUAGES CXX)

set(FPTN_SERVER_PATH "${CMAKE_CURRENT_SOURCE_DIR}/src/fptn-server")

enable_testing()

# project
add_compile_definitions(FPTN_VERSION=\"${FPTN_VERSION}\")
add_compile_definitions(FPTN_MTU_SIZE=1500)
add_compile_definitions(FPTN_DEFAULT_SNI=\"tv.telecom.kz\")
add_compile_definitions(FPTN_IP_PACKET_MAX_SIZE=1450)
add_compile_definitions(FPTN_ENABLE_PACKET_PADDING=1)
add_compile_definitions(FPTN_PROTOBUF_PROTOCOL_VERSION=0x01)
# client
add_compile_definitions(FPTN_CLIENT_DEFAULT_ADDRESS_IP6=\"fd00::1\")
add_compile_definitions(FPTN_CLIENT_DEFAULT_ADDRESS_IP4=\"10.0.0.1\")
# server
add_compile_definitions(FPTN_SERVER_DEFAULT_ADDRESS_IP6=\"fc00:1::1\")
add_compile_definitions(FPTN_SERVER_DEFAULT_NET_ADDRESS_IP6=\"fc00:1::\")
add_compile_definitions(FPTN_SERVER_DEFAULT_ADDRESS_IP4=\"172.20.0.1\")
add_compile_definitions(FPTN_SERVER_DEFAULT_NET_ADDRESS_IP4=\"172.20.0.0\")
# github
add_compile_definitions(FPTN_GITHUB_USERNAME=\"batchar2\")
add_compile_definitions(FPTN_GITHUB_REPOSITORY=\"fptn\")
add_compile_definitions(FPTN_GITHUB_PAGE_LINK=\"https://batchar2.github.io/fptn/\")
# SSL
#add_compile_definitions(BOOST_ASIO_USE_BORINGSSL)
#add_compile_definitions(OPENSSL_IS_BORINGSSL)
#add_definitions(-DBOOST_ASIO_USE_BORINGSSL)
add_compile_definitions(BOOST_IOSTREAMS_USE_BZIP2)
add_compile_definitions(BOOST_IOSTREAMS_USE_ZLIB)

# cmake_policy(SET CMP0077 NEW)
set(CMAKE_INCLUDE_CURRENT_DIR ON)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# -- depends: tuntap  ---
if(APPLE OR UNIX)
  include(depends/cmake/FetchLibTunTap.cmake)
elseif(WIN32)
  include(depends/cmake/FetchWintun.cmake)
else()
  message(FATAL_ERROR "Unsupported platform")
endif()

# --- depends: base64 ---
include(depends/cmake/FetchBase64.cmake)

# --- protobuf ---
include_directories(${CMAKE_BINARY_DIR}/depends/protobuf/fptn_protocol/)
add_subdirectory(depends/protobuf)

# --- include ---
include_directories(src/)
include_directories(depends/)

# --- project ---
set(CMAKE_COMPILE_WARNING_AS_ERROR ON) # check all warnings!
if(MSVC)
  set(CMAKE_WINDOWS_EXPORT_ALL_SYMBOLS TRUE)
  add_compile_options(/W4 /WX)
  # target_compile_options("/wd4996")  # Disable warning
else()
  add_compile_options(-Wall -Werror)
endif()

# --- clang-tidy setup ---
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
# search clang-tidy
find_program(
  CLANG_TIDY_EXE
  NAMES clang-tidy-22
        clang-tidy-21
        clang-tidy-20
        clang-tidy-19
        clang-tidy-18
        clang-tidy-17
        clang-tidy-16
        clang-tidy-15
        clang-tidy)
if(CLANG_TIDY_EXE)
  execute_process(
    COMMAND ${CLANG_TIDY_EXE} --version
    OUTPUT_VARIABLE CLANG_TIDY_VERSION_STRING
    OUTPUT_STRIP_TRAILING_WHITESPACE)
  message(STATUS "[CLANG-TIDY] clang-tidy version: ${CLANG_TIDY_VERSION_STRING}")
  if(CLANG_TIDY_VERSION_STRING MATCHES "version ([0-9]+)")
    set(CLANG_TIDY_VERSION ${CMAKE_MATCH_1})
    if(CLANG_TIDY_VERSION GREATER_EQUAL 20)
      message(STATUS "[CLANG-TIDY]  clang-tidy ${CLANG_TIDY_VERSION} accepted, enabling")
      set(CMAKE_CXX_CLANG_TIDY "${CLANG_TIDY_EXE};-extra-arg=-std=c++20")
    else()
      message(WARNING "[CLANG-TIDY]  clang-tidy version ${CLANG_TIDY_VERSION} is too old (<15), disabling")
    endif()
  else()
    message(WARNING "[CLANG-TIDY]  Could not parse clang-tidy version, disabling")
  endif()
else()
  message(WARNING "[CLANG-TIDY]  clang-tidy not found, skipping clang-tidy checks.")
endif()

if(APPLE OR UNIX)
  add_subdirectory(src/fptn-server)
  add_subdirectory(src/fptn-passwd)
endif()
add_subdirectory(src/fptn-client)

# --- install ---
install(TARGETS fptn-client-cli DESTINATION bin)
if(APPLE OR UNIX)
  install(TARGETS fptn-server DESTINATION bin)
  install(TARGETS fptn-passwd DESTINATION bin)
endif()

# --- packaging ---
if(CMAKE_SYSTEM_NAME STREQUAL "Linux") # deb
  add_custom_target(
    build-deb
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
    COMMAND
      bash -c
      "${CMAKE_CURRENT_SOURCE_DIR}/deploy/linux/deb/create-client-cli-deb-package.sh ${CMAKE_BINARY_DIR}/src/fptn-client/fptn-client-cli ${FPTN_VERSION}; ${CMAKE_CURRENT_SOURCE_DIR}/deploy/linux/deb/create-server-deb-package.sh ${CMAKE_BINARY_DIR}/src/fptn-server/fptn-server ${CMAKE_BINARY_DIR}/src/fptn-passwd/fptn-passwd ${FPTN_VERSION}"
    COMMENT "Building .deb package"
    VERBATIM)
  if("${FPTN_BUILD_WITH_GUI_CLIENT}")
    add_custom_target(
      build-deb-gui
      WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
      COMMAND
        bash -c
        "${CMAKE_CURRENT_SOURCE_DIR}/deploy/linux/deb/create-client-gui-deb-package.sh ${CMAKE_BINARY_DIR}/src/fptn-client/fptn-client-gui ${CMAKE_CURRENT_SOURCE_DIR}/deploy/linux/deb/assets/FptnClient512x512.png ${FPTN_VERSION}"
      COMMENT "Building .deb package"
      VERBATIM)
  endif()
elseif(CMAKE_SYSTEM_NAME STREQUAL "Darwin") # MacOS
  if("${FPTN_BUILD_WITH_GUI_CLIENT}")
    add_custom_target(
      build-pkg
      WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
      COMMAND
        bash -c
        "${CMAKE_CURRENT_SOURCE_DIR}/deploy/macos/create-pkg.py --fptn-client-cli=${CMAKE_BINARY_DIR}/src/fptn-client/fptn-client-cli --fptn-client-gui=${CMAKE_BINARY_DIR}/src/fptn-client/fptn-client-gui  --version=${FPTN_VERSION}"
      COMMENT "Building .dmg package"
      VERBATIM)
  endif()
elseif(WIN32)
  if("${FPTN_BUILD_WITH_GUI_CLIENT}")
    add_custom_target(
      build-installer
      WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
      COMMAND ${CMAKE_COMMAND} -E echo "Building installer for Windows..."
      COMMAND
        python ${CMAKE_CURRENT_SOURCE_DIR}/deploy/windows/create-installer.py --wintun-dll=${CMAKE_BINARY_DIR}/wintun/wintun.dll
        --fptn-client=${CMAKE_BINARY_DIR}/src/fptn-client/Release/fptn-client-gui.exe
        --fptn-client-cli=${CMAKE_BINARY_DIR}/src/fptn-client/Release/fptn-client-cli.exe --output-folder=${CMAKE_CURRENT_SOURCE_DIR}
        --version=${FPTN_VERSION}
      COMMENT "Building .exe installer"
      VERBATIM)
  endif()
else()
  message(FATAL_ERROR "Unsupported platform")
endif()

# --- tests ---
add_subdirectory(tests)
