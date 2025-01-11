cmake_minimum_required(VERSION 3.16)

# Find OpenSSL
find_package(OpenSSL REQUIRED)
include_directories(${OPENSSL_INCLUDE_DIR})

# libhv options
set(ENABLE_CXX ON CACHE BOOL "Enable C++ support" FORCE)
set(BUILD_TESTING OFF CACHE BOOL "Disable testing globally" FORCE)
set(ENABLE_PYTHON OFF CACHE BOOL "Disable Python support" FORCE)
set(LIBTUNTAP_DISABLE_TESTS ON CACHE BOOL "Disable library tests" FORCE)

include(FetchContent)
FetchContent_Declare(Libtuntap URL https://github.com/LaKabane/libtuntap/archive/refs/heads/master.zip)
FetchContent_GetProperties(Libtuntap)
if (NOT Libtuntap_POPULATED)
    FetchContent_Populate(Libtuntap)
endif()

set(Libtuntap_SOURCE_DIR "${CMAKE_BINARY_DIR}/_deps/libtuntap-src")
set(Libtuntap_BINARY_DIR "${CMAKE_BINARY_DIR}/_deps/libtuntap-build")
set(Libtuntap_INCLUDE_DIR "${Libtuntap_BINARY_DIR}/include")

add_subdirectory("${Libtuntap_SOURCE_DIR}" "${Libtuntap_BINARY_DIR}" EXCLUDE_FROM_ALL)

include_directories("${Libtuntap_SOURCE_DIR}/libtuntap/")
include_directories("${Libtuntap_SOURCE_DIR}/libtuntap/bindings/cpp")

link_directories("${Libtuntap_BINARY_DIR}/lib/")

