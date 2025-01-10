cmake_minimum_required(VERSION 3.16)

# Find OpenSSL
find_package(OpenSSL REQUIRED)
include_directories(${OPENSSL_INCLUDE_DIR})

# libhv options
set(WITH_OPENSSL ON CACHE BOOL "with openssl library" FORCE)
set(BUILD_STATIC ON CACHE BOOL "build static library" FORCE)
set(BUILD_SHARED OFF CACHE BOOL "do not build shared library" FORCE)
set(WITH_NGHTTP2 OFF CACHE BOOL "do not use nghttp2" FORCE)
set(BUILD_EXAMPLES OFF CACHE BOOL "do not build examples" FORCE)


include(FetchContent)
FetchContent_Declare(Libhv URL https://github.com/ithewei/libhv/archive/refs/tags/v1.3.3.zip)
FetchContent_GetProperties(Libhv)
if (NOT Libhv_POPULATED)
    FetchContent_Populate(Libhv)
endif()

set(Libhv_SOURCE_DIR "${CMAKE_BINARY_DIR}/_deps/libhv-src")
set(Libhv_BINARY_DIR "${CMAKE_BINARY_DIR}/_deps/libhv-build")
set(Libhv_INCLUDE_DIR "${Libhv_BINARY_DIR}/include")

add_subdirectory("${Libhv_SOURCE_DIR}" "${Libhv_BINARY_DIR}" EXCLUDE_FROM_ALL)

include_directories("{Libhv_INCLUDE_DIR}")

# path
link_directories(${CMAKE_BINARY_DIR}/lib/)
