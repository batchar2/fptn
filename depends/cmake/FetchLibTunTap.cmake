cmake_minimum_required(VERSION 3.16)

include(FetchContent)
FetchContent_Declare(Libtuntap URL https://github.com/LaKabane/libtuntap/archive/ec1213733eb2e66e033ff8864d9fd476f9e35ffe.zip)
FetchContent_GetProperties(Libtuntap)
if(NOT Libtuntap_POPULATED)
  FetchContent_Populate(Libtuntap)
endif()

set(Libtuntap_SOURCE_DIR "${CMAKE_BINARY_DIR}/_deps/libtuntap-src")
set(Libtuntap_BINARY_DIR "${CMAKE_BINARY_DIR}/_deps/libtuntap-build")
set(Libtuntap_INCLUDE_DIR "${Libtuntap_BINARY_DIR}/include")

add_subdirectory("${Libtuntap_SOURCE_DIR}" "${Libtuntap_BINARY_DIR}" EXCLUDE_FROM_ALL)
include_directories("${Libtuntap_SOURCE_DIR}/libtuntap/")
include_directories("${Libtuntap_SOURCE_DIR}/libtuntap/bindings/cpp")

link_directories("${Libtuntap_BINARY_DIR}/lib/")
