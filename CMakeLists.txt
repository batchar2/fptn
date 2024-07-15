cmake_minimum_required(VERSION 3.22)
project(FOPN VERSION 0.1 LANGUAGES CXX)

set(CMAKE_INCLUDE_CURRENT_DIR ON)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_VERBOSE_MAKEFILE ON)

# add depends tuntap
add_subdirectory(depends/libs/libtuntap)
include_directories(depends/libs/libtuntap/)
include_directories(depends/libs/libtuntap/bindings/cpp)
link_directories(${CMAKE_BINARY_DIR}/depends/libs/libtuntap/lib)
# add depends libhv 
set(WITH_OPENSSL ON CACHE BOOL "with openssl library" FORCE)
set(BUILD_STATIC ON CACHE BOOL "with openssl library" FORCE)
set(BUILD_SHARED OFF CACHE BOOL "with openssl library" FORCE)
set(WITH_NGHTTP2 OFF CACHE BOOL "with nghttp2 library" FORCE)
set(BUILD_EXAMPLES OFF CACHE BOOL "build examples" FORCE)
include_directories(CMAKE_BINARY_DIR/depends/libs/libhv/include)
link_directories(${CMAKE_BINARY_DIR}/lib/)
add_subdirectory(depends/libs/libhv)

# include
include_directories(code/)
include_directories(depends/common/libs)

add_subdirectory(code/server)
add_subdirectory(code/client)
