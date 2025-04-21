cmake_minimum_required(VERSION 3.16)

FetchContent_Declare(Boringssl URL https://github.com/google/boringssl/archive/refs/tags/0.20250415.0.zip)
FetchContent_GetProperties(Boringssl)
#if(NOT Boringssl_POPULATED)
#    FetchContent_Populate(Boringssl)
#endif()
#FetchContent_GetProperties(boringssl)
#if(NOT boringssl_POPULATED)
#    FetchContent_MakeAvailable(boringssl)
#endif()
#add_library(Boringssl)

#set(BORINGSSL_SOURCE_DIR "${FETCHCONTENT_BASE_DIR}/boringssl-src")
#set(BORINGSSL_BUILD_DIR "${CMAKE_CURRENT_BINARY_DIR}/_deps/boringssl-build")
#set(BORINGSSL_INSTALL_DIR "${BORINGSSL_SOURCE_DIR}/install")


#if(NOT EXISTS "${BORINGSSL_INSTALL_DIR}")
#    execute_process(COMMAND "${CMAKE_COMMAND}"
#            "-DCMAKE_TOOLCHAIN_FILE=${CMAKE_TOOLCHAIN_FILE}"
#            "-DCMAKE_BUILD_TYPE=${CMAKE_BUILD_TYPE}"
##            "-DANDROID_ABI=${ANDROID_ABI}"
##            "-DANDROID_PLATFORM=android-29"
#            "-DOPENSSL_SMALL=ON"
#            "-GNinja"
#            "-S" "${BORINGSSL_SOURCE_DIR}"
#            "-B" "${BORINGSSL_BUILD_DIR}"
#    )
#    execute_process(COMMAND "${CMAKE_COMMAND}"
#            "--build"
#            "${BORINGSSL_BUILD_DIR}"
#            "--target" "crypto" "ssl" "install"
#    )
#endif()


#include(FetchContent)
#FetchContent_Declare(Boringssl URL https://github.com/google/boringssl/archive/refs/tags/0.20250415.0.zip)
#FetchContent_GetProperties(Boringssl)
#if(NOT Boringssl_POPULATED)
#    FetchContent_Populate(Boringssl)
#endif()
#
#set(Boringssl_SOURCE_DIR "${CMAKE_BINARY_DIR}/_deps/boringssl-src")
#set(Boringssl_BINARY_DIR "${CMAKE_BINARY_DIR}/_deps/boringssl-build")
#set(Boringssl_INCLUDE_DIR "${Boringssl_BINARY_DIR}/include")
#
#add_subdirectory("${Boringssl_SOURCE_DIR}" "${Boringssl_BINARY_DIR}" EXCLUDE_FROM_ALL)

#include_directories("${Boringssl_SOURCE_DIR}/libtuntap/")
#include_directories("${Boringssl_SOURCE_DIR}/libtuntap/bindings/cpp")

#link_directories("${Boringssl_BINARY_DIR}/lib/")
