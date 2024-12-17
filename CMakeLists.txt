cmake_minimum_required(VERSION 3.16)
project(fptn VERSION "${FPTN_VERSION}" LANGUAGES CXX)

set(FPTN_SERVER_PATH "${CMAKE_CURRENT_SOURCE_DIR}/src/fptn-server")

enable_testing()

# enable ssl for cpphttp-lib
add_compile_definitions(CPPHTTPLIB_OPENSSL_SUPPORT)

add_compile_definitions(FPTN_VERSION=\"${FPTN_VERSION}\")
add_compile_definitions(FPTN_MTU_SIZE=1500)
add_compile_definitions(FPTN_IP_PACKET_MAX_SIZE=1450)
add_compile_definitions(FPTN_ENABLE_PACKET_PADDING=1)
add_compile_definitions(FPTN_PROTOBUF_PROTOCOL_VERSION=0x01)

# cmake_policy(SET CMP0077 NEW)
set(CMAKE_INCLUDE_CURRENT_DIR ON)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_VERBOSE_MAKEFILE ON)
if(WIN32)
    set(CMAKE_WINDOWS_EXPORT_ALL_SYMBOLS TRUE)
endif()

# -- depends: tuntap  ---
if(APPLE OR UNIX)
    set(ENABLE_CXX ON CACHE BOOL "Enable C++ support" FORCE)
    set(BUILD_TESTING OFF CACHE BOOL "Disable testing globally" FORCE)
    set(ENABLE_PYTHON OFF CACHE BOOL "Disable Python support" FORCE)
    set(LIBTUNTAP_DISABLE_TESTS ON CACHE BOOL "Disable library tests" FORCE)
    add_subdirectory(depends/libs/libtuntap EXCLUDE_FROM_ALL)
    include_directories(depends/libs/libtuntap/)
    include_directories(depends/libs/libtuntap/bindings/cpp)
    link_directories(${CMAKE_BINARY_DIR}/depends/libs/libtuntap/lib)
elseif(WIN32)
    include(depends/cmake/wintun/wintun.cmake)
else()
    message(FATAL_ERROR "Unsupported platform")
endif()

# --- depends: libhv ---
find_package(OpenSSL REQUIRED)
include_directories(${OPENSSL_INCLUDE_DIR})
set(WITH_OPENSSL ON CACHE BOOL "with openssl library" FORCE)
set(BUILD_STATIC ON CACHE BOOL "with openssl library" FORCE)
set(BUILD_SHARED OFF CACHE BOOL "with openssl library" FORCE)
set(WITH_NGHTTP2 OFF CACHE BOOL "with nghttp2 library" FORCE)
set(BUILD_EXAMPLES OFF CACHE BOOL "build examples" FORCE)
include_directories(CMAKE_BINARY_DIR/depends/libs/libhv/include)
link_directories(${CMAKE_BINARY_DIR}/lib/)
add_subdirectory(depends/libs/libhv EXCLUDE_FROM_ALL)

# --- protobuf ---
include_directories(${CMAKE_BINARY_DIR}/depends/protobuf/fptn_protocol/)
add_subdirectory(depends/protobuf)


# --- include ---
include_directories(src/)
include_directories(depends/)

# --- project ---
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
if(CMAKE_SYSTEM_NAME STREQUAL "Linux")  # deb
    add_custom_target(build-deb
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        COMMAND bash -c "\
            ${CMAKE_CURRENT_SOURCE_DIR}/deploy/linux/deb/create-client-cli-deb-package.sh ${CMAKE_BINARY_DIR}/src/fptn-client/fptn-client-cli ${FPTN_VERSION}; \
            ${CMAKE_CURRENT_SOURCE_DIR}/deploy/linux/deb/create-server-deb-package.sh ${CMAKE_BINARY_DIR}/src/fptn-server/fptn-server ${CMAKE_BINARY_DIR}/src/fptn-passwd/fptn-passwd ${FPTN_VERSION} \
        "
        COMMENT "Building .deb package"
        VERBATIM
    )
    if("${FPTN_BUILD_WITH_GUI_CLIENT}")
        add_custom_target(build-deb-gui
                WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
                COMMAND bash -c "\
                ${CMAKE_CURRENT_SOURCE_DIR}/deploy/linux/deb/create-client-gui-deb-package.sh ${CMAKE_BINARY_DIR}/src/fptn-client/fptn-client-gui ${CMAKE_CURRENT_SOURCE_DIR}/deploy/linux/deb/assets/FptnClient512x512.png ${FPTN_VERSION} \
            "
                COMMENT "Building .deb package"
                VERBATIM
        )
    endif()
elseif(CMAKE_SYSTEM_NAME STREQUAL "Darwin") # MacOS
    if("${FPTN_BUILD_WITH_GUI_CLIENT}")
        add_custom_target(build-pkg
            WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
            COMMAND bash -c "${CMAKE_CURRENT_SOURCE_DIR}/deploy/macos/create-pkg.py --fptn-client-cli=${CMAKE_BINARY_DIR}/src/fptn-client/fptn-client-cli --fptn-client-gui=${CMAKE_BINARY_DIR}/src/fptn-client/fptn-client-gui  --version=${FPTN_VERSION}"
            COMMENT "Building .dmg package"
            VERBATIM
        )
    endif()
elseif(WIN32)
    if("${FPTN_BUILD_WITH_GUI_CLIENT}")
        add_custom_target(build-installer
            WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
            COMMAND ${CMAKE_COMMAND} -E echo "Building installer for Windows..."
            COMMAND python ${CMAKE_CURRENT_SOURCE_DIR}/deploy/windows/create-installer.py
                    --wintun-dll=${CMAKE_BINARY_DIR}/wintun/wintun.dll
                    --fptn-client=${CMAKE_BINARY_DIR}/src/fptn-client/Release/fptn-client-gui.exe
                    --fptn-client-cli=${CMAKE_BINARY_DIR}/src/fptn-client/Release/fptn-client-cli.exe
                    --output-folder=${CMAKE_CURRENT_SOURCE_DIR}
                    --version=${FPTN_VERSION}
            COMMENT "Building .exe installer"
            VERBATIM
        )
    endif()
else()
    message(FATAL_ERROR "Unsupported platform")
endif()

# --- tests ---
add_subdirectory(tests)
