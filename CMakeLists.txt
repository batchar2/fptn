cmake_minimum_required(VERSION 3.16)
project(fptn VERSION "${FPTN_VERSION}" LANGUAGES CXX)

add_compile_definitions(FPTN_VERSION=\"${FPTN_VERSION}\")

enable_testing()

# cmake_policy(SET CMP0077 NEW)
set(CMAKE_INCLUDE_CURRENT_DIR ON)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_VERBOSE_MAKEFILE ON)

# -- depends: tuntap  ---
set(ENABLE_CXX ON CACHE BOOL "Enable C++ support" FORCE)
set(BUILD_TESTING OFF CACHE BOOL "Disable testing globally" FORCE)
set(ENABLE_PYTHON OFF CACHE BOOL "Disable Python support" FORCE)
set(LIBTUNTAP_DISABLE_TESTS ON CACHE BOOL "Disable library tests" FORCE)
add_subdirectory(depends/libs/libtuntap EXCLUDE_FROM_ALL)
include_directories(depends/libs/libtuntap/)
include_directories(depends/libs/libtuntap/bindings/cpp)
link_directories(${CMAKE_BINARY_DIR}/depends/libs/libtuntap/lib)

# --- depends: libhv ---
set(WITH_OPENSSL ON CACHE BOOL "with openssl library" FORCE)
set(BUILD_STATIC ON CACHE BOOL "with openssl library" FORCE)
set(BUILD_SHARED OFF CACHE BOOL "with openssl library" FORCE)
set(WITH_NGHTTP2 OFF CACHE BOOL "with nghttp2 library" FORCE)
set(BUILD_EXAMPLES OFF CACHE BOOL "build examples" FORCE)
include_directories(CMAKE_BINARY_DIR/depends/libs/libhv/include)
link_directories(${CMAKE_BINARY_DIR}/lib/)
add_subdirectory(depends/libs/libhv EXCLUDE_FROM_ALL)

# --- include ---
include_directories(src/)
include_directories(depends/)

# --- project ---
add_subdirectory(depends/protobuf/fptn_protocol)
if(APPLE OR UNIX)
    add_subdirectory(src/fptn-server)
    add_subdirectory(src/fptn-passwd)
endif()
add_subdirectory(src/fptn-client)

# --- tests ---
add_subdirectory(tests)

# --- install ---
install(TARGETS fptn-client-cli DESTINATION bin)
if(APPLE OR UNIX)
    install(TARGETS fptn-server DESTINATION bin)
    install(TARGETS fptn-passwd DESTINATION bin)
endif()

# --- packaging ---
if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    # deb
    add_custom_target(build-deb
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        COMMAND bash -c "\
            ${CMAKE_CURRENT_SOURCE_DIR}/deploy/linux/deb/create-client-cli-deb-package.sh ${CMAKE_BINARY_DIR}/src/fptn-client/fptn-client-cli ${FPTN_VERSION}; \
            ${CMAKE_CURRENT_SOURCE_DIR}/deploy/linux/deb/create-server-deb-package.sh ${CMAKE_BINARY_DIR}/src/fptn-server/fptn-server ${CMAKE_BINARY_DIR}/src/fptn-passwd/fptn-passwd ${FPTN_VERSION} \
        "
        COMMENT "Building .deb package"
        VERBATIM
    )
    add_custom_target(build-deb-gui
            WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
            COMMAND bash -c "\
            ${CMAKE_CURRENT_SOURCE_DIR}/deploy/linux/deb/create-client-gui-deb-package.sh ${CMAKE_BINARY_DIR}/src/fptn-client/fptn-client-gui ${CMAKE_CURRENT_SOURCE_DIR}/deploy/linux/deb/assets/FptnClient512x512.png ${FPTN_VERSION} \
        "
            COMMENT "Building .deb package"
            VERBATIM
    )
elseif(CMAKE_SYSTEM_NAME STREQUAL "Darwin")
    if("${FPTN_BUILD_WITH_GUI_CLIENT}")
        # macOS
        add_custom_target(build-pkg
            WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
            COMMAND bash -c "${CMAKE_CURRENT_SOURCE_DIR}/deploy/macos/fptn-client-dmg/create-pkg.py --fptn-client-cli=${CMAKE_BINARY_DIR}/src/fptn-client/fptn-client-cli --fptn-client-gui=${CMAKE_BINARY_DIR}/src/fptn-client/fptn-client-gui  --version=${FPTN_VERSION}"
            COMMENT "Building .dmg package"
            VERBATIM
        )
    endif()
else()
    # message(FATAL_ERROR "Unsupported platform")
endif()
