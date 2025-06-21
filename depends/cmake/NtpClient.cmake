include(FetchContent)
FetchContent_Declare(ntp_client URL https://github.com/batchar2/NTP-client/archive/refs/heads/master.zip)
FetchContent_GetProperties(ntp_client)
if(NOT ntp_client_POPULATED)
    FetchContent_Populate(ntp_client)
endif()

set(ntp_client_SOURCE_DIR "${CMAKE_BINARY_DIR}/_deps/ntp_client-src")
set(ntp_client_BINARY_DIR "${CMAKE_BINARY_DIR}/_deps/ntp_client-build")
set(ntp_client_INCLUDE_DIR "${ntp_client_SOURCE_DIR}/include")

add_subdirectory("${ntp_client_SOURCE_DIR}" "${Libtuntap_BINARY_DIR}" EXCLUDE_FROM_ALL)
include_directories("${ntp_client_SOURCE_DIR}/include/")

link_directories("${ntp_client_BINARY_DIR}")
