include(FetchContent)

FetchContent_Declare(Wintun URL https://www.wintun.net/builds/wintun-0.14.1.zip)

FetchContent_GetProperties(Wintun)
if(NOT wintun_POPULATED)
  FetchContent_Populate(Wintun)
endif()

set(Wintun_INCLUDE_DIR "${wintun_SOURCE_DIR}/include")

if(CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64" OR CMAKE_SYSTEM_PROCESSOR MATCHES
                                              "AMD64")
  set(Wintun_REDISTRIBUTABLE "${wintun_SOURCE_DIR}/bin/amd64/wintun.dll")
  set(Wintun_REDISTRIBUTABLE_DIR "${wintun_SOURCE_DIR}/bin/amd64")
elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "arm64" OR CMAKE_SYSTEM_PROCESSOR MATCHES
                                                 "aarch64")
  set(Wintun_REDISTRIBUTABLE "${wintun_SOURCE_DIR}/bin/arm64/wintun.dll")
  set(Wintun_REDISTRIBUTABLE_DIR "${wintun_SOURCE_DIR}/bin/arm64")
else()
  message(FATAL_ERROR "Unknown architecture: ${CMAKE_SYSTEM_PROCESSOR}")
endif()

set(TARGET_DIRECTORY "${CMAKE_BINARY_DIR}/wintun")
file(MAKE_DIRECTORY ${TARGET_DIRECTORY})
file(COPY ${Wintun_REDISTRIBUTABLE} DESTINATION ${TARGET_DIRECTORY})

add_library(Wintun INTERFACE)
target_include_directories(Wintun INTERFACE "${Wintun_INCLUDE_DIR}")
