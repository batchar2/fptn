include(FetchContent)

FetchContent_Declare(Base64 URL https://github.com/tobiaslocker/base64/archive/refs/heads/master.zip)

FetchContent_GetProperties(Base64)
if (NOT Base64_POPULATED)
	FetchContent_Populate(Base64)
endif()

set(Base64_SOURCE_DIR "${CMAKE_CURRENT_BINARY_DIR}/_deps/base64-src")
set(Base64_INCLUDE_DIR "${Base64_SOURCE_DIR}/include")
set(Base64_INCLUDE_DIRS ${Base64_INCLUDE_DIR} CACHE PATH "Base64 Include Directories")

add_library(Base64 INTERFACE)
target_include_directories(Base64 INTERFACE "${Base64_INCLUDE_DIR}")

include_directories(${Base64_INCLUDE_DIR})