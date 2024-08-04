project(fptn-passwd)

include_directories(${CMAKE_CURRENT_SOURCE_DIR})

find_package(Boost REQUIRED)
find_package(OpenSSL REQUIRED)
find_package(argparse REQUIRED)

add_executable("${PROJECT_NAME}"
    fptn-passwd.cpp
)

target_link_libraries(
    "${PROJECT_NAME}"
    OpenSSL::SSL 
    OpenSSL::Crypto
    argparse::argparse
)
