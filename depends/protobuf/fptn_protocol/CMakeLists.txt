project(fptn_protocol LANGUAGES CXX)

set(CMAKE_INCLUDE_CURRENT_DIR ON)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(Protobuf REQUIRED)

# include
if (PROTOBUF_INCLUDE_DIR)
    include_directories(${PROTOBUF_INCLUDE_DIR})
endif()
if (protobuf_INCLUDE_DIRS)
    include_directories(${protobuf_INCLUDE_DIRS})
endif()
if (Protobuf_INCLUDE_DIRS)
    include_directories(${Protobuf_INCLUDE_DIRS})
endif()
if (CONAN_INCLUDE_DIRS_PROTOBUF)
    include_directories(${CONAN_INCLUDE_DIRS_PROTOBUF})
endif()
include_directories(${SOURCE_DIR} ${INCLUDE_DIR} ${CMAKE_CURRENT_BINARY_DIR})
include_directories(${CMAKE_CURRENT_BINARY_DIR}/depends/fptn_protocol/)

# Generate C++ source and header files from the .proto files
set(protobuf_files protocol.proto)
protobuf_generate_cpp(PROTO_SRCS PROTO_HDRS ${protobuf_files})

add_library("${PROJECT_NAME}" STATIC 
    ${PROTO_SRCS} 
    ${PROTO_HDRS}
)
target_include_directories("${PROJECT_NAME}" INTERFACE
    ${CMAKE_CURRENT_BINARY_DIR} protobuf::protobuf 
)
target_link_libraries("${PROJECT_NAME}" ${Protobuf_LIBRARIES} ${protobuf_LIBRARIES} protobuf::protobuf)
