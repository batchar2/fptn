include(FetchContent)

FetchContent_Declare(CamouflageTLS URL https://github.com/fptn-project/camouflage-tls/archive/refs/heads/main.zip)
FetchContent_MakeAvailable(CamouflageTLS)

set(CamouflageTLS_INCLUDE_DIR "${camouflagetls_SOURCE_DIR}/include")
set(CamouflageTLS_INCLUDE_DIRS ${CamouflageTLS_INCLUDE_DIR} CACHE PATH "Camouflage Include Directories")

if(NOT TARGET CamouflageTLS)
  add_library(CamouflageTLS INTERFACE)
  target_include_directories(CamouflageTLS INTERFACE "${CamouflageTLS_INCLUDE_DIR}")
endif()

target_include_directories(CamouflageTLS INTERFACE "${camouflagetls_SOURCE_DIR}/include")
