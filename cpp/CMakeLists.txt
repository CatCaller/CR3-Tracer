cmake_minimum_required(VERSION 3.20)
project(cr3logger CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE RelWithDebInfo)
endif()

set(MEMPROCFS_ROOT "${CMAKE_SOURCE_DIR}/../../KVM-Folders/MemProcFS" CACHE PATH "MemProcFS checkout root")

add_executable(cr3logger src/cr3logger.cpp)
target_include_directories(cr3logger PRIVATE "${MEMPROCFS_ROOT}/includes")
target_compile_definitions(cr3logger PRIVATE LINUX)
target_compile_options(cr3logger PRIVATE -Wall -Wextra)

if(NOT EXISTS "${MEMPROCFS_ROOT}/files/vmm.so")
    message(FATAL_ERROR "vmm.so not found at ${MEMPROCFS_ROOT}/files/vmm.so")
endif()
target_link_directories(cr3logger PRIVATE "${MEMPROCFS_ROOT}/files")
target_link_libraries(cr3logger PRIVATE ":vmm.so")
set_target_properties(cr3logger PROPERTIES
    BUILD_RPATH "${MEMPROCFS_ROOT}/files"
    INSTALL_RPATH "${MEMPROCFS_ROOT}/files"
)
