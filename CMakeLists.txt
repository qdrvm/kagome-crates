cmake_minimum_required(VERSION 3.12)

project(kagome-rust-dependencies C CXX)

include(cmake/add_rust_library.cmake)

add_rust_library(schnorrkel HEADER_FILE ${PROJECT_SOURCE_DIR}/generated/include/schnorrkel.h LIB_NAME schnorrkel_crust)
add_rust_library(arkworks HEADER_FILE ${PROJECT_SOURCE_DIR}/generated/include/arkworks.h LIB_NAME arkworks_crust)
add_rust_library(bandersnatch HEADER_FILE ${PROJECT_SOURCE_DIR}/generated/include/bandersnatch_vrfs.h LIB_NAME bandersnatch_vrfs_crust)

install(
    DIRECTORY generated/include/
    TYPE INCLUDE
)
