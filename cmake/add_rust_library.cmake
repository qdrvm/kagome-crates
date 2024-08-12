
include(GNUInstallDirs)

find_program(RUSTC rustc REQUIRED)
find_program(CARGO cargo REQUIRED)

if (CMAKE_BUILD_TYPE STREQUAL "Release" OR CMAKE_BUILD_TYPE STREQUAL "RelWithDebInfo")
  set(CARGO_BUILD_TYPE "release")
  set(CARGO_BUILD_OPTION "--release")
  message(STATUS "CMAKE_BUILD_TYPE=${CMAKE_BUILD_TYPE}, adding ${release_option}")
else ()
  message(STATUS "CMAKE_BUILD_TYPE=${CMAKE_BUILD_TYPE}, default 'debug' is used")
  set(CARGO_BUILD_TYPE "debug")
endif ()

set(CRATES_DIR "${PROJECT_SOURCE_DIR}/crates")

function (add_rust_library CRATE_NAME)
    cmake_parse_arguments(x "" "HEADER_FILE;LIB_NAME" "" ${ARGV})
    message(STATUS HEADER_FILE: ${x_HEADER_FILE})
    message(STATUS LIB_NAME: ${x_LIB_NAME})

    set(CARGO_COMMAND "${CMAKE_COMMAND}" -E env 
            HEADER_FILE="${x_HEADER_FILE}" CBINDGEN_CONFIG="${PROJECT_SOURCE_DIR}/cbindgen.toml" 
        cargo build 
            --target-dir "${CMAKE_BINARY_DIR}/${CRATE_NAME}" 
            ${CARGO_BUILD_OPTION})
    message(STATUS ${CARGO_COMMAND})
    add_custom_target(
        "cargo_build_${CRATE_NAME}"
        ALL
        COMMAND ${CARGO_COMMAND}
        WORKING_DIRECTORY "${CRATES_DIR}/${CRATE_NAME}"
    )    

    add_library(${CRATE_NAME} STATIC IMPORTED GLOBAL)

    set_target_properties(${CRATE_NAME} PROPERTIES
        INTERFACE_INCLUDE_DIRECTORIES ${include_path}
        IMPORTED_LOCATION ${lib}
    )
    add_dependencies(${CRATE_NAME} cargo_build)


    if (BUILD_SHARED_LIBS)
        set(PREFIXED_LIB_NAME ${CMAKE_SHARED_LIBRARY_PREFIX}${x_LIB_NAME}${CMAKE_SHARED_LIBRARY_SUFFIX})
    else ()
        set(PREFIXED_LIB_NAME ${CMAKE_STATIC_LIBRARY_PREFIX}${x_LIB_NAME}${CMAKE_STATIC_LIBRARY_SUFFIX})
    endif ()

    install(
        FILES "${CMAKE_BINARY_DIR}/${CRATE_NAME}/${CARGO_BUILD_TYPE}/${PREFIXED_LIB_NAME}"
        DESTINATION "${CMAKE_INSTALL_LIBDIR}"
    )

    include(CMakePackageConfigHelpers)
    configure_package_config_file(cmakeConfig.cmake.in
        "${CMAKE_BINARY_DIR}/${CRATE_NAME}Config.cmake"
        INSTALL_DESTINATION "share/${CRATE_NAME}"
    )
    install(
        FILES "${CMAKE_BINARY_DIR}/${CRATE_NAME}Config.cmake"
        DESTINATION "share/${CRATE_NAME}"
    )
endfunction()
