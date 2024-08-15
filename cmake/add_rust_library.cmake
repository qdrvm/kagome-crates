
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
set(CRATES_INCLUDE ${PROJECT_SOURCE_DIR}/generated/include)

function (add_rust_library CRATE_NAME)
    set(CRATE_BUILD ${CMAKE_BINARY_DIR}/${CRATE_NAME})
    set(CRATE_LIB_STATIC ${CRATE_BUILD}/${CARGO_BUILD_TYPE}/${CMAKE_STATIC_LIBRARY_PREFIX}${CRATE_NAME}${CMAKE_STATIC_LIBRARY_SUFFIX})
    set(CRATE_LIB_SHARED ${CRATE_BUILD}/${CARGO_BUILD_TYPE}/${CMAKE_SHARED_LIBRARY_PREFIX}${CRATE_NAME}${CMAKE_SHARED_LIBRARY_SUFFIX})
    set(CRATE_HEADER ${CRATES_INCLUDE}/${CRATE_NAME}.h)
    if(BUILD_SHARED_LIBS)
        set(CRATE_LIB ${CRATE_LIB_SHARED})
    else()
        set(CRATE_LIB ${CRATE_LIB_STATIC})
    endif()

    set(CARGO_COMMAND "${CMAKE_COMMAND}" -E env 
            HEADER_FILE=${CRATE_HEADER} CBINDGEN_CONFIG="${PROJECT_SOURCE_DIR}/cbindgen.toml" 
        cargo build 
            --target-dir ${CRATE_BUILD}
            ${CARGO_BUILD_OPTION})
    add_custom_target(
        "cargo_build_${CRATE_NAME}"
        ALL
        COMMAND ${CARGO_COMMAND}
        WORKING_DIRECTORY "${CRATES_DIR}/${CRATE_NAME}"
    )    

    add_library(${CRATE_NAME} STATIC IMPORTED GLOBAL)
    add_dependencies(${CRATE_NAME} "cargo_build_${CRATE_NAME}")

    install(
        FILES ${CRATE_LIB}
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
