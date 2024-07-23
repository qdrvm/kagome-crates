# Kagome Rust Dependencies
This repo contains wrappers for rust library which KAGOME uses. 
The crates in crates/ dir declare C API wrappers for Rust libraries and use cbindgen to generate an actual C header.
They need to be in the same CMake project so that Hunter, KAGOME's package manager, always builds them all with the same Rust compiler, otherwise conflicts in Rust runtime symbols happen when linking.
In case any of those are required in projects other than KAGOME, this repo may be repurposed in one of the following ways:
 - Extract cmake/add_rust_library.cmake, cmakeConfig.cmake.in and cbingden.toml, along with crates/build-helper crate to a separate repo and use it as a dependency here and for the new project.
 - Rewrite CMakeLists.txt here so that the list of the rust crates is not hardcoded, but passed as an argument to CMake, so that projects that depend on the current one may just pass the desired list of Rust-to-C binding repos.
