BUILD_DIR ?= build
BUILD_TYPE ?= Release

BUILD_THREADS := $$(nproc 2>/dev/null || sysctl -n hw.ncpu)


build:
	if [ "$$(uname)" = "Darwin" ]; then \
		export SDKROOT=$$(xcrun --sdk macosx --show-sdk-path) ; \
	fi ; \
	cmake . -B"$(BUILD_DIR)" -DCMAKE_INSTALL_PREFIX=install -DCMAKE_BUILD_TYPE=$(BUILD_TYPE) ; \
	cmake --build "$(BUILD_DIR)" -- -j$(BUILD_THREADS) ; \
	cmake --install "$(BUILD_DIR)" 

run_tests:
	cd .ci && ./run_all_tests.sh
