cmake_minimum_required(VERSION 3.22)
project(lumabridge_linux_receiver VERSION 0.1.0 LANGUAGES CXX C)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

find_package(PkgConfig REQUIRED)
pkg_check_modules(FFMPEG REQUIRED IMPORTED_TARGET libavcodec libavutil libswscale)
pkg_check_modules(SDL2 REQUIRED IMPORTED_TARGET sdl2)
pkg_check_modules(LIBVA IMPORTED_TARGET libva libva-drm)

if(NOT DEFINED LUMABRIDGE_FFI_INCLUDE_DIR)
    set(LUMABRIDGE_FFI_INCLUDE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../../core/crates/lumabridge-ffi/include")
endif()
if(NOT DEFINED LUMABRIDGE_FFI_LIB_DIR)
    set(LUMABRIDGE_FFI_LIB_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../../core/target/release")
endif()

find_library(LUMABRIDGE_FFI_LIBRARY
    NAMES lumabridge_ffi
    PATHS "${LUMABRIDGE_FFI_LIB_DIR}"
    NO_DEFAULT_PATH
)
if(NOT LUMABRIDGE_FFI_LIBRARY)
    find_library(LUMABRIDGE_FFI_LIBRARY NAMES lumabridge_ffi REQUIRED)
endif()

add_library(lumabridge_rx_lib STATIC
    src/Config.cpp
    src/VaapiH264Decoder.cpp
    src/DisplayRenderer.cpp
)
target_include_directories(lumabridge_rx_lib PUBLIC
    "${CMAKE_CURRENT_SOURCE_DIR}/src"
    "${LUMABRIDGE_FFI_INCLUDE_DIR}"
)
target_link_libraries(lumabridge_rx_lib PUBLIC
    PkgConfig::FFMPEG
    PkgConfig::SDL2
)
if(LIBVA_FOUND)
    target_compile_definitions(lumabridge_rx_lib PUBLIC LUMABRIDGE_HAS_LIBVA=1)
    target_link_libraries(lumabridge_rx_lib PUBLIC PkgConfig::LIBVA)
endif()
target_compile_options(lumabridge_rx_lib PRIVATE -Wall -Wextra -Werror)

add_executable(lumabridge-linux-receiver
    src/main.cpp
)
target_link_libraries(lumabridge-linux-receiver PRIVATE
    lumabridge_rx_lib
    "${LUMABRIDGE_FFI_LIBRARY}"
    pthread
    dl
)
target_compile_options(lumabridge-linux-receiver PRIVATE -Wall -Wextra -Werror)
set_target_properties(lumabridge-linux-receiver PROPERTIES
    BUILD_RPATH "${LUMABRIDGE_FFI_LIB_DIR}"
    INSTALL_RPATH "$ORIGIN;${LUMABRIDGE_FFI_LIB_DIR}"
)

add_executable(lumabridge-linux-receiver-tests
    tests/receiver_tests.cpp
)
target_link_libraries(lumabridge-linux-receiver-tests PRIVATE
    lumabridge_rx_lib
    "${LUMABRIDGE_FFI_LIBRARY}"
    pthread
    dl
)
target_compile_options(lumabridge-linux-receiver-tests PRIVATE -Wall -Wextra -Werror)
set_target_properties(lumabridge-linux-receiver-tests PROPERTIES
    BUILD_RPATH "${LUMABRIDGE_FFI_LIB_DIR}"
)
