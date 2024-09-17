#!/bin/bash

set -euxo pipefail

rm -rf build

OT_CMAKE_NINJA_TARGET=${OT_CMAKE_NINJA_TARGET:-}

OT_SRCDIR="$(pwd)"
readonly OT_SRCDIR

OT_OPTIONS=(
    "-DCMAKE_TOOLCHAIN_FILE=$IDF_PATH/tools/cmake/toolchain-esp32c6.cmake"
    "-DCMAKE_BUILD_TYPE=MinSizeRel"
    "-DBUILD_TESTING=off"
    "-DOT_PLATFORM=external"
    "-DOT_SLAAC=ON"
)
readonly OT_OPTIONS

build()
{
    local builddir="${OT_CMAKE_BUILD_DIR:-build}"

    mkdir -p "${builddir}"
    cd "${builddir}"

    cmake -GNinja \
        -DOT_FTD=OFF \
        -DOT_MTD=ON \
        -DOT_RCP=OFF \
        -DOT_APP_CLI=OFF \
        -DOT_APP_NCP=OFF \
        -DOT_APP_RCP=OFF \
        -DOT_PLATFORM=external \
        -DOT_SLAAC=ON \
        -DOT_SETTINGS_RAM=ON \
        -DCMAKE_BUILD_TYPE=MinSizeRel \
        -DOT_SRP_CLIENT=ON \
        -DOT_ECDSA=ON \
        -DOT_COMPILE_WARNING_AS_ERROR=ON "$@" "${OT_SRCDIR}"

    if [[ -n ${OT_CMAKE_NINJA_TARGET[*]} ]]; then
        ninja "${OT_CMAKE_NINJA_TARGET[@]}"
    else
        ninja
    fi

    cd "${OT_SRCDIR}"
}

main()
{
    local options=("${OT_OPTIONS[@]}")

    options+=("$@")

    build "${options[@]}"

    rm -rf ../libs/*.a
    cp build/lib/*.a ../libs
}

main "$@"
