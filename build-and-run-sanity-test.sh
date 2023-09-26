#!/usr/bin/env bash

echo "Building OpenTDF library and run unittests"
export VRUN_BACKEND_TESTS="true"
export VBUILD_UNIT_TESTS="true"
export VEXPORT_COMBINED_LIB="true"

cd ./src && ./build-all.sh

if [[ -z "${VEXPORT_COMBINED_LIB}" ]]; then
    echo "Skip building the sample"
else
    echo "Build the sample executable using OpenTDF library"
    cd ../examples && mkdir build && cd build && cmake .. && make

    echo "Run the sanity test"
    ./tdf_sample
fi
