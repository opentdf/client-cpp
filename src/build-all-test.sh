#!/bin/bash
VBUILD_UNIT_TESTS=true

bash build-all.sh

TDF_LIB_OUTPUT="tdf-lib-cpp"

if [ ! -d ${TDF_LIB_OUTPUT} ]; then
    echo "Error: failed to locate tdf library $(pwd)..."
fi

# run unit tests
if make test; then
    echo "All unit-test passed"
else
    echo "Error: Unit test failed. Fix it!!"
    exit -1;
fi

# package the library.
if make install; then
    echo "Packaging ${TDF_LIB_OUTPUT} passed"
else
    echo "Error: Packaging ${TDF_LIB_OUTPUT} failed. Fix it!!"
    exit -1;
fi