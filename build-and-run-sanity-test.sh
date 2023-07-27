#!/usr/bin/env bash

echo "Building OpenTDF library and run unittests"
export VRUN_BACKEND_TESTS="true"
export VBUILD_UNIT_TESTS="true"

# Code coverage only on linux
if [[ $OSTYPE == "linux-gnu" ]]; then
    export VBUILD_CODE_COVERAGE="true"
fi

cd ../../src && ./build-all.sh

if [[ "$VBUILD_CODE_COVERAGE" == "true" ]]; then
    echo "Running code coverage..."
	lcov --capture --directory . --output-file coverage.info
    genhtml coverage.info --output-directory code-coverage
	html2text  -width 200 code-coverage/index.html
	tar -zcvf code-coverage.tar.gz code-coverage
fi

echo "Build the sample executable using OpenTDF library"
cd ../examples && mkdir build && cd build && cmake .. && make

echo "Run the sanity test"
./tdf_sample
