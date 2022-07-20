#!/usr/bin/env bash

echo "Building OpenTDF library and run unittests"
export VRUN_BACKEND_TESTS="true"
cd ../../src
echo "Error: failed to locate tdf library $(pwd)..."

echo "Build the sample executable using OpenTDF library"
cd ../../examples && mkdir build && cd build && cmake .. && make

echo "Run the sanity test"
./tdf_sample