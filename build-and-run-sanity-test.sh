#!/usr/bin/env bash

echo "Building OpenTDF library and run unittests"
cd ../../src && ./build-all.sh && cd build && make test

echo "Build the sample executable using OpenTDF library"
cd ../../examples && mkdir build && cd build && cmake .. && make

echo "Run the sanity test"
./tdf_sample