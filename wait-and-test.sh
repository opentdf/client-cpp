#!/usr/bin/env bash

cd ../..
cd src
./build-all.sh
cd build
make test
cd ../../examples
mkdir build
cd build
cmake ..
make
./tdf_sample