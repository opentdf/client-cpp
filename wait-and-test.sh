#!/usr/bin/env bash

cd ../..
cd ${{ github.workspace }}
cd src
./build-all.sh
cd build
make test
cd ${{ github.workspace }}
cd examples
mkdir build
cd build
cmake ..
make
./tdf_sample