#!/bin/bash
# minimal build script to be executed from the src directory
rm -rf build
mkdir build
cd build
conan install .. 
conan build .. --build-folder .
