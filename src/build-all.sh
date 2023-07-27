#!/bin/bash
# minimal build script to be executed from the src directory
export VBUILD_UNIT_TESTS="true"
# Run the backend test
#export VRUN_BACKEND_TESTS="true"
TDF_LIB_OUTPUT="tdf-lib-cpp"

rm -rf build
mkdir build
cd build
conan install .. --build=missing
conan build .. --build-folder .

# run unit tests
if make test; then
    echo "All unit-test passed"
else
    echo "Error: Unit test failed. Fix it!!"
    exit -1;
fi

gcovr

# package the library.
if make install; then
    echo "Packaging ${TDF_LIB_OUTPUT} passed"
else
    echo "Error: Packaging ${TDF_LIB_OUTPUT} failed. Fix it!!"
    exit -1;
fi

# prepare artifact content in dist directory
cd ..
rm -rf ../dist
mkdir ../dist
cp -r build/package/* ../dist
cp ../VERSION ../dist
cp ../README.md ../dist
cp ../LICENSE ../dist
cp -r ../examples ../dist
