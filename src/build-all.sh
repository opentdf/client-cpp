#!/bin/bash
# minimal build script to be executed from the src directory
export VBUILD_UNIT_TESTS="true"
# Run the backend test
#export VRUN_BACKEND_TESTS="true"

# Code coverage only on linux
if [[ $OSTYPE == "linux-gnu" ]]; then
    export VBUILD_CODE_COVERAGE="true"
fi

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
    #exit -1;
fi

# package the library.
if make install; then
    echo "Packaging ${TDF_LIB_OUTPUT} passed"
else
    echo "Error: Packaging ${TDF_LIB_OUTPUT} failed. Fix it!!"
    #exit -1;
fi

if [[ "$VBUILD_CODE_COVERAGE" == "true" ]]; then
    echo "Running code coverage..."
	lcov --capture --directory . --output-file coverage.info
    genhtml coverage.info --output-directory code-coverage
	html2text  -width 200 code-coverage/index.html
	tar -zcvf code-coverage.tar.gz code-coverage
    cp  code-coverage.tar.gz ../
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
