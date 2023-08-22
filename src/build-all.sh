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

# Generate initial coverage information
if [[ "$VBUILD_CODE_COVERAGE" == "true" ]]; then
    lcov -b . -c -i -d . -o coverage_wtest_base.info
fi

# run unit tests
if make test; then
    echo "All unit-test passed"
else
    echo "Error: Unit test failed. Fix it!!"
    exit -1;
fi

if [[ "$VBUILD_CODE_COVERAGE" == "true" ]]; then

    # Generate coverage based on executed tests
    lcov -b . -c -d . -o coverage_wtest_run.info
    echo "I am here for coverage"
    pwd
    ls -al
    echo "find gcno files:"
    find -name "*.gcno"
    echo "find gcda files:"
    find -type f -name "*.gcda"
    echo "find gcov"
    find -type f -name "*.gcov"
    pwd
    gcov src/tdf_client.cpp
    ls -al
    echo "find gcov2"
    find -type f -name "*.gcov"

    # Merge coverage tracefiles
    lcov -a coverage_wtest_base.info -a coverage_wtest_run.info  -o coverage_total.info
 
    # Remove third-party library
    lcov -r coverage_total.info  "/usr/include/*" -o coverage_total_step1.info
    lcov -r coverage_total_step1.info "boost/*" -o coverage_total_step2.info
    lcov -r coverage_total_step2.info "/home/runner/.conan/data/*" -o coverage_total_final.info

    cd ..
    LOCATION=your_gcov_folder_name
    mkdir $LOCATION
    chmod -R 777 /home/runner/work/client-cpp/client-cpp/src/your_gcov_folder_name
    sudo find -name '*.cpp' -exec cp -f -t $LOCATION {} +
    sudo find -name '*.gcno' -exec cp -f -t $LOCATION {} +
    sudo find -name '*.gcda' -exec cp -f -t $LOCATION {} +
    cd $LOCATION
    chmod -R 777 /home/runner/work/client-cpp/client-cpp/src/your_gcov_folder_name
    sudo find -name '*.cpp' -exec gcov -bf {} \;
    pwd
    ls -la
    echo "find gcov3"
    find -type f -name "*.gcov"
    echo "${cat asym_decryption.cpp.gcda}"
    echo "${cat asym_decryption.cpp.gcno}"

    gcovr --sonarqube > "coverageForBuild.xml"
    pwd
    ls -la
    echo "${cat coverageForBuild.xml}"

    # Extra: Clear up previous data, create code-coverage folder
    if [[ -d ./code-coverage/ ]] ; then
        rm -rf ./code-coverage/*
    else
        mkdir code-coverage
    fi
 
    # Generate webpage
    genhtml -o ./code-coverage/ coverage_total_final.info

    tar -zcvf code-coverage.tar.gz code-coverage
    cp  code-coverage.tar.gz ../../
fi

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
