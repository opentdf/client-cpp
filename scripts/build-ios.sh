cd ../src
rm -rf build
mkdir build
cd build
#run the install step
conan install .. --profile:build=../../.conan/profiles/build_profile  --profile:host=../../.conan/profiles/ios_profile --build=missing 
cmake .. -G Xcode -DCMAKE_TOOLCHAIN_FILE=../../.conan/profiles/ios.toolchain.cmake -DPLATFORM=SIMULATOR64
cmake --build . --config Release