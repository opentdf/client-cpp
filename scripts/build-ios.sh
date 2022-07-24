cd ../src
rm -rf build
mkdir build
cd build
#run the install step
conan install .. --profile:build /Users/avery.pfeiffer/code/virtru/virtru-tdf3-cpp/virtru-tdf3-src/tools/build_profile --profile:host /Users/avery.pfeiffer/code/virtru/virtru-tdf3-cpp/virtru-tdf3-src/tools/ios_profile -s arch=armv8 -s compiler.version=13.1 -s os=iOS --build=missing 
cmake .. -G Xcode -DCMAKE_TOOLCHAIN_FILE=../../.conan/profiles/ios.toolchain.cmake -DPLATFORM=SIMULATOR64 -DVOSNAME=iphonesimulator
cmake .. -GXcode -DCMAKE_TOOLCHAIN_FILE=conan_toolchain.cmake
# cmake --build . --config Debug