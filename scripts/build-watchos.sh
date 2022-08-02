cd ../src
rm -rf build
mkdir build
cd build
#run the install step
conan install .. --profile:build ./../../.conan/profiles/build_profile --profile:host ./../../.conan/profiles/watchos_profile -s arch=armv7k -s compiler.version=13.1 -s os=watchOS --build=missing 
# cmake .. -G Xcode -DCMAKE_TOOLCHAIN_FILE=../../.conan/profiles/ios.toolchain.cmake -DPLATFORM=WATCHOS -DVOSNAME=WATCHOS