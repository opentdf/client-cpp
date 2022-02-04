REM minimal build script to be executed from the src directory
rmdir /s /q  build
mkdir build
cd build
conan install .. --build=missing
conan build .. --build-folder .
