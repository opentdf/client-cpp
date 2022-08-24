REM minimal build script to be executed from the src directory
rmdir /s /q build
mkdir build
pushd build

REM Install the prerequisites
conan install .. --build=missing
set builderrorlevel=%errorlevel%
if %builderrorlevel% neq 0 goto fin

REM Build the project
conan build .. --build-folder .
set builderrorlevel=%errorlevel%
if %builderrorlevel% neq 0 goto fin

:fin
REM return to where we came from
popd
exit /b %builderrorlevel%
