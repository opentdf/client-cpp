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

REM Populate dist directory
cd ..
rmdir /s /q ..\dist
mkdir ..\dist
mkdir ..\dist\lib
xcopy /s build\lib\release\* ..\dist\lib
mkdir ..\dist\include
xcopy /s lib\include ..\dist\include
xcopy ..\VERSION ..\dist
xcopy ..\README.md ..\dist
xcopy ..\LICENSE ..\dist
mkdir ..\dist\examples
xcopy /s ..\examples ..\dist\examples

:fin
REM return to where we came from
popd
exit /b %builderrorlevel%
