cmake_minimum_required (VERSION 3.8)
project(opentdf-client)

# enable verbose logging
set(CMAKE_VERBOSE_MAKEFILE ON)
# enable `compile_commands.json` generation so `clangd`-based language servers work
# (VSCode, other IDEs that use the LSP protocol)
# https://clangd.llvm.org/installation.html#project-setup
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

#include(${CMAKE_BINARY_DIR}/conanbuildinfo.cmake)
#conan_basic_setup()

find_package("OpenSSL")
find_package("Boost")
find_package("libiconv")
find_package("ZLIB")
find_package("gsl_microsoft/20180102")
find_package("LibXml2")
find_package("pybind11")
find_package("libarchive")

include_directories(${CONAN_INCLUDE_DIRS})

add_subdirectory(src)

