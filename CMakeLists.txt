cmake_minimum_required (VERSION 3.8)
project(opentdf-client)

# enable verbose logging
set(CMAKE_VERBOSE_MAKEFILE ON)

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

add_subdirectory(tdf-src)

