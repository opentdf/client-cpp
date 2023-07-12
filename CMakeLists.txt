cmake_minimum_required (VERSION 3.8)
project(opentdf-client)

# enable verbose logging
set(CMAKE_VERBOSE_MAKEFILE ON)
# enable `compile_commands.json` generation so `clangd`-based language servers work
# (VSCode, other IDEs that use the LSP protocol)
# https://clangd.llvm.org/installation.html#project-setup
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

find_package("OpenSSL")
find_package("Boost")
find_package("Microsoft.GSL")
find_package("LibXml2")
find_package("nlohmann_json")
find_package("jwt-cpp")
find_package("magic-enum")

link_libraries(
 openssl::openssl
 boost::boost
 Microsoft.GSL::GSL
 LibXml2::LibXml2
 nlohmann_json::nlohmann_json
 jwt-cpp::jwt-cpp
)

#BZip2::BZip2
#ZLIB::ZLIB
#libbacktrace::libbacktrace
#Iconv::Iconv
#picojson::picojson

include_directories(
${CMAKE_INCLUDE_PATH}
)

add_subdirectory(src)

