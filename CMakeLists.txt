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

include_directories(
${OpenSSL_INCLUDE_DIRS}
${Boost_INCLUDE_DIRS}
${Microsoft.GSL_INCLUDE_DIRS}
${Libxml2_INCLUDE_DIRS}
${nlohmann_json_INCLUDE_DIRS}
${jwt-cpp_INCLUDE_DIRS}
)

add_subdirectory(src)

