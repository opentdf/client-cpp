###########################################################
# Python bindings library
###########################################################
cmake_minimum_required (VERSION 3.8)

# enable verbose logging
set(CMAKE_VERBOSE_MAKEFILE ON)

# Set the project name
project(opentdf)

set(CMAKE_CXX_STANDARD 17)

# generate compile_commands.json
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# Get this from VERSION file
file(READ ${PROJECT_SOURCE_DIR}/../../VERSION PYTHON_SDK_BUILD_VERSION)
string(STRIP "${PYTHON_SDK_BUILD_VERSION}" PYTHON_SDK_BUILD_VERSION)
SET(PACKAGE_VERSION ${PYTHON_SDK_BUILD_VERSION})

# add source files
set(SOURCE_FILES pips/python_module.cpp)

set(TDFLIB "opentdf_static_combined")
if(${CMAKE_SYSTEM_NAME} MATCHES "Windows")
    set(PYTHON_MODULE_SUFFIX ".pyd")
    set(VBUILDTYPEDIR $ENV{VBUILDTYPE}/)
else()
    set(PYTHON_MODULE_SUFFIX ".so")
endif()

set(TDF_PYTHON_BINDINGS_FILENAME ${PROJECT_NAME}${PYTHON_MODULE_SUFFIX})
set(TDF_LIB_DIR ${PROJECT_SOURCE_DIR}/../build/lib)

find_package(PythonInterp 3)
find_package(PythonLibs   3)

message("Libs of conan: " ${CONAN_LIBS} )
message("Lib dirs of conan: " ${CONAN_LIB_DIRS} )
message("Include dirs of conan: " ${CONAN_INCLUDE_DIRS} )
message("Include dirs of python: " ${PYTHON_INCLUDE_DIRS} )
message("Output python bindings name: " ${TDF_PYTHON_BINDINGS_FILENAME} )
message("python lib dir: "  ${PYTHON_LIBRARY})

# BUG: on armv7 CMAKE finds wrong python library, so hardcoded.
if($ENV{VIRTRU_SDK_BUILD_ARCH} MATCHES "armv7l")
    set (PYTHON_LIBRARY /usr/lib/arm-linux-gnueabihf/libpython3.7m.so)
    message("updated python lib dir: "  ${PYTHON_LIBRARY})
endif()

# Include paths
include_directories(
        ${PROJECT_SOURCE_DIR}
        ${PROJECT_SOURCE_DIR}/../lib/include
        ${PROJECT_SOURCE_DIR}/../lib/src
        ${PROJECT_SOURCE_DIR}/../../tdf-cpp/tdf-src/lib/include
        ${PROJECT_SOURCE_DIR}/../../tdf-cpp/tdf-src/lib/src
        ${PROJECT_SOURCE_DIR}/../../tdf-cpp/tdf-src/thirdparty-libs/common
        ${CONAN_INCLUDE_DIRS}
        ${PYTHON_INCLUDE_DIRS}
        ${PYBIND11_INCLUDE_DIRS}
)

link_directories(
        ${CONAN_LIB_DIRS}
        ${TDF_LIB_DIR}
)

if(${CMAKE_SYSTEM_NAME} MATCHES "Darwin")
    link_libraries(${CONAN_LIBS}
            ${TDFLIB})
else()
    link_libraries(${CONAN_LIBS}
            ${TDFLIB}
            ${PYTHON_LIBRARY})
endif()

add_library(${PROJECT_NAME} SHARED ${SOURCE_FILES})
set_target_properties(${PROJECT_NAME} PROPERTIES PREFIX "")
set_target_properties(${PROJECT_NAME} PROPERTIES SUFFIX "")

if(${CMAKE_SYSTEM_NAME} MATCHES "Darwin")
    set_target_properties(${PROJECT_NAME} PROPERTIES LINK_FLAGS "-undefined dynamic_lookup")
endif()

set_target_properties(${PROJECT_NAME} PROPERTIES OUTPUT_NAME ${TDF_PYTHON_BINDINGS_FILENAME})

# Note we really use the static_combined lib, but it's generated as a custom post-build command of static, so it's not a visible target
add_dependencies(${PROJECT_NAME} opentdfstatic)

############################################################
# Package for distribution
############################################################

set(TDF_LIB_INSTALL_LOCATION  ${PROJECT_SOURCE_DIR}/../../tdf-lib-python)
set(TDF_LIB_PYTHON_INSTALL_LOCATION  ${TDF_LIB_INSTALL_LOCATION})

# Create python
install(DIRECTORY DESTINATION ${TDF_LIB_PYTHON_INSTALL_LOCATION})

# Copy tdf_python.so/pyd to lib-python/lib
install(PROGRAMS ${CMAKE_CURRENT_BINARY_DIR}/${VBUILDTYPEDIR}${TDF_PYTHON_BINDINGS_FILENAME}
        DESTINATION ${TDF_LIB_PYTHON_INSTALL_LOCATION}/lib/${PROJECT_NAME})

# Place the initialization file in the python module directory
CONFIGURE_FILE(${PROJECT_SOURCE_DIR}/setup/__init__.py
        ${TDF_LIB_PYTHON_INSTALL_LOCATION}/lib/${PROJECT_NAME}/__init__.py)

# Configure and copy the setup file.
CONFIGURE_FILE(${PROJECT_SOURCE_DIR}/setup/setup.py
        ${TDF_LIB_PYTHON_INSTALL_LOCATION}/lib/setup.py)

# Copy the sample dir
set(TDF_PYTHON_SAMPLE ${PROJECT_SOURCE_DIR}/sample)
file(COPY ${TDF_PYTHON_SAMPLE} DESTINATION ${TDF_LIB_PYTHON_INSTALL_LOCATION})

# Copy the README
CONFIGURE_FILE(${PROJECT_SOURCE_DIR}/README.md
        ${TDF_LIB_PYTHON_INSTALL_LOCATION})

CONFIGURE_FILE(${PROJECT_SOURCE_DIR}/../../VERSION
        ${TDF_LIB_PYTHON_INSTALL_LOCATION})

CONFIGURE_FILE(${PROJECT_SOURCE_DIR}/../../LICENSE
        ${TDF_LIB_PYTHON_INSTALL_LOCATION})



