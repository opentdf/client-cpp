cmake_minimum_required(VERSION 3.5)

# The places to look for the tdf library folders
set(FIND_TDFLIB_PATHS ${PROJECT_SOURCE_DIR}/../tdf-lib-cpp)

# The location of the include folder (and thus the header files)
# find_path uses the paths we defined above as places to look
# Saves the location of the header files in a variable called TDFLIB_INCLUDE_DIR
find_path(TDFLIB_INCLUDE_DIR tdf.h policy_object.h  # The variable to store the path in and the name of the header files
        PATH_SUFFIXES include               # The folder name containing the header files
        PATHS ${FIND_TDFLIB_PATHS} # Where to look (defined above)
        NO_DEFAULT_PATH
        NO_CMAKE_ENVIRONMENT_PATH
        NO_CMAKE_PATH
        NO_SYSTEM_ENVIRONMENT_PATH
        NO_CMAKE_SYSTEM_PATH
        NO_CMAKE_FIND_ROOT_PATH
        )

# The location of the lib folder (and thus the .a file)
# find_library uses the paths we defined above as places to look
# Saves the location of the .a file in a variable called TDFLIB_LIBRARY
find_library(TDFLIB_LIBRARY               # The variable to store where it found the .a files
        NAMES tdf.a                        # The name of the .a file (without the 'lib')
        PATH_SUFFIXES lib                  # The folder the .a file is in
        PATHS ${FIND_TDFLIB_PATHS})       # Where to look (defined above)

message(STATUS "${TDFLIB_LIBRARY} lib locaiton...")
