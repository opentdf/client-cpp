#!/bin/bash
# minimal build script
mkdir build
conan install . --build-folder build
conan build . --build-folder build
