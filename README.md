# client-cpp
Minimal c/c++ client to generate and access TDF files


## Local Building

1. Clone repo
2. `cd tdf-src`
3. ```bash
    rm -rf build
    mkdir build
    cd build
    conan install ..
    conan build .. --build-folder .
    ```
    
    For more details on conan and publishing, see [client-cpp/conan/README.md](client-cpp/conan/README.md)
