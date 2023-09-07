# OpenTDF - client-cpp
Minimal c/c++ client to generate and access TDF files

## Building

### Dependencies

To build the client the following dependencies are needed

- [conan](https://conan.io)
- [cmake](https://cmake.org)

#### Install deps via Homebrew

Using [Hombrew](https://brew.sh) (for Mac and Linux)

```
brew install conan cmake
```

### Installing a published release with Conan (recommended, will prefer prebuilt binaries but build missing deps from source)
``` sh
conan install opentdf-client/1.1.3@ --build=missing
```
For more details on Conan and publishing, see [OpenTDF/client-conan](https://github.com/opentdf/client-conan)

### Local In-Tree Building

1. `cd src`
1. `sh build-all.sh`

### Local In-Tree Building+Testing

1. `sh build-and-run-sanity-test.sh`

