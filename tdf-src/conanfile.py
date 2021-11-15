from conans import ConanFile, CMake

class TDFLibConan(ConanFile):
    generators = "cmake"
    settings = "os", "compiler", "build_type", "arch"

    default_options = ("libzip:with_openssl=False", "libarchive:with_zlib=False")
        
    def requirements(self):
        self.requires("openssl/1.1.1l@")
        self.requires("boost/1.76.0@")
        self.requires("libiconv/1.16@")
        self.requires("zlib/1.2.11@")
        self.requires("gsl_microsoft/20180102@bincrafters/stable")
        self.requires("libxml2/2.9.10@")
        self.requires("pybind11/2.6.2@")
        self.requires("libarchive/3.5.1@")
        self.requires("nlohmann_json/3.10.4@")
        self.requires("jwt-cpp/0.4.0@")

    def build(self):
        cmake = CMake(self)
        cmake.configure()
        cmake.build()
