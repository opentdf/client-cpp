from conans import ConanFile, CMake

class TDFLibConan(ConanFile):
    generators = "cmake"
    settings = "os", "compiler", "build_type", "arch"

    def configure(self):
        if str(self.settings.arch).startswith('arm'):
            self.options["openssl"].no_asm = True
            self.options["libxml2"].zlib = False
            self.options["libxml2"].lzma = False
            self.options["libxml2"].icu = False
        
    def requirements(self):
        self.requires("openssl/1.1.1o@")
        if str(self.settings.arch).startswith('arm'):
            self.requires("boost/1.74.0@")
        else:
            self.requires("boost/1.76.0@")
        self.requires("ms-gsl/2.1.0@")
        self.requires("libxml2/2.9.10@")
        self.requires("pybind11/2.6.2@")
        self.requires("nlohmann_json/3.10.4@")
        self.requires("jwt-cpp/0.4.0@")

    def build(self):
        cmake = CMake(self)
        cmake.configure()
        cmake.build()
