from conans import ConanFile, CMake
from conan.tools.scm import Version

class TDFLibConan(ConanFile):
    generators = "cmake"
    settings = "os", "compiler", "build_type", "arch"
    options = {"fPIC": [True, False]}
    default_options = {"fPIC": True}

    def configure(self):
        if str(self.settings.arch).startswith('arm'):
            self.options["openssl"].no_asm = True
            self.options["libxml2"].lzma = False
            self.options["libxml2"].zlib = False
            self.options["libxml2"].icu = False

    def config_options(self):
        if self.settings.os == "Windows":
            del self.options.fPIC
        else:
            self.options["libxml2"].iconv = False
        
    def requirements(self):
        self.requires("openssl/1.1.1q")
        self.requires("boost/1.79.0")
        self.requires("ms-gsl/2.1.0")
        self.requires("libxml2/2.9.14")
        self.requires("nlohmann_json/3.11.1")
        self.requires("jwt-cpp/0.4.0")
        self.requires("zlib/1.2.12")

    def build(self):
        cmake = CMake(self)
        cmake.configure()
        cmake.build()
