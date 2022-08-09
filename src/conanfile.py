from conans import ConanFile, CMake
from conan.tools.scm import Version

class TDFLibConan(ConanFile):
    generators = "cmake"
    settings = "os", "compiler", "build_type", "arch"
    options = {"with_libiconv": [True, False], "with_zlib": [True, False], "fPIC": [True, False]}
    default_options = {"with_libiconv": False, "with_zlib": True, "fPIC": True}

    def configure(self):
        if str(self.settings.arch).startswith('arm'):
            self.options["openssl"].no_asm = True
            self.options["libxml2"].zlib = False
            self.options["libxml2"].lzma = False
            self.options["libxml2"].icu = False

    def config_options(self):
        if self.settings.os == "Windows":
            del self.options.fPIC
        if not self.options.with_zlib:
            self.options["libxml2"].zlib = False
        if not self.options.with_libiconv:
            self.options["boost"].without_locale = True
            self.options["boost"].without_log = True
            self.options["libxml2"].iconv = False
        
    def requirements(self):
        self.requires("openssl/1.1.1q@")
        if str(self.settings.arch).startswith('arm'):
            self.requires("boost/1.74.0@")
        else:
            self.requires("boost/1.79.0@")
        self.requires("ms-gsl/2.1.0@")
        self.requires("libxml2/2.9.14@")
        self.requires("nlohmann_json/3.11.1@")
        self.requires("jwt-cpp/0.4.0@")
        if not self.options.with_zlib:
            self.requires("zlib/1.2.11@")

    def build(self):
        cmake = CMake(self)
        cmake.configure()
        cmake.build()
