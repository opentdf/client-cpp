from conans import ConanFile, CMake
from conan.tools.scm import Version

class TDFLibConan(ConanFile):
    generators = "cmake"
    settings = "os", "compiler", "build_type", "arch"
    options = {"with_libiconv": [True, False], "with_zlib": [True, False], "with_libarchive": [True, False], "fPIC": [True, False], "branch_version": [True, False]}
    default_options = {"with_libiconv": True, "with_zlib": True, "with_libarchive": False, "fPIC": True, "branch_version": False}

    def configure(self):
        if str(self.settings.arch).startswith('arm'):
            self.options["openssl"].no_asm = True
            self.options["libxml2"].zlib = False
            self.options["libxml2"].lzma = False
            self.options["libxml2"].icu = False

    def config_options(self):
        # Do not require libarchive as of 1.1.0
        if Version(self.version) < "1.1.0":
            self.options.with_libarchive = True
        if self.settings.os == "Windows":
            del self.options.fPIC
        if not self.options.with_zlib:
            self.options["libxml2"].zlib = False
        if not self.options.with_libiconv:
            self.options["boost"].without_locale = True
            self.options["boost"].without_log = True
        
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
        # We do not require libiconv but conan-center only allows 'stock' references, and boost+libxml2
        # specify differerent versions, which causes a build fail due to the dependency conflict.
        # Overriding the version here allows a clean build with the stock build settings.
        # Preferred solution is to set with_libiconv to False
        if self.options.get_safe("with_libiconv"):
            self.requires("libiconv/1.17@")
        # Same for zlib
        # Preferred solution is to set with_zlib to False
        if self.options.get_safe("with_zlib"):
            self.requires("zlib/1.2.12@")

    def build(self):
        cmake = CMake(self)
        cmake.configure()
        cmake.build()
