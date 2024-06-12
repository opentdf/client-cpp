from conans import ConanFile, CMake
from conan.tools.scm import Version

class TDFLibConan(ConanFile):
    generators = "cmake"
    settings = "os", "compiler", "build_type", "arch"
    options = {"fPIC": [True, False]}
    default_options = {"fPIC": True}

    def configure(self):
        self.options["boost"].without_log = True
        if str(self.settings.arch).startswith('arm'):
            self.options["libxml2"].lzma = False
            self.options["libxml2"].zlib = False

    def config_options(self):
        if self.settings.os == "Windows":
            del self.options.fPIC
        
    def requirements(self):
        self.requires("openssl/[>=3.1 <4]")
        self.requires("boost/1.85.0")
        self.requires("ms-gsl/2.1.0")
        self.requires("libxml2/2.12.7")
        self.requires("nlohmann_json/3.11.3")
        self.requires("jwt-cpp/0.7.0")
        self.requires("zlib/[>=1.2.11 <2]")
        self.requires("magic_enum/0.8.2")
        self.requires("picojson/cci.20210117")

    def build(self):
        cmake = CMake(self)
        cmake.configure()
        cmake.build()
