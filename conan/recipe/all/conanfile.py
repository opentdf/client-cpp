from conans import ConanFile, CMake, tools
import os

required_conan_version = ">=1.33.0"


class OpenTDFConan(ConanFile):
    name = "opentdf-client"
    url = "https://github.com/conan-io/conan-center-index"
    homepage = "https://www.virtru.com"
    topics = ("opentdf", "opentdf-client", "tdf", "virtru")
    description = "<Description of OpentdfClient here>"
    license = "MIT"
    generators = "cmake"
    settings = "os", "arch", "compiler", "build_type"
    options = {"build_python": [True, False]}
    default_options = {"build_python": False}
    exports_sources = ["CMakeLists.txt"]

    _cmake = None

    @property
    def _source_subfolder(self):
        return "source_subfolder"

    @property
    def _build_subfolder(self):
        return "build_subfolder"

    def requirements(self):
        self.requires("openssl/1.1.1l@")
        self.requires("boost/1.76.0@")
        self.requires("libiconv/1.16@")
        self.requires("zlib/1.2.11@")
        self.requires("gsl_microsoft/20180102@bincrafters/stable")
        self.requires("libxml2/2.9.10@")
        self.requires("libarchive/3.5.1@")
        self.requires("pybind11/2.6.2@")

    def source(self):
        tools.get(**self.conan_data["sources"][self.version], destination=self._source_subfolder, strip_root=True)

    def _configure_cmake(self):
        if self._cmake:
            return self._cmake
        self._cmake = CMake(self)
        self._cmake.configure(build_folder=self._build_subfolder)
        return self._cmake

    def build(self):
        cmake = self._configure_cmake()
        cmake.build()

    def package(self):
        cmake = self._configure_cmake()
        cmake.install()
        self.copy("*", dst="lib", src=os.path.join(self._source_subfolder,"tdf-lib-cpp/lib"))
        self.copy("*", dst="include", src=os.path.join(self._source_subfolder,"tdf-lib-cpp/include"))
        self.copy("LICENSE", dst="licenses", src=os.path.join(self._source_subfolder,"tdf-lib-cpp"))

    # TODO - this only advertises the static lib, add dynamic lib also
    def package_info(self):
        self.cpp_info.components["libopentdf"].libs = ["opentdf_static"]
        self.cpp_info.components["libopentdf"].names["cmake_find_package"] = "opentdf-client"
        self.cpp_info.components["libopentdf"].names["cmake_find_package_multi"] = "opentdf-client"
        self.cpp_info.components["libopentdf"].names["pkg_config"] = "opentdf-client"
        self.cpp_info.components["libopentdf"].requires = ["openssl::openssl", "boost::boost", "libiconv::libiconv", "zlib::zlib", "gsl_microsoft::gsl_microsoft", "pybind11::pybind11", "libxml2::libxml2", "libarchive::libarchive"]
