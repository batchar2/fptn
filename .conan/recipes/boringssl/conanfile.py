from conan import ConanFile
from conan.tools.files import get
from conan.tools.cmake import CMake, cmake_layout


class BoringSSLConan(ConanFile):
    name = "openssl"
    version = "boringssl"

    generators = "CMakeToolchain"
    settings = "os", "arch", "compiler", "build_type"
    options = {"shared": [True, False], "fPIC": [True, False]}
    default_options = {"shared": False, "fPIC": True}

    requires = (
        "zlib/1.3.1",
    )

    def source(self):
        url = "https://boringssl.googlesource.com/boringssl/+archive/2b44a3701a4788e1ef866ddc7f143060a3d196c9.tar.gz"
        get(self, url, strip_root=False)

    def build(self):
        cmake = CMake(self)
        # cmake.definitions["BORINGSSL_GREASE_ENABLED"] = "ON"
        cmake.configure()
        cmake.build()

    def package(self):
        cmake = CMake(self)
        cmake.install()

    def package_info(self):
        self.cpp_info.components["ssl"].libs = ["ssl"]
        self.cpp_info.components["crypto"].libs = ["crypto"]

        # include dir
        self.cpp_info.includedirs = ["include"]
        self.cpp_info.components["ssl"].includedirs = ["include"]
        self.cpp_info.components["crypto"].includedirs = ["include"]

        # for CMake find_package(OpenSSL)
        self.cpp_info.set_property("cmake_file_name", "OpenSSL")
        self.cpp_info.components["ssl"].set_property("cmake_target_name", "OpenSSL::SSL")
        self.cpp_info.components["crypto"].set_property("cmake_target_name", "OpenSSL::Crypto")
