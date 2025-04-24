from conan import ConanFile
from conan.tools.files import get, copy
from conan.tools.cmake import CMake, cmake_layout


class BoringSSLConan(ConanFile):
    name = "openssl"
    version = "boringssl"

    generators = "CMakeToolchain"
    settings = "os", "arch", "compiler", "build_type"
    options = {"shared": [True, False], "fPIC": [True, False]}
    default_options = {"shared": False, "fPIC": True}

    requires = ("zlib/1.3.1",)

    def source(self):
        url = "https://github.com/batchar2/boringssl/archive/refs/heads/main.tar.gz"
        get(self, url, strip_root=False)
        src = self.source_folder + "/boringssl-main"
        copy(self, "*", src=src, dst=self.source_folder)

    def build(self):
        cmake = CMake(self)
        cmake.configure(variables={"BUILD_TESTING": False, "ENABLE_EXPRESSION_TESTS": False})
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
        self.cpp_info.components["ssl"].set_property(
            "cmake_target_name", "OpenSSL::SSL"
        )
        self.cpp_info.components["crypto"].set_property(
            "cmake_target_name", "OpenSSL::Crypto"
        )
