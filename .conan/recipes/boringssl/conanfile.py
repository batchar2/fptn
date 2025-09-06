from conan import ConanFile
from conan.tools.files import get, copy
from conan.tools.cmake import CMake, CMakeToolchain, cmake_layout
from conan.tools.apple import is_apple_os


class BoringSSLConan(ConanFile):
    name = "openssl"
    version = "boringssl"

    settings = "os", "arch", "compiler", "build_type"
    options = {"shared": [True, False], "fPIC": [True, False]}
    default_options = {"shared": False, "fPIC": True}

    requires = ("zlib/1.3.1",)

    def config_options(self):
        if self.settings.os == "Windows":
            del self.options.fPIC

    def layout(self):
        cmake_layout(self)

    def source(self):
        url = "https://github.com/batchar2/boringssl/archive/refs/heads/main.tar.gz"
        get(self, url, strip_root=True)

    def generate(self):
        tc = CMakeToolchain(self)
        tc.variables["BUILD_TESTING"] = False
        tc.variables["ENABLE_EXPRESSION_TESTS"] = False
        if self.settings.os == "iOS":
            tc.variables["CMAKE_MACOSX_BUNDLE"] = False
            tc.variables["CMAKE_XCODE_ATTRIBUTE_CODE_SIGNING_REQUIRED"] = "NO"
            tc.variables["CMAKE_XCODE_ATTRIBUTE_CODE_SIGNING_ALLOWED"] = "NO"
            if self.settings.os == "iOS":
                tc.variables["CMAKE_OSX_DEPLOYMENT_TARGET"] = self.settings.os.version
                tc.variables["CMAKE_OSX_ARCHITECTURES"] = self.settings.arch
                tc.variables["CMAKE_XCODE_ATTRIBUTE_ONLY_ACTIVE_ARCH"] = "NO"
                tc.variables["CMAKE_XCODE_ATTRIBUTE_ENABLE_BITCODE"] = "YES"
            if hasattr(self, 'settings_build'):
                tc.variables["CMAKE_SYSTEM_NAME"] = self.settings.os
                if self.settings.os == "iOS":
                    tc.variables["CMAKE_OSX_SYSROOT"] = "iphoneos"
        tc.generate()

    def build(self):
        cmake = CMake(self)
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
