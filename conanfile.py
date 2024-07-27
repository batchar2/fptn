from conan import ConanFile
from conan.tools.cmake import CMakeToolchain, CMake, CMakeDeps, cmake_layout


PROGRAM_VERSION = "1.0.0"


class FPTN(ConanFile):
    name = "fptn"
    version = PROGRAM_VERSION
    requires = (
        "fmt/11.0.1",
        "glog/0.7.1",
        "boost/1.83.0",
        "argparse/3.0",
        "openssl/3.2.2",
        "jwt-cpp/0.7.0",
        "protobuf/5.27.0",
        "websocketpp/0.8.2",
        "pcapplusplus/23.09",
        "nlohmann_json/3.11.3",
    )
    settings = (
        "os",
        "arch",
        "compiler",
        "build_type",
    )
    generators = (
        "CMakeDeps",
        "CMakeToolchain",
    )
    default_options = {
        "*:shared": False,
        "*:fPIC": True,
        # --- boost options ---
        "boost/*:without_atomic": False,
        "boost/*:without_system": False,
        "boost/*:without_exception": False,
        "boost/*:without_container": False,
        "boost/*:without_filesystem": False,
        "boost/*:without_json": False,
        "boost/*:without_python": True,
        "boost/*:without_chrono": True,
        "boost/*:without_context": True,
        "boost/*:without_contract": True,
        "boost/*:without_coroutine": True,
        "boost/*:without_date_time": True,
        "boost/*:without_fiber": True,
        "boost/*:without_graph": True,
        "boost/*:without_graph_parallel": True,
        "boost/*:without_iostreams": True,
        "boost/*:without_locale": True,
        "boost/*:without_log": True,
        "boost/*:without_math": True,
        "boost/*:without_mpi": True,
        "boost/*:without_nowide": True,
        "boost/*:without_program_options": True,
        "boost/*:without_random": True,
        "boost/*:without_regex": True,
        "boost/*:without_serialization": True,
        "boost/*:without_stacktrace": True,
        "boost/*:without_test": True,
        "boost/*:without_thread": True,
        "boost/*:without_timer": True,
        "boost/*:without_url": True,
        "boost/*:without_type_erasure": True,
        "boost/*:without_wave": True,
    }

    def layout(self):
        cmake_layout(self)

    def build_requirements(self):
        self.test_requires("gtest/1.14.0")

    def build(self):
        cmake = CMake(self)
        cmake.configure()
        cmake.build()

    def configure(self):
        self.settings.compiler.cppstd = "17"
