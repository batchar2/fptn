from conan import ConanFile
from conan.tools.cmake import CMakeToolchain, CMake


# CI will replace automaticaly
FPTN_VERSION = "0.0.0"


class FPTN(ConanFile):
    name = "fptn"
    version = FPTN_VERSION
    requires = (
        "fmt/11.0.2",
        "boost/1.83.0",
        "argparse/3.1",
        "openssl/3.2.2",
        "jwt-cpp/0.7.0",
        "spdlog/1.15.0",
        "protobuf/5.27.0",
        "websocketpp/0.8.2",
        "cpp-httplib/0.18.3",
        "pcapplusplus/23.09",
        "nlohmann_json/3.11.3",
        "prometheus-cpp/1.3.0",
    )
    settings = (
        "os",
        "arch",
        "compiler",
        "build_type",
    )
    generators = ("CMakeDeps",)
    options = {
        "setup": [True, False],
        "with_gui_client": [True, False],
    }
    default_options = {
        # --- program ---
        "setup": False,
        "with_gui_client": False,
        # -- depends --
        "*:fPIC": True,
        "*:shared": False,
        # --- protobuf options ---
        "protobuf/*:lite": True,
        "protobuf/*:upb": False,
        "protobuf/*:with_rtti": False,
        "protobuf/*:with_zlib": False,
        "protobuf/*:debug_suffix": False,
        # --- boost options ---
        "boost/*:without_atomic": False,
        "boost/*:without_system": False,
        "boost/*:without_process": False,
        "boost/*:without_exception": False,
        "boost/*:without_container": False,
        "boost/*:without_filesystem": False,
        "boost/*:without_coroutine": False,
        "boost/*:without_context": False,
        "boost/*:without_timer": False,
        "boost/*:without_json": False,
        "boost/*:without_random": False,
        "boost/*:without_python": True,
        "boost/*:without_chrono": True,
        "boost/*:without_contract": True,
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
        "boost/*:without_regex": True,
        "boost/*:without_serialization": True,
        "boost/*:without_stacktrace": True,
        "boost/*:without_test": True,
        "boost/*:without_thread": True,
        "boost/*:without_url": True,
        "boost/*:without_type_erasure": True,
        "boost/*:without_wave": True,
        # --- Qt (only for MacOS and Windows) ---
        "qt/*:shared": True,
        "qt/*:qttools": True,
        "qt/*:with_harfbuzz": False,
        "qt/*:with_mysql": False,
        "qt/*:with_pq": False,
        "qt/*:with_odbc": False,
        "qt/*:with_zstd": False,
        "qt/*:with_brotli": False,
        "qt/*:with_dbus": False,
        "qt/*:with_openal": False,
        "qt/*:with_gstreamer": False,
        "qt/*:with_pulseaudio": False,
    }

    def requirements(self):
        if self.options.with_gui_client:
            self.requires("qt/6.7.1")
        if self.settings.os != "Windows":
            self.requires("meson/1.4.1", override=True, force=True)

    def build_requirements(self):
        self.test_requires("gtest/1.14.0")
        if self.settings.os != "Windows":
            self.build_requires("meson/1.4.1", override=True)

    def generate(self):
        tc = CMakeToolchain(self)
        if self.options.with_gui_client:
            tc.variables["FPTN_BUILD_WITH_GUI_CLIENT"] = "True"
        tc.variables["FPTN_VERSION"] = FPTN_VERSION
        tc.generate()

    def build(self):
        cmake = CMake(self)
        cmake.configure()
        cmake.build()

    def config_options(self):
        if self.settings.os == "Windows":
            self.options.rm_safe("fPIC")
