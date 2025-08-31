import os
import subprocess

from conan import ConanFile
from conan.tools.cmake import CMakeToolchain, CMake
from conan.tools.files import copy

# CI will replace this automatically
FPTN_VERSION = "0.0.0"


class FPTN(ConanFile):
    name = "fptn"
    version = FPTN_VERSION
    requires = (
        "argparse/3.2",
        "cpp-httplib/0.20.1",
        "boost/1.88.0",
        "fmt/11.2.0",
        "jwt-cpp/0.7.1",
        "nlohmann_json/3.12.0",
        "prometheus-cpp/1.3.0",
        "protobuf/5.29.3",
        "spdlog/1.15.3",
        "zlib/1.3.1",
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
        "build_only_fptn_lib": [True, False],
    }
    default_options = {
        # --- program ---
        "setup": False,
        "with_gui_client": False,
        "build_only_fptn_lib": False,
        # -- depends --
        "*:fPIC": True,
        "*:shared": False,
        # --- protobuf options ---
        "protobuf/*:lite": True,
        "protobuf/*:upb": False,
        "protobuf/*:with_rtti": False,
        "protobuf/*:with_zlib": False,
        "protobuf/*:upb": False,
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
        "boost/*:without_iostreams": False,
        "boost/*:without_regex": False,
        "boost/*:without_zlib": False,
        "boost/*:without_python": True,
        "boost/*:without_chrono": True,
        "boost/*:without_contract": True,
        "boost/*:without_fiber": True,
        "boost/*:without_graph": True,
        "boost/*:without_graph_parallel": True,
        "boost/*:without_locale": True,
        "boost/*:without_log": True,
        "boost/*:without_math": True,
        "boost/*:without_mpi": True,
        "boost/*:without_nowide": True,
        "boost/*:without_program_options": True,
        "boost/*:without_serialization": True,
        "boost/*:without_stacktrace": True,
        "boost/*:without_test": True,
        "boost/*:without_thread": True,
        "boost/*:without_url": True,
        "boost/*:without_type_erasure": True,
        "boost/*:without_wave": True,
        # --- Qt ---
        "qt/*:shared": True,
        "qt/*:openssl": False,
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
        # --- prometheuscpp dependency ---
        "civetweb/*:with_ssl": False,
        "prometheus-cpp/*:with_compression": False,
        "prometheus-cpp/*:with_push": False,
    }
    exports_sources = (
        "CMakeLists.txt",
        "src/*",
        "depends/*",
        "tests/*",
    )

    def requirements(self):
        # WE USE BORINGSSL
        self._register_local_recipe("boringssl", "openssl", "boringssl", True, False)
        if not self.options.build_only_fptn_lib:
            # pcap++ does not support iOS and Android.
            # Since libfptn is built as a detached part of the whole project,
            #   we don't use pcap++ in that case.
            self.requires("pcapplusplus/25.05")
        if self.options.with_gui_client:
            self.requires("qt/6.7.1")
        if self.settings.os != "Windows":
            self.requires("meson/1.8.2", override=True, force=True)

    def build_requirements(self):
        self.tool_requires("protobuf/5.29.3")

        self.test_requires("gtest/1.16.0")

        if self.settings.os != "Windows":
            self.build_requires("meson/1.8.2", override=True)
        self.build_requires("cmake/3.22.0", override=True)

    def generate(self):
        tc = CMakeToolchain(self)
        tc.variables["FPTN_VERSION"] = FPTN_VERSION
        if self.options.with_gui_client:
            tc.variables["FPTN_BUILD_WITH_GUI_CLIENT"] = "True"
        if self.options.build_only_fptn_lib:
            tc.variables["FPTN_BUILD_ONLY_FPTN_LIB"] = "True"

        # setup protobuf compiler
        protobuf_build = self.dependencies.build["protobuf"]
        protoc_path = os.path.join(protobuf_build.package_folder, "bin", "protoc")
        tc.cache_variables["Protobuf_PROTOC_EXECUTABLE"] = protoc_path

        tc.generate()

    def build(self):
        cmake = CMake(self)
        cmake.configure()
        cmake.build()

    def package(self):
        if self.options.build_only_fptn_lib:
            copy(
                self,
                "*.h",
                src=os.path.join(self.source_folder, "src", "fptn-protocol-lib"),
                dst=os.path.join(self.package_folder, "include", "fptn"),
            )
            copy(
                self,
                "*.h",
                src=os.path.join(self.source_folder, "src", "common"),
                dst=os.path.join(self.package_folder, "include", "fptn", "common"),
            )
            copy(
                self,
                "*.h",
                src=os.path.join(self.build_folder, "src", "fptn-protocol-lib", "protobuf"),
                dst=os.path.join(self.package_folder, "include", "fptn", "protobuf"),
            )
            # copy lib
            copy(
                self,
                "*.a",
                src=os.path.join(self.build_folder, "src", "fptn-protocol-lib"),
                dst=os.path.join(self.package_folder, "lib"),
            )
            copy(
                self,
                "*.lib",
                src=os.path.join(self.build_folder, "src", "fptn-protocol-lib"),
                dst=os.path.join(self.package_folder, "lib"),
            )
            ntp_client_build_include = os.path.join(self.build_folder, "_deps", "ntp_client-src", "include")
            # copy NTP depends
            if os.path.exists(ntp_client_build_include):
                copy(
                    self,
                    "*.h",
                    src=ntp_client_build_include,
                    dst=os.path.join(self.package_folder, "include", "ntp_client"),
                )
            ntp_client_lib_src = os.path.join(self.build_folder, "_deps", "ntp_client-build")
            if os.path.exists(ntp_client_lib_src):
                copy(
                    self,
                    "*.a",
                    src=ntp_client_lib_src,
                    dst=os.path.join(self.package_folder, "lib"),
                )
                copy(
                    self,
                    "*.lib",
                    src=ntp_client_lib_src,
                    dst=os.path.join(self.package_folder, "lib"),
                )

    def package_info(self):
        if self.options.build_only_fptn_lib:
            self.cpp_info.libs = [
                "fptn-protocol-lib_static",
                "ntp_client",
            ]
            self.cpp_info.includedirs = ["include"]
            self.cpp_info.libdirs = ["lib"]

            # Add depends
            self.cpp_info.requires = [
                "argparse::argparse",
                "cpp-httplib::cpp-httplib",
                "boost::boost",
                "fmt::fmt",
                "jwt-cpp::jwt-cpp",
                "nlohmann_json::nlohmann_json",
                "prometheus-cpp::prometheus-cpp",
                "protobuf::protobuf",
                "spdlog::spdlog",
                "zlib::zlib",
            ]

    def config_options(self):
        if self.settings.os == "Windows":
            self.options.rm_safe("fPIC")

    def export(self):
        copy(self, f"*", src=self.recipe_folder, dst=self.export_folder)

    def _register_local_recipe(self, recipe, name, version, override=False, force=False):
        script_dir = os.path.dirname(os.path.abspath(__file__))
        recipe_rel_path = os.path.join(script_dir, ".conan", "recipes", recipe)
        subprocess.run(
            [
                "conan",
                "export",
                recipe_rel_path,
                f"--name={name}",
                f"--version={version}",
                "--user=local",
                "--channel=local",
            ],
            check=True,
        )
        self.requires(f"{name}/{version}@local/local", override=override, force=force)
