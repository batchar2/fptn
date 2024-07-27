import sys
import pathlib
import subprocess
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
    replace_requires = (
        # Fix for MacOS
        ("meson/*", "meson/1.4.1"),
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
    options = {
        "setup": [True, False],
        "with_gui_client": [True, False],
    }
    default_options = {
        # --- program ---
        "setup": False,
        "with_gui_client": False,
        # -- depends --
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
        # --- qt ---
        "qt*:shared": True,
        "qt*:qttools": True,
        # "qt*:opengl": "no",
        # "qt*:with_x11": False,
        "qt*:with_icu": False,
        "qt*:with_harfbuzz": False,
        "qt*:with_mysql": False,
        "qt*:with_pq": False,
        "qt*:with_odbc": False,
        "qt*:with_zstd": False,
        "qt*:with_brotli": False,
        "qt*:with_dbus": False,
        "qt*:with_libalsa": False,
        "qt*:with_openal": False,
        "qt*:with_gstreamer": False,
        "qt*:with_pulseaudio": False,
        "qt*:with_gssapi": False,
    }
    
    def layout(self):
        cmake_layout(self)
    
    def requirements(self):
        if self.options.with_gui_client:
            self.requires("qt/6.7.1")
        # Fix for MacOS
        self.requires("meson/1.4.1", override=True, force=True)

    def build_requirements(self):
        self.test_requires("gtest/1.14.0")
        # Fix for MacOS
        self.build_requires("meson/1.4.1", override=True)

    def build(self):
        # write cmake variables
        conan_cmake_variables = ""
        if self.options.with_gui_client:
            conan_cmake_variables = "set(FPTN_BUILD_WITH_GUI_CLIENT True)"
        with open(pathlib.Path(self.build_folder) / "conan_variables.cmake", "w") as fp:
            fp.write(conan_cmake_variables)

        cmake = CMake(self)
        cmake.configure()
        cmake.build()

        if self.options.setup:
            base_path = pathlib.Path(self.package_folder) / "build" / "Release" / "code"
            programs = [base_path / "fptn-client" / "fptn-client-cli",]
            if sys.platform == "linux" or sys.platform == "linux2" or sys.platform == "darwin":
                programs.extend([
                    base_path / "fptn-passwd" / "fptn-passwd",
                    base_path / "fptn-server" / "fptn-server",
                ])
            if self.options.with_gui_client:
                programs.extend([
                    base_path / "fptn-client" / "fptn-client-gui",
                ])
            
            cp_commands = " ;".join(
                f"cp -v '{program}' /usr/local/bin/" for program in programs
            )
            cmd = f'sudo sh -c "{cp_commands}"'
            try:
                subprocess.run(f"sudo sh -c '{cmd}'", shell=True, check=True)
            except subprocess.CalledProcessError as e:
                print(f"Error occurred while installing binaries: {e}")
                
    def configure(self):
        self.settings.compiler.cppstd = "17"
