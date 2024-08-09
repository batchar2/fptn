#!/usr/bin/env python3
import os
import sys
import shutil
import pathlib
import argparse
import plistlib
import tempfile
import subprocess

from macos_pkg_builder import Packages


APP_NAME = "FptnClient"
SCRIPT_FOLDER = pathlib.Path(__file__).parent
ICON = SCRIPT_FOLDER / "assets" / "FptnClient.icns"


def run_command(command, cwd=None):
    result = subprocess.run(
        command, shell=True, cwd=cwd, text=True, capture_output=True
    )
    if result.returncode != 0:
        raise RuntimeError(
            f"Command '{command}' failed with error: {result.stderr.strip()}"
        )
    return result.stdout.strip()


def save_tunnelblick_tun_driver(target_dir: pathlib.Path) -> bool:
    repo_url = "https://github.com/Tunnelblick/Tunnelblick.git"
    with tempfile.TemporaryDirectory() as temp_git_dir:
        print("Cloning repository...")
        run_command(f"git clone --depth 1 -b master {repo_url}", cwd=temp_git_dir)
        source_folder = (
            pathlib.Path(temp_git_dir)
            / "Tunnelblick"
            / "third_party"
            / "tun-notarized.kext"
        )
        if source_folder.exists():
            print(f"Copying folder '{source_folder}' to target directory...")
            shutil.copytree(source_folder, target_dir, dirs_exist_ok=True)
        else:
            raise FileNotFoundError(f"Source folder '{source_folder}' does not exist.")
    return True


def create_app(
    app_path: pathlib.Path, fptn_client_cli: pathlib.Path, version: str
) -> bool:
    print(app_path)
    try:
        app_contents_path = app_path / "Contents"
        macos_path = app_contents_path / "MacOS"
        resources_path = app_contents_path / "Resources"
        os.makedirs(macos_path, exist_ok=True)
        os.makedirs(resources_path, exist_ok=True)

        # save driver
        tun_driver_path = resources_path / "tun.kext"
        save_tunnelblick_tun_driver(tun_driver_path)

        # copy program
        binary_dest = macos_path / "fptn-client-cli"
        shutil.copy(fptn_client_cli, binary_dest)
        os.chmod(binary_dest, 0o755)

        # copy wrapper of program
        fptn_client_cli_wrapper_sh = (
            SCRIPT_FOLDER / "scripts" / "fptn-client-cli-wrapper.sh"
        )
        fptn_client_cli_wrapper_sh_dest = macos_path / "fptn-client-cli-wrapper.sh"
        shutil.copy(fptn_client_cli_wrapper_sh, fptn_client_cli_wrapper_sh_dest)
        os.chmod(binary_dest, 0o755)

        # copy icon
        icon_dest = resources_path / ICON.name
        shutil.copy(ICON, icon_dest)

        # Create Info.plist
        plist = {
            "CFBundleName": APP_NAME,
            "CFBundleExecutable": "fptn-client-cli",
            "CFBundleIdentifier": "com.fptn.vpn",
            "CFBundleVersion": version,
            "CFBundleIconFile": ICON.name,
            "LSUIElement": True,
            "LSApplicationCategoryType": "public.app-category.utilities",
            "LSRequiresNativeExecution": True,
        }

        with open(app_contents_path / "Info.plist", "wb") as plist_file:
            plistlib.dump(plist, plist_file)

        plist_content = {
            "Label": "net.tunnelblick.tun",
            "ProgramArguments": ["/sbin/kextload", "/Library/Extensions/tun.kext"],
            "KeepAlive": False,
            "RunAtLoad": True,
            "UserName": "root",
        }

        with open(resources_path / "net.tunnelblick.tun.plist", "wb") as plist_file:
            plistlib.dump(plist_content, plist_file)

        return True
    except Exception as e:
        print(f"Error creating .app: {e}")
        return False


def create_pkg(app_path: pathlib.Path) -> bool:
    try:
        post_install = SCRIPT_FOLDER / "scripts" / "post_install.sh"
        pkg_obj = Packages(
            pkg_output="fptn-client-cli.pkg",
            pkg_bundle_id="com.fptn-vpn.installer",
            pkg_as_distribution=True,
            pkg_title="FPTN-VPN",
            pkg_postinstall_script=str(post_install.resolve()),
            pkg_file_structure={
                str(app_path.resolve()): f"/Applications/{APP_NAME}.app",
            },
        )
        if pkg_obj.build():
            return True
        else:
            print("Error building package.")
            return False
    except Exception as e:
        print(f"Error creating package: {e}")
        return False


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="PKG build configuration.")
    parser.add_argument(
        "--fptn-client-cli", required=True, help="Path to the application binary."
    )
    parser.add_argument("--version", required=True, help="Version")
    args = parser.parse_args()

    fptn_client_cli = pathlib.Path(args.fptn_client_cli)
    if not fptn_client_cli.is_file():
        print(f"Binary file does not exist: {fptn_client_cli}")
        sys.exit(1)

    with tempfile.TemporaryDirectory() as temp_dir:
        app_path = pathlib.Path(temp_dir) / f"{APP_NAME}-{args.version}.app"
        if create_app(app_path, fptn_client_cli, args.version):
            pkg_path = pathlib.Path(f"fptn-client-cli-{args.version}-apple-silicon.pkg")
            if create_pkg(app_path):
                print(f"Package created successfully: {pkg_path}")
            else:
                print("Failed to create package.")
        else:
            print("Failed to create .app")
