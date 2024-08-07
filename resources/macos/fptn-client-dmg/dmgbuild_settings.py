#!/usr/bin/env python
import os
import pathlib
import argparse
import subprocess

import dmgbuild


if __name__ == "__main__":
    SCRIPT_FOLDER = pathlib.Path(__file__).parent

    parser = argparse.ArgumentParser(description="DMG build configuration.")
    parser.add_argument(
        "--fptn-client-cli", required=True, help="Path to the application binary."
    )
    args = parser.parse_args()

    fptn_client_cli = pathlib.Path(args.fptn_client_cli)
    post_install = SCRIPT_FOLDER / "files" / "post_install.sh"
    post_uninstall = SCRIPT_FOLDER / "files" / "post_uninstall.sh"

    background = SCRIPT_FOLDER / "files" / "background.png"

    settings = {
        "volume_name": "fptn-client",
        "background": str(background.resolve()),
        "icon_size": 128,
        "icon_locations": {
            "fptn-client-cli": (75, 75),
            "Applications": (225, 75),
        },
        "window_size": (600, 400),
        "files": [
            str(fptn_client_cli.resolve()),
        ],
        "symlinks": {
            "Applications": "/Applications",
        },
    }
    dmgbuild.build_dmg(
        filename="fptn-client-cli.dmg",
        volume_name="fptn-client",
        settings=settings
    )
    subprocess.run([
        "pkgbuild",
        "--root", str(fptn_client_cli.parent),
        "--identifier", "com.fptn.fptn-client-cli",
        "--version", "1.0",
        "--install-location", "/usr/local/bin",
        "--scripts", str(SCRIPT_FOLDER / "scripts"),
        "fptn-client-cli.pkg"
    ])
    subprocess.run([
        "productbuild",
        "--distribution", str(SCRIPT_FOLDER / "files" / "distribution.xml"),
        "--package-path", ".",
        "--resources", str(SCRIPT_FOLDER / "resources"),
        "fptn-client-cli-installer.pkg"
    ])

    os.remove("fptn-client-cli.dmg")
    os.remove("fptn-client-cli.pkg")
