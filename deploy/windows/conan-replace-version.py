import re
import sys


def replace_version(file_path, new_version):
    with open(file_path, "r") as file:
        content = file.read()
    pattern = r'^FPTN_VERSION = ".*"'
    replacement = f'FPTN_VERSION = "{new_version}"'
    new_content = re.sub(pattern, replacement, content, flags=re.MULTILINE)
    with open(file_path, "w") as file:
        file.write(new_content)


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print(f"Usage: python {sys.argv[0]} <file_path> <new_version>")
        sys.exit(1)

    file_path = sys.argv[1]
    new_version = sys.argv[2]

    print("new_version>>>", new_version)
    replace_version(file_path, new_version)
    print(f"Replaced version in {file_path} with {new_version}")
