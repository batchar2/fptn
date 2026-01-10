#!/usr/bin/env python3

import argparse
import base64
import json
import subprocess
import os
import sys


def get_md5_fingerprint(cert_path="/etc/fptn/server.crt"):
    if not os.path.exists(cert_path):
        print(f"Certificate file not found: {cert_path}", file=sys.stderr)
        sys.exit(1)
    try:
        cmd = ["openssl", "x509", "-noout", "-fingerprint", "-md5", "-in", cert_path]
        output = subprocess.check_output(cmd).decode("utf-8").strip()
        # Output format: MD5 Fingerprint=AB:CD:EF:...
        fingerprint = output.split("=")[1].replace(":", "").lower()
        return fingerprint
    except subprocess.CalledProcessError as e:
        print(f"Error computing MD5 fingerprint: {e}", file=sys.stderr)
        sys.exit(1)


def generate_token(username, password, server_ip, service_name, md5_fingerprint):
    token_data = {
        "version": 1,
        "service_name": service_name,
        "username": username,
        "password": password,
        "servers": [{"name": service_name, "host": server_ip, "md5_fingerprint": md5_fingerprint, "port": 443}],
    }

    json_str = json.dumps(token_data, separators=(",", ":"))
    b64_bytes = base64.b64encode(json_str.encode("utf-8"))
    b64_str = b64_bytes.decode("utf-8").rstrip("=")
    return f"fptn:{b64_str}"


def main():
    parser = argparse.ArgumentParser(description="FPTN VPN Token Generator")
    parser.add_argument("--user", required=True, help="VPN username")
    parser.add_argument("--password", required=True, help="VPN password")
    parser.add_argument("--server-ip", required=True, help="VPN server public IP")
    parser.add_argument("--service-name", default="MyFptnServer", help="VPN service name")
    parser.add_argument("--cert-path", default="/etc/fptn/server.crt", help="Path to server certificate")

    args = parser.parse_args()

    md5_fingerprint = get_md5_fingerprint(args.cert_path)
    token = generate_token(
        username=args.user,
        password=args.password,
        server_ip=args.server_ip,
        service_name=args.service_name,
        md5_fingerprint=md5_fingerprint,
    )
    print(token)


if __name__ == "__main__":
    main()
