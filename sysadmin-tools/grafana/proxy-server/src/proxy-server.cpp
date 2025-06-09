/*=============================================================================
Copyright (c) 2024-2025 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#include <iostream>
#include <memory>
#include <string>

#define CPPHTTPLIB_OPENSSL_SUPPORT
#include <argparse/argparse.hpp>  // NOLINT(build/include_order)
#include <httplib/httplib.h>      // NOLINT(build/include_order)

#include "fptn-protocol-lib/https/https_client.h"

class ProxyServer {
 public:
  ProxyServer(const std::string& target_host, int target_port)
      : target_host_(target_host), target_port_(target_port) {}

  void Run(int listen_port) {
    httplib::Server server;

    server.Get(
        "/.*", [this](const httplib::Request& req, httplib::Response& res) {
          this->handleRequest(req, res);
        });

    std::cerr << "Proxy server running on port " << listen_port
              << ", forwarding to " << target_host_ << ":" << target_port_
              << std::endl;
    server.listen("0.0.0.0", listen_port);
  }

 protected:
  void handleRequest(const httplib::Request& req, httplib::Response& res) {
    fptn::protocol::https::HttpsClient client(
        target_host_, target_port_, "fptn.org");

    const auto response = client.Get(req.path);
    if (res.status != 200) {
      std::cerr << "Proxy returned error! " << " Status=" << res.status
                << " Msg=" << response.errmsg << std::endl;
    }
    res.status = response.code;
    res.body = response.body;
  }

 private:
  std::string target_host_;
  int target_port_;
};

int main(int argc, char* argv[]) {
  argparse::ArgumentParser args("http-proxy", "1.0.0");
  // Required arguments
  args.add_argument("--target-host")
      .required()
      .help("Target host to proxy requests to (e.g., example.com)");
  // Optional arguments
  args.add_argument("--target-port")
      .help("Target port (default: 443)")
      .default_value(443)
      .scan<'i', int>();
  args.add_argument("--listen-port")
      .help("Port to listen on (default: 8080)")
      .default_value(8080)
      .scan<'i', int>();
  try {
    args.parse_args(argc, argv);

    // Get argument values
    const auto target_host = args.get<std::string>("--target-host");
    const auto target_port = args.get<int>("--target-port");
    const auto listen_port = args.get<int>("--listen-port");

    ProxyServer proxy(target_host, target_port);
    proxy.Run(listen_port);
  } catch (const std::exception& err) {
    std::cerr << "Error: " << err.what() << std::endl;
    std::cerr << args;
    return EXIT_FAILURE;
  }
  return EXIT_SUCCESS;
}
