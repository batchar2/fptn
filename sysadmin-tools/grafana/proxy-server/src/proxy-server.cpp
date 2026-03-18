/*=============================================================================
Copyright (c) 2024-2026 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#define CPPHTTPLIB_OPENSSL_SUPPORT
#define CPPHTTPLIB_OPENSSL_SUPPORT

#include <fptn-protocol-lib/https/api_client/api_client.h>  // NOLINT(build/include_order)
#include <iostream>
#include <string>

#include <argparse/argparse.hpp>  // NOLINT(build/include_order)
#include <httplib/httplib.h>      // NOLINT(build/include_order)

void run_server(const int port) {
  httplib::Server server;
  server.Get("/metrics", [](const httplib::Request& req, httplib::Response& res) {
    const std::string host = req.get_param_value("host");
    const std::string port_str = req.get_param_value("port");
    const std::string key = req.get_param_value("key");

    if (host.empty() || port_str.empty() || key.empty()) {
      res.status = 400;
      res.body = "Missing required parameters: host, port, key";
      return;
    }
    int port = 443;
    try {
      port = std::stoi(port_str);
    } catch (...) {
      res.status = 400;
      res.body = "Invalid port number";
      return;
    }

    try {
      const std::string target_url = "/api/v1/metrics/" + key;
      std::cout << "Proxying to: " << "https://" << host + ":" << port_str
                << target_url << std::endl;

      fptn::protocol::https::ApiClient client(
          host, port, fptn::protocol::https::CensorshipStrategy::kSni);
      auto response = client.Get(target_url);
      res.status = response.code;
      res.body = response.body;
    } catch (const std::exception& e) {
      res.status = 500;
      res.body = std::string("Proxy error: ") + e.what();
    }
  });
  server.listen("0.0.0.0", port);
}

int main(int argc, char* argv[]) {
  // Proxy server for forwarding requests to external hosts
  // Request format: http://localhost:8080/?host=<host>&port=<port>&key=<key>
  // Example: http://localhost:8080/?host=192.168.1.100&port=443&key=abc123
  argparse::ArgumentParser args("http-proxy", "1.0.1");
  args.add_argument("--listen-port")
      .help("Port to listen on (default: 8080)")
      .default_value(8080)
      .scan<'i', int>();
  try {
    args.parse_args(argc, argv);
    const auto listen_port = args.get<int>("--listen-port");
    run_server(listen_port);
  } catch (const std::exception& err) {
    std::cerr << "Error: " << err.what() << std::endl;
    std::cerr << args;
    return EXIT_FAILURE;
  }
  return EXIT_SUCCESS;
}
