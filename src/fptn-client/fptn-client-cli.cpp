/*=============================================================================
Copyright (c) 2024-2025 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#include <iostream>

#if defined(__linux__) || defined(__APPLE__)
#include <unistd.h>  // NOLINT(build/include_order)
#endif

#include <memory>
#include <string>
#include <utility>

#include <argparse/argparse.hpp>
#include <boost/asio.hpp>
#include <boost/process.hpp>

#include "common/logger/logger.h"
#include "common/network/net_interface.h"

#include "config/config_file.h"
#include "http/client.h"
#include "routing/iptables.h"
#include "vpn/vpn_client.h"

namespace {
void WaitForSignal() {
  boost::asio::io_context io_context;
  boost::asio::signal_set signals(io_context, SIGINT, SIGTERM);
  signals.async_wait([&](auto, auto) { io_context.stop(); });
  io_context.run();
}
}  // namespace

int main(int argc, char* argv[]) {
#if defined(__linux__) || defined(__APPLE__)
  if (geteuid() != 0) {
    std::cerr << "You must be root to run this program." << std::endl;
    return EXIT_FAILURE;
  }
#endif

  try {
    argparse::ArgumentParser args("fptn-client", FPTN_VERSION);
    // Required arguments
    args.add_argument("--access-token").required().help("Access token");
    // Optional arguments
    args.add_argument("--out-network-interface")
        .default_value("")
        .help("Network out interface");
    args.add_argument("--gateway-ip")
        .default_value("0.0.0.0")
        .help("Your default gateway ip");
    args.add_argument("--tun-interface-name")
        .default_value("tun0")
        .help("Network interface name");
    args.add_argument("--tun-interface-ip")
        .default_value(FPTN_CLIENT_DEFAULT_ADDRESS_IP4)
        .help("Network interface IPv4 address");
    args.add_argument("--tun-interface-ipv6")
        .default_value(FPTN_CLIENT_DEFAULT_ADDRESS_IP6)
        .help("Network interface IPv6 address");
    args.add_argument("--tun-interface-ipv6")
        .default_value(FPTN_CLIENT_DEFAULT_ADDRESS_IP6)
        .help("Network interface IPv6 address");
    args.add_argument("--sni")
        .default_value(FPTN_DEFAULT_SNI)
        .help(
            "Domain name for SNI in TLS handshake (used to obfuscate VPN "
            "traffic)");
    // parse cmd arguments
    try {
      args.parse_args(argc, argv);
    } catch (const std::runtime_error& err) {
      std::cerr << err.what() << std::endl;
      std::cerr << args;
      return EXIT_FAILURE;
    }

    if (fptn::logger::init("fptn-client-cli")) {
      SPDLOG_INFO("Application started successfully.");
    } else {
      std::cerr << "Logger initialization failed. Exiting application."
                << std::endl;
      return EXIT_FAILURE;
    }

    /* parse cmd args */
    const auto out_network_interface_name =
        args.get<std::string>("--out-network-interface");
    const auto gateway_ip =
        pcpp::IPv4Address(args.get<std::string>("--gateway-ip"));
    const auto tun_interface_name =
        args.get<std::string>("--tun-interface-name");
    const auto tun_interface_address_ipv4 =
        pcpp::IPv4Address(args.get<std::string>("--tun-interface-ip"));
    const auto tun_interface_address_ipv6 =
        pcpp::IPv6Address(args.get<std::string>("--tun-interface-ipv6"));
    const auto sni = args.get<std::string>("--sni");

    /* check gateway address */
    const auto using_gateway_ip =
        (gateway_ip == pcpp::IPv4Address("0.0.0.0")
                ? fptn::routing::GetDefaultGatewayIPAddress()
                : pcpp::IPv4Address(gateway_ip));
    if (using_gateway_ip == pcpp::IPv4Address("0.0.0.0")) {
      SPDLOG_ERROR(
          "Unable to find the default gateway IP address. "
          "Please check your connection and make sure no other VPN is active. "
          "If the error persists, specify the gateway address in the FPTN "
          "settings using your router's IP "
          "address with the \"--gateway-ip\" option. If the issue "
          "remains unresolved, please contact the developer via Telegram "
          "@fptn_chat.");
      return EXIT_FAILURE;
    }

    /* check config */
    const auto access_token = args.get<std::string>("--access-token");
    fptn::config::ConfigFile config(access_token, sni);
    fptn::config::ConfigFile::Server selected_server;
    try {
      config.Parse();
      selected_server = config.FindFastestServer();
    } catch (std::runtime_error& err) {
      SPDLOG_ERROR("Config error: {}", err.what());
      return EXIT_FAILURE;
    }
    const int server_port = selected_server.port;
    const auto server_ip = fptn::routing::ResolveDomain(selected_server.host);
    if (server_ip == pcpp::IPv4Address("0.0.0.0")) {
      SPDLOG_ERROR("DNS resolve error: {}", selected_server.host);
      return EXIT_FAILURE;
    }

    SPDLOG_INFO(
        "\n--- Starting client ---\n"
        "VERSION:            {}\n"
        "SNI:                {}\n"
        "GATEWAY IP:         {}\n"
        "NETWORK INTERFACE:  {}\n"
        "VPN SERVER NAME:    {}\n"
        "VPN SERVER IP:      {}\n"
        "VPN SERVER PORT:    {}\n"
        "TUN INTERFACE IPv4: {}\n"
        "TUN INTERFACE IPv6: {}\n",
        FPTN_VERSION, sni, using_gateway_ip.toString(),
        out_network_interface_name, selected_server.name, selected_server.host,
        selected_server.port, tun_interface_address_ipv4.toString(),
        tun_interface_address_ipv6.toString());

    /* auth & dns */
    auto http_client =
        std::make_unique<fptn::http::Client>(server_ip, server_port,
            tun_interface_address_ipv4, tun_interface_address_ipv6, sni);
    const bool status =
        http_client->Login(config.GetUsername(), config.GetPassword());
    if (!status) {
      SPDLOG_ERROR("The username or password you entered is incorrect");
      return EXIT_FAILURE;
    }
    const auto [dnsServerIPv4, dnsServerIPv6] = http_client->GetDns();
    if (dnsServerIPv4 == pcpp::IPv4Address("0.0.0.0") ||
        dnsServerIPv6 == pcpp::IPv6Address("")) {
      SPDLOG_ERROR("DNS server error! Check your connection!");
      return EXIT_FAILURE;
    }

    /* tun interface */
    auto virtual_network_interface =
        std::make_unique<fptn::common::network::TunInterface>(
            tun_interface_name,
            /* IPv4 */
            tun_interface_address_ipv4, 30,
            /* IPv6 */
            tun_interface_address_ipv6, 126);

    /* iptables */
    auto iptables = std::make_unique<fptn::routing::IPTables>(
        out_network_interface_name, tun_interface_name, server_ip,
        dnsServerIPv4, dnsServerIPv6, using_gateway_ip,
        tun_interface_address_ipv4, tun_interface_address_ipv6);

    /* vpn client */
    fptn::vpn::VpnClient vpn_client(std::move(http_client),
        std::move(virtual_network_interface), dnsServerIPv4, dnsServerIPv6);

    /* loop */
    vpn_client.Start();

    // Wait for the WebSocket tunnel to establish
    constexpr std::chrono::seconds kTimeout(10);
    const auto start = std::chrono::steady_clock::now();
    while (!vpn_client.IsStarted()) {
      if (std::chrono::steady_clock::now() - start > kTimeout) {
        SPDLOG_ERROR("Couldn't open websocket tunnel!");
        return EXIT_FAILURE;
      }
      std::this_thread::sleep_for(std::chrono::microseconds(200));
    }

    // start
    iptables->Apply();
    WaitForSignal();

    /* clean */
    iptables->Clean();
    vpn_client.Stop();
    spdlog::shutdown();

    return EXIT_SUCCESS;
  } catch (const std::exception& ex) {
    SPDLOG_ERROR("An error occurred: {}. Exiting...", ex.what());
  } catch (...) {
    SPDLOG_ERROR("An unknown error occurred. Exiting...");
  }
  return EXIT_FAILURE;
}
