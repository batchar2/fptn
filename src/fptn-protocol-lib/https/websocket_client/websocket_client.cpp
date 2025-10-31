/*=============================================================================
Copyright (c) 2024-2025 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#include "fptn-protocol-lib/https/websocket_client/websocket_client.h"

#include <memory>
#include <string>
#include <utility>

#include <spdlog/spdlog.h>  // NOLINT(build/include_order)

#include "fptn-protocol-lib/https/api_client/api_client.h"
#include "fptn-protocol-lib/https/obfuscator/methods/none/none_obfuscator.h"
namespace fptn::protocol::https {

WebsocketClient::WebsocketClient(pcpp::IPv4Address server_ip,
    int server_port,
    pcpp::IPv4Address tun_interface_address_ipv4,
    pcpp::IPv6Address tun_interface_address_ipv6,
    NewIPPacketCallback new_ip_pkt_callback,
    std::string sni,
    std::string access_token,
    std::string expected_md5_fingerprint,
    obfuscator::IObfuscatorSPtr obfuscator,
    OnConnectedCallback on_connected_callback)
    : ctx_(fptn::protocol::https::utils::CreateNewSslCtx()),
      resolver_(boost::asio::make_strand(ioc_)),
      obfuscator_(std::move(obfuscator)),
      ws_(ssl_stream_type(
          obfuscator_socket_type(boost::asio::make_strand(ioc_), obfuscator_),
          ctx_)),
      server_ip_(server_ip),
      server_port_str_(std::to_string(server_port)),
      tun_interface_address_ipv4_(tun_interface_address_ipv4),
      tun_interface_address_ipv6_(tun_interface_address_ipv6),
      new_ip_pkt_callback_(std::move(new_ip_pkt_callback)),
      sni_(std::move(sni)),
      access_token_(std::move(access_token)),
      expected_md5_fingerprint_(std::move(expected_md5_fingerprint)),
      on_connected_callback_(std::move(on_connected_callback)) {
  // Настройка SSL - теперь через ws_.next_layer()
  auto* ssl = ws_.next_layer().native_handle();
  fptn::protocol::https::utils::SetHandshakeSni(ssl, sni_);
  fptn::protocol::https::utils::SetHandshakeSessionID(ssl);

  // Настройка верификации сертификата
  fptn::protocol::https::utils::AttachCertificateVerificationCallback(
      ssl, [this](const std::string& md5_fingerprint) mutable {
        if (md5_fingerprint == expected_md5_fingerprint_) {
          SPDLOG_INFO("Certificate verified successfully (MD5 matched: {}).",
              md5_fingerprint);
          return true;
        }
        SPDLOG_ERROR(
            "Certificate MD5 mismatch. Expected: {}, got: {}. Please update "
            "your token.",
            expected_md5_fingerprint_, md5_fingerprint);
        return false;
      });

  // Настройка WebSocket
  ws_.text(false);
  ws_.binary(true);
  ws_.auto_fragment(true);
  ws_.read_message_max(128 * 1024);
  ws_.set_option(boost::beast::websocket::stream_base::timeout::suggested(
      boost::beast::role_type::client));
}

WebsocketClient::~WebsocketClient() {
  Stop();

  // Очистка SSL callback
  if (auto* ssl = ws_.next_layer().native_handle()) {
    fptn::protocol::https::utils::AttachCertificateVerificationCallbackDelete(
        ssl);
  }
}

void WebsocketClient::Run() {
  try {
    if (running_.exchange(true)) {
      SPDLOG_WARN("WebsocketClient is already running");
      return;
    }

    SPDLOG_INFO("Connecting to {}:{}", server_ip_.toString(), server_port_str_);

    if (obfuscator_) {
      obfuscator_->Reset();
    }

    resolver_.async_resolve(server_ip_.toString(), server_port_str_,
        boost::beast::bind_front_handler(
            &WebsocketClient::onResolve, shared_from_this()));

    th_ = std::thread([this]() {
      SPDLOG_DEBUG("Starting IO context");
      ioc_.run();
      SPDLOG_DEBUG("IO context stopped");
    });

  } catch (const std::exception& e) {
    SPDLOG_ERROR("Exception in Run: {}", e.what());
    running_ = false;
  }
}

bool WebsocketClient::Stop() {
  if (!running_.exchange(false)) {
    return false;
  }

  SPDLOG_INFO("Stopping WebsocketClient");

  was_connected_ = false;

  boost::system::error_code ec;

  // Закрываем WebSocket
  try {
    if (ws_.is_open()) {
      ws_.close(boost::beast::websocket::close_code::normal, ec);
      if (ec) {
        SPDLOG_WARN("WebSocket close error: {}", ec.message());
      }
    }
  } catch (const std::exception& e) {
    SPDLOG_ERROR("Exception during WebSocket close: {}", e.what());
  }

  // Закрываем SSL
  try {
    auto& ssl = ws_.next_layer();
    if (ssl.native_handle()) {
      SSL_set_quiet_shutdown(ssl.native_handle(), 1);
      SSL_shutdown(ssl.native_handle());
    }
    ssl.shutdown(ec);
  } catch (const std::exception& e) {
    SPDLOG_ERROR("Exception during SSL shutdown: {}", e.what());
  }

  // Закрываем TCP соединение
  try {
    get_obfuscator_layer().close();
  } catch (const std::exception& e) {
    SPDLOG_ERROR("Exception during TCP shutdown: {}", e.what());
  }

  // Останавливаем IO context
  try {
    ioc_.stop();
  } catch (const std::exception& e) {
    SPDLOG_ERROR("Exception while stopping IO context: {}", e.what());
  }

  // Ждем завершения потока
  if (th_.joinable()) {
    th_.join();
  }

  // Очищаем очередь
  std::lock_guard<std::mutex> lock(mutex_);
  while (!out_queue_.empty()) {
    out_queue_.pop();
  }

  SPDLOG_INFO("WebsocketClient stopped successfully");
  return true;
}

void WebsocketClient::onResolve(const boost::beast::error_code& ec,
    const boost::asio::ip::tcp::resolver::results_type& results) {
  if (ec) {
    return Fail(ec, "resolve");
  }

  SPDLOG_DEBUG("Resolved successfully, connecting...");

  // Устанавливаем таймаут
  get_obfuscator_layer().expires_after(std::chrono::seconds(30));

  // Подключаемся к серверу через obfuscator_socket
  get_obfuscator_layer().async_connect(
      results, boost::beast::bind_front_handler(
                   &WebsocketClient::onConnect, shared_from_this()));
}

void WebsocketClient::onConnect(const boost::beast::error_code& ec,
    const boost::asio::ip::tcp::resolver::results_type::endpoint_type& ep) {
  (void)ep;
  if (ec) {
    return Fail(ec, "connect");
  }

  SPDLOG_DEBUG("Connected to {}:{}", ep.address().to_string(), ep.port());

  // Устанавливаем таймаут
  get_obfuscator_layer().expires_after(std::chrono::seconds(30));

  // Выполняем SSL handshake
  ws_.next_layer().async_handshake(boost::asio::ssl::stream_base::client,
      boost::beast::bind_front_handler(
          &WebsocketClient::onSslHandshake, shared_from_this()));
}

void WebsocketClient::onSslHandshake(const boost::beast::error_code& ec) {
  if (ec) {
    return Fail(ec, "ssl_handshake");
  }

  SPDLOG_DEBUG("SSL handshake completed");

  // Сбрасываем таймаут
  get_obfuscator_layer().expires_never();

  // Устанавливаем декоратор для WebSocket handshake
  ws_.set_option(boost::beast::websocket::stream_base::decorator(
      [this](boost::beast::websocket::request_type& req) {
        const auto headers = fptn::protocol::https::RealBrowserHeaders(sni_);
        for (const auto& [key, value] : headers) {
          req.set(key, value);
        }
        req.set("Authorization", "Bearer " + access_token_);
        req.set("ClientIP", tun_interface_address_ipv4_.toString());
        req.set("ClientIPv6", tun_interface_address_ipv6_.toString());
        req.set("Client-Agent", "FptnClient/1.0");
      }));

  // Выполняем WebSocket handshake
  ws_.async_handshake(server_ip_.toString(), kUrlWebSocket_,
      boost::beast::bind_front_handler(
          &WebsocketClient::onHandshake, shared_from_this()));
}

void WebsocketClient::onHandshake(const boost::beast::error_code& ec) {
  if (ec) {
    return Fail(ec, "handshake");
  }

  was_connected_ = true;
  SPDLOG_INFO("WebSocket connection established successfully");

  // Настраиваем таймауты WebSocket
  boost::beast::websocket::stream_base::timeout timeout_option;
  timeout_option.handshake_timeout = std::chrono::seconds(10);
  timeout_option.idle_timeout = std::chrono::seconds(30);
  timeout_option.keep_alive_pings = true;
  ws_.set_option(timeout_option);

  // Вызываем callback подключения
  if (on_connected_callback_) {
    on_connected_callback_();
  }

  // Начинаем чтение
  DoRead();
}

void WebsocketClient::DoRead() {
  if (!running_ || !ws_.is_open()) {
    return;
  }

  ws_.async_read(buffer_, boost::beast::bind_front_handler(
                              &WebsocketClient::onRead, shared_from_this()));
}

void WebsocketClient::onRead(
    const boost::beast::error_code& ec, std::size_t transferred) {
  (void)transferred;
  if (ec) {
    return Fail(ec, "read");
  }

  SPDLOG_DEBUG("Received {} bytes", transferred);

  if (buffer_.size() > 0) {
    // Обрабатываем полученные данные
    std::string data = boost::beast::buffers_to_string(buffer_.data());

    // Извлекаем payload из protobuf
    std::string raw = protobuf::GetProtoPayload(std::move(data));

    // Парсим IP пакет (заглушка - замените на реальную реализацию)
    auto packet = fptn::common::network::IPPacket::Parse(std::move(raw));

    if (running_ && packet) {
      new_ip_pkt_callback_(std::move(packet));
    }

    buffer_.consume(buffer_.size());
  }

  // Продолжаем чтение
  DoRead();
}

bool WebsocketClient::Send(fptn::common::network::IPPacketPtr packet) {
  if (!running_ || !was_connected_) {
    return false;
  }

  std::lock_guard<std::mutex> lock(mutex_);

  if (out_queue_.size() >= kMaxSizeOutQueue_) {
    SPDLOG_WARN("Send queue is full, dropping packet");
    return false;
  }

  out_queue_.push(std::move(packet));

  // Если это первое сообщение в очереди, запускаем отправку
  if (out_queue_.size() == 1) {
    DoWrite();
  }

  return true;
}

void WebsocketClient::DoWrite() {
  if (!running_ || !ws_.is_open()) {
    return;
  }

  std::lock_guard<std::mutex> lock(mutex_);
  if (out_queue_.empty()) {
    return;
  }

  auto packet = std::move(out_queue_.front());

  // Создаем protobuf сообщение (заглушка)
  std::string message = protobuf::CreateProtoPayload(std::move(packet));

  ws_.async_write(boost::asio::buffer(message),
      boost::beast::bind_front_handler(
          &WebsocketClient::onWrite, shared_from_this()));
}

void WebsocketClient::onWrite(
    const boost::beast::error_code& ec, std::size_t bytes_transferred) {
  (void)bytes_transferred;
  if (ec) {
    return Fail(ec, "write");
  }

  SPDLOG_DEBUG("Sent {} bytes", bytes_transferred);

  std::lock_guard<std::mutex> lock(mutex_);
  if (!out_queue_.empty()) {
    out_queue_.pop();
  }

  // Если в очереди еще есть сообщения, продолжаем отправку
  if (!out_queue_.empty()) {
    DoWrite();
  }
}

void WebsocketClient::Fail(
    const boost::beast::error_code& ec, const char* what) {
  if (running_) {
    SPDLOG_ERROR("{} failed: {} (code: {})", what, ec.message(), ec.value());
  }
  Stop();
}

bool WebsocketClient::IsStarted() { return running_ && was_connected_; }

}  // namespace fptn::protocol::https
