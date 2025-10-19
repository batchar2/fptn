/*=============================================================================
Copyright (c) 2024-2025 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#pragma once

#include <array>
#include <functional>
#include <memory>
#include <thread>
#include <utility>
#include <vector>

#include <boost/asio.hpp>
#include <boost/asio/buffer.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/beast.hpp>

#include "common/network/ip_packet.h"

#include "fptn-protocol-lib/https/obfuscator/methods/obfuscator_interface.h"

namespace fptn::protocol::https::obfuscator {

class Socket : public std::enable_shared_from_this<Socket> {
 public:
  using next_layer_type = boost::asio::ip::tcp::socket;
  using executor_type = next_layer_type::executor_type;
  using endpoint_type = next_layer_type::endpoint_type;
  using lowest_layer_type = next_layer_type;

  explicit Socket(const executor_type& ex);
  explicit Socket(const executor_type& ex, IObfuscatorSPtr obfuscator);

  explicit Socket(next_layer_type&& socket);
  explicit Socket(next_layer_type&& socket, IObfuscatorSPtr obfuscator);

  void SetObfuscator(IObfuscatorSPtr obfuscator);

  next_layer_type& next_layer();
  const next_layer_type& next_layer() const;

  lowest_layer_type& lowest_layer();
  const lowest_layer_type& lowest_layer() const;

  executor_type get_executor();
  template <typename MutableBufferSequence, typename ReadHandler>
  void async_read_some(
      const MutableBufferSequence& buffers, ReadHandler&& handler) {
    auto self = shared_from_this();

    const std::size_t kBuffSize = boost::asio::buffer_size(buffers) / 2;
    auto chunk = std::make_shared<std::vector<std::uint8_t>>(kBuffSize);

    socket_.async_read_some(boost::asio::buffer(*chunk),
        [self, buffers, chunk, handler = std::forward<ReadHandler>(handler)](
            boost::system::error_code ec, std::size_t bytes_read) mutable {
          std::size_t prepared_bytes = 0;

          if (!self->obfuscator_) {
            handler(boost::asio::error::not_connected, 0);
            return;
          }

          if (ec) {
            handler(ec, 0);
            return;
          }

          {
            const std::lock_guard<std::mutex> lock(self->mutex_);

            if (bytes_read > 0) {
              std::vector<std::uint8_t> out_data;

              // ИСПРАВЛЕНИЕ 1: Передаем bytes_read вместо chunk->size()
              self->obfuscator_->Deobfuscate(
                  chunk->data(), bytes_read, out_data);

              if (!out_data.empty()) {
                prepared_bytes = boost::asio::buffer_copy(
                    buffers, boost::asio::buffer(out_data));

                // // ИСПРАВЛЕНИЕ 3: Сохраняем остаток в output_buffer_
                // if (prepared_bytes < out_data.size()) {
                //   self->output_buffer_.insert(self->output_buffer_.end(),
                //       out_data.begin() + prepared_bytes, out_data.end());
                // // }
                //
                // std::cerr << "Read " << bytes_read << " bytes, "
                //           << "Deobfuscated to " << out_data.size() << " bytes, "
                //           << "Copied " << prepared_bytes << " bytes, "
                //           << "Buffer leftover: "
                //           << (out_data.size() - prepared_bytes) << std::endl;
              }
            }
          }
          handler(ec, prepared_bytes);
        });
  }


  template <typename MutableBufferSequence>
  std::size_t read_some(
      const MutableBufferSequence& buffers, boost::system::error_code& ec) {
    std::lock_guard<std::mutex> lock(mutex_);  // mutex

    if (!obfuscator_) {
      ec = boost::asio::error::not_connected;
      return 0;
    }

    if (!output_buffer_.empty()) {
      std::size_t bytes_copied = boost::asio::buffer_copy(
          buffers, boost::asio::buffer(output_buffer_));
      output_buffer_.erase(
          output_buffer_.begin(), output_buffer_.begin() + bytes_copied);
      return bytes_copied;
    }

    const std::size_t bytes_read = socket_.read_some(buffers, ec);

    if (ec || bytes_read == 0) {
      return 0;
    }

    if (obfuscator_) {
      auto buffer_it = boost::asio::buffer_sequence_begin(buffers);
      auto buffer = *buffer_it;
      auto* data = static_cast<std::uint8_t*>(const_cast<void*>(buffer.data()));

      std::vector<std::uint8_t> input_data(data, data + bytes_read);
      std::vector<std::uint8_t> output_data;

      obfuscator_->Deobfuscate(
          input_data.data(), input_data.size(), output_data);

      if (!output_data.empty()) {
        std::size_t buffer_size = boost::asio::buffer_size(buffers);
        std::size_t bytes_to_copy = std::min(output_data.size(), buffer_size);

        std::memcpy(data, output_data.data(), bytes_to_copy);

        if (output_data.size() > bytes_to_copy) {
          output_buffer_.insert(output_buffer_.end(),
              output_data.begin() + bytes_to_copy, output_data.end());
        }

        return bytes_to_copy;
      }
      return 0;
    }
    return bytes_read;
  }

  // template <typename MutableBufferSequence, typename ReadHandler>
  // void async_read_some(
  //     const MutableBufferSequence& buffers, ReadHandler&& handler) {
  //   auto self = shared_from_this();
  //   (void)output_buffer_;
  //   const std::size_t kBuffSize = boost::asio::buffer_size(buffers) / 2;
  //   auto temp_buffer =
  //   std::make_shared<std::vector<std::uint8_t>>(kBuffSize);
  //
  //   socket_.async_read_some(boost::asio::buffer(*temp_buffer),
  //       [self, buffers, temp_buffer,
  //           handler = std::forward<ReadHandler>(handler)](
  //           boost::system::error_code ec, std::size_t bytes_read) mutable {
  //         std::size_t prepared_bytes = 0;
  //
  //         if (!self->obfuscator_) {
  //           ec = boost::asio::error::not_connected;
  //           return;
  //         }
  //
  //         {
  //           const std::lock_guard<std::mutex> lock(self->mutex_);
  //
  //           if (bytes_read > 0 && self->obfuscator_) {
  //             std::vector<std::uint8_t> out_data;
  //
  //             self->obfuscator_->Deobfuscate(
  //                 temp_buffer->data(), temp_buffer->size(), out_data);
  //
  //             if (!out_data.empty()) {
  //               // prepared_bytes = boost::asio::buffer_copy(
  //               //     buffers, boost::asio::buffer(out_data));
  //               auto buffer_it = boost::asio::buffer_sequence_begin(buffers);
  //               auto buffer = *buffer_it;
  //               auto* data = static_cast<std::uint8_t*>(
  //                   const_cast<void*>(buffer.data()));
  //               std::memcpy(data, out_data.data(), out_data.size());
  //               prepared_bytes = out_data.size();
  //
  //               std::cerr << "Buffer size: "
  //                         << boost::asio::buffer_size(buffers)
  //                         << ", Output data: " << out_data.size()
  //                         << ", Prepared bytes: " << prepared_bytes
  //                         << std::endl;
  //             }
  //           }
  //         }
  //         handler(ec, prepared_bytes);
  //       });
  // }

  // template <typename MutableBufferSequence>
  // std::size_t read_some(
  //     const MutableBufferSequence& buffers, boost::system::error_code& ec) {
  //   std::lock_guard<std::mutex> lock(mutex_);  // mutex
  //
  //   if (!obfuscator_) {
  //     ec = boost::asio::error::not_connected;
  //     return 0;
  //   }
  //
  //   if (!output_buffer_.empty()) {
  //     std::size_t bytes_copied = boost::asio::buffer_copy(
  //         buffers, boost::asio::buffer(output_buffer_));
  //     output_buffer_.erase(
  //         output_buffer_.begin(), output_buffer_.begin() + bytes_copied);
  //     return bytes_copied;
  //   }
  //
  //   const std::size_t bytes_read = socket_.read_some(buffers, ec);
  //
  //   if (ec || bytes_read == 0) {
  //     return 0;
  //   }
  //
  //   if (obfuscator_) {
  //     auto buffer_it = boost::asio::buffer_sequence_begin(buffers);
  //     auto buffer = *buffer_it;
  //     auto* data =
  //     static_cast<std::uint8_t*>(const_cast<void*>(buffer.data()));
  //
  //     std::vector<std::uint8_t> input_data(data, data + bytes_read);
  //     std::vector<std::uint8_t> output_data;
  //
  //     obfuscator_->Deobfuscate(
  //         input_data.data(), input_data.size(), output_data);
  //
  //     if (!output_data.empty()) {
  //       std::size_t buffer_size = boost::asio::buffer_size(buffers);
  //       std::size_t bytes_to_copy = std::min(output_data.size(),
  //       buffer_size);
  //
  //       std::memcpy(data, output_data.data(), bytes_to_copy);
  //
  //       if (output_data.size() > bytes_to_copy) {
  //         output_buffer_.insert(output_buffer_.end(),
  //             output_data.begin() + bytes_to_copy, output_data.end());
  //       }
  //
  //       return bytes_to_copy;
  //     }
  //     return 0;
  //   }
  //   return bytes_read;
  // }

  template <typename ConstBufferSequence, typename WriteHandler>
  void async_write_some(
      const ConstBufferSequence& buffers, WriteHandler&& handler) {
    std::vector<std::uint8_t> plain_data;
    std::size_t total_size = boost::asio::buffer_size(buffers);
    plain_data.reserve(total_size);

    for (auto it = boost::asio::buffer_sequence_begin(buffers);
        it != boost::asio::buffer_sequence_end(buffers); ++it) {
      auto buffer = *it;
      const auto* data = static_cast<const uint8_t*>(buffer.data());
      plain_data.insert(plain_data.end(), data, data + buffer.size());
    }

    auto obfuscated_data = obfuscator_->Obfuscate(plain_data);

    auto obfuscated_buffer =
        std::make_shared<std::vector<std::uint8_t>>(std::move(obfuscated_data));

    auto self = shared_from_this();
    boost::asio::async_write(socket_, boost::asio::buffer(*obfuscated_buffer),
        [self, obfuscated_buffer, handler = std::forward<WriteHandler>(handler),
            plain_size = plain_data.size()](
            boost::system::error_code ec, std::size_t /*written*/) mutable {
          handler(ec, ec ? 0 : plain_size);
        });
  }

  template <typename ConstBufferSequence>
  std::size_t write_some(
      const ConstBufferSequence& buffers, boost::system::error_code& ec) {
    std::vector<std::uint8_t> plain_data;
    std::size_t total_size = boost::asio::buffer_size(buffers);
    plain_data.reserve(total_size);

    for (auto it = boost::asio::buffer_sequence_begin(buffers);
        it != boost::asio::buffer_sequence_end(buffers); ++it) {
      auto buffer = *it;
      const auto* data = static_cast<const std::uint8_t*>(buffer.data());
      plain_data.insert(plain_data.end(), data, data + buffer.size());
    }
    auto obfuscated_data = obfuscator_->Obfuscate(plain_data);
    return socket_.write_some(boost::asio::buffer(obfuscated_data), ec);
  }

  // Other methods
  template <typename ConnectHandler>
  void async_connect(
      const endpoint_type& peer_endpoint, ConnectHandler&& handler) {
    socket_.async_connect(peer_endpoint, std::forward<ConnectHandler>(handler));
  }

  void close(boost::system::error_code& ec);

  void close();

  bool is_open() const;

  endpoint_type remote_endpoint(boost::system::error_code& ec) const;

  endpoint_type local_endpoint(boost::system::error_code& ec) const;

  template <typename Option>
  void set_option(const Option& option) {
    socket_.set_option(option);
  }

  void expires_after(std::chrono::steady_clock::duration timeout);
  void expires_never();

 private:
  mutable std::mutex mutex_;
  next_layer_type socket_;
  IObfuscatorSPtr obfuscator_;
  std::vector<std::uint8_t> temp_read_buffer_;
  std::vector<std::uint8_t> output_buffer_;  // Buffer for ready-to-read data
};

// External functions for working with Socket
void teardown(boost::beast::role_type role,
    Socket& socket,
    boost::system::error_code& ec);

template <typename TeardownHandler>
void async_teardown(
    boost::beast::role_type role, Socket& socket, TeardownHandler&& handler) {
  boost::system::error_code ec;
  teardown(role, socket, ec);
  std::forward<TeardownHandler>(handler)(ec);
}

using SocketSPtr = std::shared_ptr<Socket>;

}  // namespace fptn::protocol::https::obfuscator
