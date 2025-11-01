/*=============================================================================
Copyright (c) 2024-2025 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#pragma once

#include <iostream>
#include <memory>
#include <mutex>
#include <thread>
#include <utility>
#include <vector>

#include <boost/asio.hpp>
#include <boost/asio/strand.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/ssl.hpp>

#include "fptn-protocol-lib/https/obfuscator/methods/obfuscator_interface.h"

namespace fptn::protocol::https::obfuscator {

// Need to refactor
template <typename Stream>
class TcpStream {
 public:
  using executor_type = typename Stream::executor_type;
  using next_layer_type = Stream;
  using lowest_layer_type = Stream;

  explicit TcpStream(executor_type ex)
      : stream_(ex), strand_(ex), obfuscator_(nullptr) {}

  explicit TcpStream(executor_type ex, IObfuscatorSPtr obfuscator = nullptr)
      : stream_(ex), strand_(ex), obfuscator_(std::move(obfuscator)) {}

  explicit TcpStream(Stream&& stream, IObfuscatorSPtr obfuscator = nullptr)
      : stream_(std::move(stream)),
        strand_(stream_.get_executor()),
        obfuscator_(std::move(obfuscator)) {}

  TcpStream(const TcpStream&) = delete;
  TcpStream& operator=(const TcpStream&) = delete;

  TcpStream(TcpStream&& other) noexcept
      : stream_(std::move(other.stream_)),
        strand_(std::move(other.strand_)),
        obfuscator_(std::move(other.obfuscator_)) {}

  TcpStream& operator=(TcpStream&& other) noexcept {
    if (this != &other) {
      stream_ = std::move(other.stream_);
      strand_ = std::move(other.strand_);
      obfuscator_ = std::move(other.obfuscator_);
    }
    return *this;
  }

  executor_type get_executor() { return stream_.get_executor(); }

  next_layer_type& next_layer() { return stream_; }

  const next_layer_type& next_layer() const { return stream_; }

  lowest_layer_type& lowest_layer() { return stream_; }

  const lowest_layer_type& lowest_layer() const { return stream_; }

  template <typename MutableBufferSequence>
  std::size_t read_some(
      const MutableBufferSequence& buffers, boost::system::error_code& ec) {
    const std::unique_lock<std::mutex> lock(mutex_);  // mutex

    if (!obfuscator_) {
      return stream_.read_some(buffers, ec);
    }

    constexpr std::size_t kTempBufferSize = 16 * 1024;
    std::array<std::uint8_t, kTempBufferSize> temp_buffer;

    std::size_t bytes_read =
        stream_.read_some(boost::asio::buffer(temp_buffer), ec);
    if (ec || bytes_read == 0) {
      return bytes_read;
    }

    const std::vector<std::uint8_t> deobfuscated =
        obfuscator_->Deobfuscate(temp_buffer.data(), bytes_read);

    if (!deobfuscated.empty()) {
      return boost::asio::buffer_copy(buffers,
          boost::asio::buffer(deobfuscated.data(), deobfuscated.size()));
    }
    return 0;
  }

  template <typename MutableBufferSequence, typename ReadHandler>
  void async_read_some(
      const MutableBufferSequence& buffers, ReadHandler&& handler) {
    if (!obfuscator_) {
      boost::asio::post(
          strand_, [this, buffers,
                       handler = std::forward<ReadHandler>(handler)]() mutable {
            stream_.async_read_some(buffers, std::move(handler));
          });
      return;
    }

    boost::asio::post(strand_, [this, buffers,
                                   handler = std::forward<ReadHandler>(
                                       handler)]() mutable {
      stream_.async_read_some(buffers,
          [this, buffers, handler = std::move(handler)](
              boost::system::error_code ec, std::size_t bytes_read) mutable {
            if (ec || bytes_read == 0) {
              handler(ec, bytes_read);
              return;
            }

            if (has_single_buffer(buffers)) {
              const auto& it = boost::asio::buffer_sequence_begin(buffers);
              const boost::asio::mutable_buffer& first_buffer = *it;
              const std::uint8_t* data_ptr =
                  static_cast<std::uint8_t*>(first_buffer.data());

              std::vector<std::uint8_t> deobfuscated =
                  obfuscator_->Deobfuscate(data_ptr, bytes_read);

              const std::size_t bytes_copied = boost::asio::buffer_copy(
                  buffers, boost::asio::buffer(deobfuscated));
              handler(ec, bytes_copied);
            } else {
              std::vector<std::uint8_t> temp_data(bytes_read);
              boost::asio::buffer_copy(boost::asio::buffer(temp_data), buffers);

              std::vector<std::uint8_t> deobfuscated =
                  obfuscator_->Deobfuscate(temp_data.data(), bytes_read);

              const std::size_t bytes_copied = boost::asio::buffer_copy(
                  buffers, boost::asio::buffer(deobfuscated));
              handler(ec, bytes_copied);
            }
          });
    });
  }

  template <typename ConstBufferSequence>
  std::size_t write_some(
      const ConstBufferSequence& buffers, boost::system::error_code& ec) {
    const std::unique_lock<std::mutex> lock(mutex_);  // mutex

    if (!obfuscator_) {
      return stream_.write_some(buffers, ec);
    }

    std::vector<std::uint8_t> plain_data(boost::asio::buffer_size(buffers));
    boost::asio::buffer_copy(boost::asio::buffer(plain_data), buffers);

    std::vector<std::uint8_t> obfuscated =
        obfuscator_->Obfuscate(plain_data.data(), plain_data.size());

    if (obfuscated.empty()) {
      ec = boost::asio::error::eof;
      return 0;
    }
    return stream_.write_some(boost::asio::buffer(obfuscated), ec);
  }

  template <typename ConstBufferSequence, typename WriteHandler>
  void async_write_some(
      const ConstBufferSequence& buffers, WriteHandler&& handler) {
    if (!obfuscator_) {
      boost::asio::post(strand_,
          [this, buffers,
              handler = std::forward<WriteHandler>(handler)]() mutable {
            stream_.async_write_some(buffers, std::move(handler));
          });
      return;
    }

    const std::size_t total_size = boost::asio::buffer_size(buffers);
    auto plain_data = std::make_shared<std::vector<std::uint8_t>>(total_size);
    boost::asio::buffer_copy(boost::asio::buffer(*plain_data), buffers);

    boost::asio::post(
        strand_, [this, plain_data,
                     handler = std::forward<WriteHandler>(handler)]() mutable {
          std::vector<std::uint8_t> obfuscated_data =
              obfuscator_->Obfuscate(plain_data->data(), plain_data->size());
          if (obfuscated_data.empty()) {
            handler(boost::system::error_code(boost::asio::error::eof), 0);
            return;
          }

          stream_.async_write_some(
              boost::asio::buffer(obfuscated_data), std::move(handler));
        });
  }

  template <typename... Args>
  auto async_connect(Args&&... args) {
    return stream_.async_connect(std::forward<Args>(args)...);
  }

  void close() {
    const std::unique_lock<std::mutex> lock(mutex_);  // mutex

    stream_.close();
  }

  void close(boost::system::error_code& ec) {
    const std::unique_lock<std::mutex> lock(mutex_);  // mutex

    stream_.close(ec);
  }

  template <typename Option>
  void set_option(const Option& option) {
    const std::unique_lock<std::mutex> lock(mutex_);  // mutex

    stream_.set_option(option);
  }

  void expires_after(std::chrono::steady_clock::duration expiry_time) {
    const std::unique_lock<std::mutex> lock(mutex_);  // mutex

    stream_.expires_after(expiry_time);
  }

  void expires_never() {
    const std::unique_lock<std::mutex> lock(mutex_);  // mutex

    stream_.expires_never();
  }

  bool is_open() const {
    const std::unique_lock<std::mutex> lock(mutex_);  // mutex

    return stream_.is_open();
  }

  auto remote_endpoint() {
    const std::unique_lock<std::mutex> lock(mutex_);  // mutex

    return stream_.socket().remote_endpoint();
  }

  auto remote_endpoint(boost::system::error_code& ec) {
    const std::unique_lock<std::mutex> lock(mutex_);  // mutex

    return stream_.socket().remote_endpoint(ec);
  }

  auto local_endpoint() {
    const std::unique_lock<std::mutex> lock(mutex_);  // mutex

    return stream_.socket().local_endpoint();
  }

  auto local_endpoint(boost::system::error_code& ec) {
    const std::unique_lock<std::mutex> lock(mutex_);  // mutex

    return stream_.socket().local_endpoint(ec);
  }

  void set_obfuscator(IObfuscatorSPtr obfuscator) {
    const std::unique_lock<std::mutex> lock(mutex_);  // mutex

    obfuscator_ = std::move(obfuscator);
  }

 protected:
  template <typename Sequence>
  static bool has_single_buffer(const Sequence& buffers) {
    // REWRITE IT
    std::size_t count = 0;
    auto end = boost::asio::buffer_sequence_end(buffers);
    for (auto it = boost::asio::buffer_sequence_begin(buffers); it != end;
        ++it) {
      ++count;
    }
    return count == 1;
  }

 private:
  mutable std::mutex mutex_;
  Stream stream_;
  boost::asio::strand<executor_type> strand_;
  IObfuscatorSPtr obfuscator_;
};

}  // namespace fptn::protocol::https::obfuscator

namespace boost::beast {

template <typename AsyncStream>
inline void teardown(boost::beast::role_type role,
    fptn::protocol::https::obfuscator::TcpStream<AsyncStream>& stream,
    boost::system::error_code& ec) {
  teardown(role, stream.next_layer(), ec);
}

template <typename AsyncStream, typename TeardownHandler>
inline void async_teardown(boost::beast::role_type role,
    fptn::protocol::https::obfuscator::TcpStream<AsyncStream>& stream,
    TeardownHandler&& handler) {
  async_teardown(
      role, stream.next_layer(), std::forward<TeardownHandler>(handler));
}

}  // namespace boost::beast
