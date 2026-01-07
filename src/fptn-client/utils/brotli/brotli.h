/*=============================================================================
Copyright (c) 2024-2025 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#pragma once

#include <string>
#include <vector>

#include <brotli/decode.h>  // NOLINT(build/include_order)

namespace fptn::utils::brotli {
inline std::string Decompress(const std::string& compressed_data) {
  const std::size_t encoded_size = compressed_data.size();
  std::size_t decoded_size = encoded_size * 30;

  while (true) {
    std::vector<std::uint8_t> decoded_buffer(decoded_size);
    std::size_t available_out = decoded_size;

    const BROTLI_BOOL result = BrotliDecoderDecompress(encoded_size,
        reinterpret_cast<const uint8_t*>(compressed_data.data()),
        &available_out, decoded_buffer.data());
    if (result == BROTLI_TRUE) {
      return std::string(
          reinterpret_cast<char*>(decoded_buffer.data()), available_out);
    }
    decoded_size *= 2;
  }
}
}  // namespace fptn::utils::brotli
