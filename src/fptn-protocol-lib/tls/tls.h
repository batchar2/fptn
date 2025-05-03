/*=============================================================================
Copyright (c) 2024-2025 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#pragma once

#include <string>

#include <openssl/ssl.h>  // NOLINT(build/include_order)

namespace fptn::protocol::tls {

std::string GetSHA1Hash(std::uint32_t number);
std::string GenerateFptnKey(std::uint32_t timestamp);
bool SetHandshakeSessionID(SSL* ssl);

bool IsFptnClientSessionID(
    const std::uint8_t* session, std::size_t session_len);

bool SetHandshakeSni(SSL* ssl, const std::string& sni);

SSL_CTX* CreateNewSslCtx();

std::string ChromeCiphers();

}  // namespace fptn::protocol::tls
cm