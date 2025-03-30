#pragma once

#include <string>
#include <memory>
#include <sstream>
#include <unordered_map>

#include <fmt/format.h>
#include <openssl/ssl.h>
#include <nlohmann/json.hpp>

#include <zlib.h>

#include <boost/asio/strand.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/connect.hpp>
#include <boost/asio/ssl/error.hpp>
#include <boost/asio/ssl/stream.hpp>

#include <boost/beast/ssl.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/version.hpp>

#include <boost/iostreams/copy.hpp>
#include <boost/iostreams/filter/gzip.hpp>
#include <boost/iostreams/filtering_stream.hpp>
#include <boost/iostreams/filtering_streambuf.hpp>


namespace fptn::common::https
{

    inline std::string chromeCiphers() noexcept
    {
        /* Google Chrome 56, Windows 10, April 2017 */
        return "ECDHE-ECDSA-AES128-GCM-SHA256:"
               "ECDHE-RSA-AES128-GCM-SHA256:"
               "ECDHE-ECDSA-AES256-GCM-SHA384:"
               "ECDHE-RSA-AES256-GCM-SHA384:"
               "ECDHE-ECDSA-CHACHA20-POLY1305:"
               "ECDHE-RSA-CHACHA20-POLY1305:"
               "ECDHE-RSA-AES128-CBC-SHA:"
               "ECDHE-RSA-AES256-CBC-SHA:"
               "RSA-AES128-GCM-SHA256:"
               "RSA-AES256-GCM-SHA384:"
               "RSA-AES128-CBC-SHA:"
               "RSA-AES256-CBC-SHA:"
               "RSA-3DES-EDE-CBC-SHA";
    }

    using Headers = std::unordered_map<std::string, std::string>;
    inline Headers realBrowserHeaders(const std::string& host, int port) noexcept
    {
        /* Just to ensure that FPTN is as similar to a web browser as possible. */
        const std::string hostHeader = (port == 443 ? host : fmt::format("{}:{}", host, port));
#ifdef __linux__// chromium ubuntu arm
        return {
            {"Host", hostHeader},
            {"User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36"},
            {"Accept-Language", "en-US,en;q=0.9"},
            {"Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7"},
            {"Referer", "https://www.google.com/"},
            {"Accept-Encoding", "gzip, deflate, br, zstd"},
            {"Sec-Ch-Ua", R"("Not:A-Brand";v="24", "Chromium";v="134")"},
            {"Sec-Ch-Ua-Mobile", "?0"},
            {"Sec-Ch-Ua-Platform", R"("Linux")"},
            {"Upgrade-Insecure-Requests", "1"},
            {"Sec-Fetch-Site", "cross-site"},
            {"Sec-Fetch-Mode", "navigate"},
            {"Sec-Fetch-User", "?1"},
            {"Sec-Fetch-Dest", "document"},
            {"Priority", "u=0, i"}
        };
#elif __APPLE__
        // apple silicon chrome
        return {
            {"Host", hostHeader},
            {"sec-ch-ua", R"("Chromium";v="128", "Not;A=Brand";v="24", "Google Chrome";v="128")"},
            {"sec-ch-ua-platform", "\"macOS\""},
            {"sec-ch-ua-mobile", "?0"},
            {"upgrade-insecure-requests", "1"},
            {"User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36"},
            {"Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7"},
            {"sec-fetch-site", "none"},
            {"sec-fetch-mode", "no-cors"},
            {"sec-fetch-dest", "empty"},
            {"Referer", "https://www.google.com/"},
            {"Accept-Encoding", "gzip, deflate, br"},
            {"Accept-Language", "ru-RU,ru;q=0.9,en-US;q=0.8,en;q=0.7"},
            {"priority", "u=4, i"}
        };
#elif _WIN32
        // chrome windows amd64
        return {
            {"Host", hostHeader},
            {"sec-ch-ua", R"("Chromium";v="128", "Not;A=Brand";v="24", "Google Chrome";v="128")"},
            {"sec-ch-ua-mobile", "?0"},
            {"sec-ch-ua-platform", "\"Windows\""},
            {"upgrade-insecure-requests", "1"},
            {"User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36"},
            {"Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7"},
            {"sec-fetch-site", "cross-site"},
            {"sec-fetch-mode", "navigate"},
            {"sec-fetch-user", "?1"},
            {"sec-fetch-dest", "document"},
            {"Referer", "https://www.google.com/"},
            {"Accept-Encoding", "gzip, deflate, br, zstd"},
            {"Accept-Language", "en-US,en;q=0.9,ru;q=0.8"},
            {"priority", "u=0, i"}
        };
#else
    #error "Unsupported system!"
#endif
    }

    struct Response final
    {
        const std::string body;
        const int code;
        const std::string errmsg;

        Response(std::string b, int c, std::string e)
            : body(std::move(b)), code(c), errmsg(std::move(e))
        {}

        nlohmann::json json() const
        {
            return nlohmann::json::parse(body);
        }
    };


    class Client final
    {
    public:
        // doesn't use sni
        explicit Client(const std::string& host, int port)
            : host_(host), port_(port), sni_(host)
        {
        }

        explicit Client(std::string host, int port, std::string sni)
            : host_(std::move(host)), port_(port), sni_(std::move(sni))
        {
        }

        Response get(const std::string& handle, int timeout = 5) noexcept
        {
            std::string body;
            std::string error;
            int respcode = 400;
            try
            {
                boost::asio::io_context ioc;
                boost::asio::ssl::context ctx(boost::asio::ssl::context::sslv23_client);
                ctx.set_verify_mode(boost::asio::ssl::verify_none); // disable validate
                ctx.set_options(boost::asio::ssl::context::no_sslv2 |
                                boost::asio::ssl::context::no_sslv3 |
                                boost::asio::ssl::context::no_tlsv1 |
                                boost::asio::ssl::context::no_tlsv1_1);
                // set chrome ciphers
                const std::string ciphers = chromeCiphers();
                SSL_CTX_set_cipher_list(ctx.native_handle(), ciphers.c_str());

                boost::beast::net::ip::tcp::resolver resolver(ioc);
                boost::beast::ssl_stream<boost::beast::tcp_stream> stream(ioc, ctx);

                const std::string port = std::to_string(port_);
                auto const results = resolver.resolve(host_, port);
                boost::beast::get_lowest_layer(stream).connect(results);
                // Set timeout for the operation
                boost::beast::get_lowest_layer(stream).expires_after(std::chrono::seconds(timeout));

                // set SNI
                if (!SSL_set_tlsext_host_name(stream.native_handle(), sni_.c_str())) {
                    throw boost::beast::system_error(
                        boost::beast::error_code(
                            static_cast<int>(::ERR_get_error()), boost::asio::error::get_ssl_category()
                        ),
                        fmt::format(R"(Failed to set SNI "{}" for host "{}" (GET "{}"))", sni_, host_, handle)
                    );
                }
                stream.handshake(boost::asio::ssl::stream_base::client);

                // request params
                boost::beast::http::request<boost::beast::http::string_body> req{
                    boost::beast::http::verb::get, handle, 11
                };
                // set http headers
                for (const auto& [key, value] : realBrowserHeaders(sni_, port_)) {
                    req.set(key, value);
                }
                // send request
                boost::beast::http::write(stream, req);
                // read answer
                boost::beast::flat_buffer buffer;
                boost::beast::http::response<boost::beast::http::dynamic_body> res;
                boost::beast::http::read(stream, buffer, res);

                respcode = static_cast<int>(res.result_int());
                body = getHttpBody(res);

                boost::beast::error_code ec;
                stream.shutdown(ec);
                if (ec == boost::beast::net::error::eof) {
                    ec = {};
                }
                if (ec) {
                    throw boost::beast::system_error{ec};
                }
            }
            catch (std::exception const& e)
            {
                error = e.what();
            }
            return { body, respcode, error };
        }

        Response post(const std::string& handle,
                      const std::string& request,
                      const std::string& contentType,
                      int timeout = 5) noexcept
        {
            std::string body;
            std::string error;
            int respcode = 400;
            try
            {
                boost::asio::io_context ioc;
                boost::asio::ssl::context ctx(boost::asio::ssl::context::sslv23_client);
                ctx.set_verify_mode(boost::asio::ssl::verify_none);
                ctx.set_options(boost::asio::ssl::context::no_sslv2 |
                                boost::asio::ssl::context::no_sslv3 |
                                boost::asio::ssl::context::no_tlsv1 |
                                boost::asio::ssl::context::no_tlsv1_1);
                SSL_CTX_set_cipher_list(ctx.native_handle(), chromeCiphers().c_str());

                boost::beast::net::ip::tcp::resolver resolver(ioc);
                boost::beast::ssl_stream<boost::beast::tcp_stream> stream(ioc, ctx);

                const std::string port = std::to_string(port_);
                auto const results = resolver.resolve(host_, port);
                boost::beast::get_lowest_layer(stream).connect(results);
                // Set timeout for the operation
                boost::beast::get_lowest_layer(stream).expires_after(std::chrono::seconds(timeout));

                if (!SSL_set_tlsext_host_name(stream.native_handle(), sni_.c_str())) {
                    throw boost::beast::system_error(
                        boost::beast::error_code(
                            static_cast<int>(::ERR_get_error()), boost::asio::error::get_ssl_category()
                        ),
                        fmt::format(R"(Failed to set SNI "{}" for host "{}" (POST "{}"))", sni_, host_, handle)
                    );
                }
                stream.handshake(boost::asio::ssl::stream_base::client);

                boost::beast::http::request<boost::beast::http::string_body> req{
                        boost::beast::http::verb::post, handle, 11
                };
                req.set(boost::beast::http::field::host, host_);
                req.set(boost::beast::http::field::content_type, contentType);
                req.set(boost::beast::http::field::content_length, std::to_string(request.size()));
                for (const auto& [key, value] : realBrowserHeaders(sni_, port_)) {
                    req.set(key, value);
                }
                req.body() = request;
                req.prepare_payload();

                boost::beast::http::write(stream, req);

                boost::beast::flat_buffer buffer;
                boost::beast::http::response<boost::beast::http::dynamic_body> res;
                boost::beast::http::read(stream, buffer, res);

                respcode = static_cast<int>(res.result_int());
                body = getHttpBody(res);

                boost::beast::error_code ec;
                stream.shutdown(ec);
                if (ec == boost::beast::net::error::eof) {
                    ec = {};
                }
                if (ec) {
                    throw boost::beast::system_error{ec};
                }
            }
            catch (std::exception const& e)
            {
                error = e.what();
            }
            return { body, respcode, error };
        }
    protected:
        std::string decompressGzip(const std::string& compressed)
        {
            constexpr size_t CHUNK_SIZE = 4096;

            std::vector<char> buffer(CHUNK_SIZE);

            z_stream strm{};
            strm.next_in = reinterpret_cast<Bytef*>(const_cast<char*>(compressed.data()));
            strm.avail_in = compressed.size();

            if (inflateInit2(&strm, 16 + MAX_WBITS) != Z_OK) {
                return {};
            }

            std::string decompressed;
            int ret = 0;
            do {
                strm.next_out = reinterpret_cast<Bytef*>(buffer.data());
                strm.avail_out = buffer.size();
                ret = inflate(&strm, Z_NO_FLUSH);

                if (ret == Z_STREAM_ERROR || ret == Z_DATA_ERROR || ret == Z_MEM_ERROR) {
                    inflateEnd(&strm);
                    return {}; // decompression error
                }
                decompressed.append(buffer.data(), buffer.size() - strm.avail_out);
            } while (ret != Z_STREAM_END);

            inflateEnd(&strm);
            return decompressed;
        }

        std::string getHttpBody(const boost::beast::http::response<boost::beast::http::dynamic_body>& res)
        {
            const auto body = boost::beast::buffers_to_string(res.body().data());
            if (res[boost::beast::http::field::content_encoding] == "gzip") {
                return decompressGzip(body);
            }
            return body;
        }
    private:
        const std::string host_;
        const int port_;
        const std::string sni_;
    };

    using ClientPtr = std::unique_ptr<Client>;
}