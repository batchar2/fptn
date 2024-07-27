#pragma once


#include <mutex>
#include <chrono>
#include <memory>
#include <utility>
#include <fstream>
#include <iostream>

#include <glog/logging.h>
#include <nlohmann/json.hpp>

#include <jwt-cpp/jwt.h>
#include <jwt-cpp/base.h>
#include <jwt-cpp/traits/nlohmann-json/defaults.h>


namespace fptn::common::jwt_token
{
    class TokenManager
    {
    public:
        TokenManager(
            const std::string& serverCrt,
            const std::string& serverKey,
            const std::string& serverPub
        ) :
            serverCrt_(serverCrt),
            serverKey_(serverKey),
            serverPub_(serverPub)
        {
        }

        std::pair<std::string, std::string> generate(const std::string& username, int bandwidthBit)
        {
            // TODO FIX  
            auto now = std::chrono::system_clock::now();
            auto accessToken = jwt::create<jwt::traits::nlohmann_json>()
                .set_issuer("auth0")
                .set_type("JWT")
                .set_id("fptn")
                .set_issued_at(now)
                .set_expires_at(now + std::chrono::seconds{36000})
                .set_payload_claim("username", username)
                .set_payload_claim("bandwidth_bit", bandwidthBit)
                .sign(jwt::algorithm::rs256("", readFromFile(serverKey_), "", ""));
            return std::make_pair(accessToken, "");
        }
        bool validate(const std::string& token, std::string& username, int& bandwidthBit)
        {
            // TODO CHECK IT
            try {
                auto decoded = jwt::decode<jwt::traits::nlohmann_json>(token);
                username = decoded.get_payload_claim("username").as_string();
                bandwidthBit = decoded.get_payload_claim("bandwidth_bit").as_integer();

                auto verifier = jwt::verify<jwt::default_clock, jwt::traits::nlohmann_json>(jwt::default_clock())
                    .allow_algorithm(jwt::algorithm::rs256("", readFromFile(serverKey_), "", ""))
                    .with_issuer("auth0");
                return true;
            } 
            catch (const jwt::error::invalid_json_exception& e)
            {
                LOG(ERROR) << "Token parsing error: " << e.what();
            } 
            catch (const jwt::error::token_verification_exception& e)
            {
                LOG(ERROR) << "Unauthorized: Invalid token. " << e.what();
            } catch (const std::exception& e)
            {
                LOG(ERROR) << "Handle other standard exceptions. " << e.what();
            }
            return false;
        }
        const std::string serverCrt() const 
        {
            return serverCrt_;
        }
        const std::string serverKey() const 
        {
            return serverKey_;
        }
        const std::string serverPub() const 
        {
            return serverPub_;
        }
    private:
        std::string readFromFile(const std::string& path)
        {
            std::string contents;
            std::ifstream is{path, std::ifstream::binary};
            if (is) {
                // get length of file:
                is.seekg (0, is.end);
                auto length = is.tellg();
                is.seekg (0, is.beg);
                contents.resize(length);

                is.read(&contents[0], length);
                if (!is) {
                    is.close();
                    return {};
                }
            }
            is.close();
            return contents;
        }
    private:
        const std::string serverCrt_;
        const std::string serverKey_;
        const std::string serverPub_;
    };

    using TokenManagerSPtr = std::shared_ptr<TokenManager>;
}
