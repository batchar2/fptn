#pragma once

#include <ctime>
#include <random>
#include <string>
#include <stdexcept>

#include <boost/algorithm/string.hpp>

#include <protocol.pb.h>

#include <common/network/ip_packet.h>


namespace fptn::common::utils
{
    inline std::string generateRandomString(int length)
    {
        const std::string characters = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

        std::mt19937 gen{std::random_device{}()};
        std::uniform_int_distribution<std::size_t> dist(0, characters.size() - 1);

        std::string result;
        for (int i = 0; i < length; i++) {
            result += characters[dist(gen)];
        }
        return result;
    }

    inline std::string removeSubstring(std::string input, const std::vector<std::string>& toRemove)
    {
        for (const auto& substr : toRemove) {
            boost::algorithm::erase_all(input, substr);
        }
        return input;
    }
}
