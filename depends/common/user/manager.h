#pragma once 

#include <mutex>
#include <string>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <iostream>
#include <filesystem>
#include <unordered_map>

#include <openssl/evp.h>


namespace fptn::common::user
{
    class UserManager 
    {
    public:
        UserManager(const std::string& filePath) : filePath_(filePath) 
        {
            createFileIfNotExists(filePath_);
            loadUsers();
        }

        bool addUser(const std::string& username, const std::string& password, int bandwidth) 
        {
            std::lock_guard<std::mutex> lock(mutex_);
            
            if (!validateUsername(username)) {
                std::cerr << "Invalid username." << std::endl;
                return false;
            }

            if (bandwidth < 0) {
                std::cerr << "Invalid bandwidth value. It should be a positive number." << std::endl;
                return false;
            }

            if (users_.find(username) != users_.end()) {
                std::cout << "User " << username << " already exists." << std::endl;
                return false;
            }
            std::string hash = hashPassword(password);
            users_[username] = {hash, bandwidth};
            saveUsers();
            std::cout << "User " << username << " added with bandwidth " << bandwidth << " MB." << std::endl;
            return true;
        }

        bool deleteUser(const std::string& username) 
        {
            std::lock_guard<std::mutex> lock(mutex_);
            
            if (users_.find(username) == users_.end()) {
                return false;
            }
            users_.erase(username);
            saveUsers();
            return true;
        }

        void listUsers() const 
        {
            std::lock_guard<std::mutex> lock(mutex_);
            
            for (const auto& [username, credentials] : users_) {
                std::cout << username << " " << std::string(credentials.first.length(), 'X') << " " << credentials.second << " MB" << std::endl;
            }
        }

        bool authenticate(const std::string& username, const std::string& password)
        {
            // TODO FIXIT
            std::lock_guard<std::mutex> lock(mutex_);

            loadUsers();

            auto it = users_.find(username);
            if (it != users_.end()) {
                std::string hash = hashPassword(password);
                return it->second.first == hash;
            }
            return false;
        }

        int getUserBandwidthBit(const std::string& username) const 
        {
            // TODO FIXIT
            std::lock_guard<std::mutex> lock(mutex_);
            auto it = users_.find(username);
            if (it != users_.end()) {
                return it->second.second * 1024 * 1024;
            }
            return 0;
        }
        int getUserBandwidth(const std::string& username) const 
        {
            // TODO FIXIT
            std::lock_guard<std::mutex> lock(mutex_);
            auto it = users_.find(username);
            if (it != users_.end()) {
                return it->second.second;
            }
            return 0;
        }
    private:
        void loadUsers() 
        {
            // FIXIT
            // update
            users_.clear();

            std::ifstream file(filePath_);
            if (file.is_open()) {
                std::string line;
                while (std::getline(file, line)) {
                    std::string username;
                    std::string passwordHash;
                    int bandwidth;

                    std::istringstream iss(line);
                    if (iss >> username >> passwordHash >> bandwidth) {
                        users_[username] = {passwordHash, bandwidth};
                    } else {
                        std::cerr << "Skipping invalid line: " << line << std::endl;
                    }
                }
            } else {
                std::cerr << "Unable to open file: " << filePath_ << std::endl;
            }
        }

        void saveUsers() const 
        {
            std::ofstream file(filePath_);
            if (file.is_open()) {
                for (const auto& [username, credentials] : users_) {
                    file << username << " " << credentials.first << " " << credentials.second << "\n";
                }
            } else {
                std::cerr << "Unable to open file: " << filePath_ << std::endl;
            }
        }

        std::string hashPassword(const std::string& password) const 
        {
            unsigned int length = 0;
            unsigned char hash[EVP_MAX_MD_SIZE] = {0};
            
            EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
            if (!mdctx) {
                std::cerr << "Failed to create EVP_MD_CTX" << std::endl;
                return "";
            }

            if (1 != EVP_DigestInit_ex(mdctx, EVP_sha256(), nullptr)) {
                std::cerr << "Failed to initialize digest" << std::endl;
                EVP_MD_CTX_free(mdctx);
                return "";
            }

            if (1 != EVP_DigestUpdate(mdctx, password.c_str(), password.size())) {
                std::cerr << "Failed to update digest" << std::endl;
                EVP_MD_CTX_free(mdctx);
                return "";
            }

            if (1 != EVP_DigestFinal_ex(mdctx, hash, &length)) {
                std::cerr << "Failed to finalize digest" << std::endl;
                EVP_MD_CTX_free(mdctx);
                return "";
            }

            EVP_MD_CTX_free(mdctx);

            std::ostringstream oss;
            for (unsigned int i = 0; i < length; ++i) {
                oss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
            }
            return oss.str();
        }

        bool validateUsername(const std::string& username) const 
        {
            return !username.empty() && std::all_of(username.begin(), username.end(), ::isalnum);
        }

        void createFileIfNotExists(const std::string& filePath) 
        {
            std::filesystem::path path(filePath);
            std::filesystem::path directoryPath = path.parent_path();
            if (!directoryPath.empty() && !std::filesystem::exists(directoryPath)) {
                std::error_code ec;
                if (!std::filesystem::create_directories(directoryPath, ec)) {
                    std::cerr << "Failed to create directories: " << ec.message() << std::endl;
                    return;
                }
            }
            if (!std::filesystem::exists(filePath)) {
                std::ofstream file(filePath);
                if (!file.is_open()) {
                    std::cerr << "Failed to create file: " << filePath << std::endl;
                }
            }
        }

    private:
        std::unordered_map<std::string, std::pair<std::string, int>> users_;
        mutable std::mutex mutex_;
        std::string filePath_;
    };

    using UserManagerSPtr = std::shared_ptr<UserManager>;
}
