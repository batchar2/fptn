/*=============================================================================
Copyright (c) 2024-2025 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#include <iostream>
#include <string>
#include <termios.h>  // NOLINT(build/include_order)
#include <unistd.h>   // NOLINT(build/include_order)

#include <argparse/argparse.hpp>

#include "common/user/common_user_manager.h"

namespace {
std::string GetPassword(const std::string& prompt) {
  std::string password;
  struct termios oldt = {};

  std::cout << prompt;
  tcgetattr(STDIN_FILENO, &oldt);
  struct termios newt = oldt;
  newt.c_lflag &= ~(ECHO);  // Turn off echo
  tcsetattr(STDIN_FILENO, TCSANOW, &newt);
  std::getline(std::cin, password);
  tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
  std::cout << std::endl;

  return password;
}
}  // namespace

int main(int argc, char* argv[]) {
  if (geteuid() != 0) {
    std::cerr << "You must be root to run this program." << std::endl;
    return EXIT_FAILURE;
  }
  try {
    argparse::ArgumentParser parser("fptn-passwd", FPTN_VERSION);
    parser.add_argument("--add-user").help("Username to add");
    parser.add_argument("--del-user").help("Username to delete");
    parser.add_argument("--bandwidth")
        .help("Bandwidth limit for the user in Megabit (default: 100)")
        .default_value(100)
        .scan<'i', int>();
    parser.add_argument("--userfile")
        .help("Path to users file (default: /etc/fptn/users.list)")
        .default_value("/etc/fptn/users.list");
    parser.add_argument("--list")
        .help("List all users")
        .default_value(false)
        .implicit_value(true);
    parser.add_argument("--get-bandwidth")
        .help("Get bandwidth limit for a user");
    parser.parse_args(argc, argv);
    const auto add_user =
        parser.present<std::string>("--add-user").value_or("");
    const auto del_user =
        parser.present<std::string>("--del-user").value_or("");
    const auto bandwidth = parser.get<int>("--bandwidth");
    const auto file_path = parser.get<std::string>("--userfile");
    const bool list = parser.get<bool>("--list");
    const auto get_bandwidth_user =
        parser.present<std::string>("--get-bandwidth").value_or("");

    fptn::common::user::CommonUserManager user_manager(file_path);

    if (!add_user.empty()) {
      const std::string password = GetPassword("Type password: ");
      const std::string retype_password = GetPassword("Retype password: ");
      if (password != retype_password) {
        std::cout << "Passwords do not match." << std::endl;
        return 1;
      }
      user_manager.AddUser(add_user, password, bandwidth);
    } else if (!del_user.empty()) {
      std::string confirm;
      std::cout << "Are you sure you want to delete user " << del_user
                << "? (Y/N): ";
      std::cin >> confirm;
      if (confirm == "Y" || confirm == "y") {
        user_manager.DeleteUser(del_user);
      } else {
        std::cout << "Deletion cancelled." << std::endl;
      }
    } else if (list) {
      user_manager.ListUsers();
    } else if (!get_bandwidth_user.empty()) {
      const int bw = user_manager.GetUserBandwidth(get_bandwidth_user);
      if (bw != -1) {
        std::cout << "Bandwidth for user " << get_bandwidth_user << ": " << bw
                  << " MB" << std::endl;
      }
    } else {
      std::cerr << "No command specified. Use --help for usage information."
                << std::endl;
      return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;
  } catch (const std::runtime_error& err) {
    std::cerr << "Argument parsing error: " << err.what() << std::endl;
  } catch (const std::exception& ex) {
    std::cerr << "An error occurred: " << ex.what() << " Exiting..."
              << std::endl;
  } catch (...) {
    std::cerr << "An unknown error occurred. Exiting..." << std::endl;
  }
  return EXIT_FAILURE;
}
