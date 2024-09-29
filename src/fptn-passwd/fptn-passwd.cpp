#include <unistd.h>
#include <termios.h>

#include <iostream>

#include <argparse/argparse.hpp>
#include <common/user/common_user_manager.h>


inline std::string getPassword(const std::string& prompt) 
{
    std::string password;
    struct termios oldt, newt;

    std::cout << prompt;
    tcgetattr(STDIN_FILENO, &oldt);
    newt = oldt;
    newt.c_lflag &= ~(ECHO); // Turn off echo
    tcsetattr(STDIN_FILENO, TCSANOW, &newt);
    std::getline(std::cin, password);
    tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
    std::cout << std::endl;
    
    return password;
}


int main(int argc, char* argv[]) 
{
    if (geteuid() != 0) {
        std::cerr << "You must be root to run this program." << std::endl;
        return EXIT_FAILURE;
    }

    argparse::ArgumentParser parser("fptn-passwd");
    parser.add_argument("--add-user")
        .help("Username to add");
    parser.add_argument("--del-user")
        .help("Username to delete");
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
    try {
        parser.parse_args(argc, argv);
    } catch (const std::runtime_error& err) {
        std::cerr << err.what() << std::endl;
        return 1;
    }

    const auto addUser = parser.present<std::string>("--add-user").value_or("");
    const auto delUser = parser.present<std::string>("--del-user").value_or("");
    const auto bandwidth = parser.get<int>("--bandwidth");
    const auto filePath = parser.get<std::string>("--userfile");
    const bool list = parser.get<bool>("--list");
    const auto getBandwidthUser = parser.present<std::string>("--get-bandwidth").value_or("");

    fptn::common::user::CommonUserManager userManager(filePath);

    if (!addUser.empty()) {
        std::string password = getPassword("Type password: ");
        std::string retypePassword = getPassword("Retype password: ");
        if (password != retypePassword) {
            std::cout << "Passwords do not match." << std::endl;
            return 1;
        }
        userManager.addUser(addUser, password, bandwidth);
    } else if (!delUser.empty()) {
        std::string confirm;
        std::cout << "Are you sure you want to delete user " << delUser << "? (Y/N): ";
        std::cin >> confirm;
        if (confirm == "Y" || confirm == "y") {
            userManager.deleteUser(delUser);
        } else {
            std::cout << "Deletion cancelled." << std::endl;
        }
    } else if (list) {
        userManager.listUsers();
    } else if (!getBandwidthUser.empty()) {
        int bandwidth = userManager.getUserBandwidth(getBandwidthUser);
        if (bandwidth != -1) {
            std::cout << "Bandwidth for user " << getBandwidthUser << ": " << bandwidth << " MB" << std::endl;
        }
    } else {
        std::cerr << "No command specified. Use --help for usage information." << std::endl;
        return 1;
    }

    return 0;
}
