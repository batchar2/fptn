find_package(GTest REQUIRED)
find_package(Boost REQUIRED)
find_package(OpenSSL REQUIRED)
find_package(spdlog REQUIRED)
find_package(fmt REQUIRED)
find_package(PcapPlusPlus REQUIRED)
find_package(nlohmann_json REQUIRED)
find_package(jwt-cpp REQUIRED)

if(WIN32)
  set(TUNTAP_LIB Wintun rpcrt4)
else()
  set(TUNTAP_LIB tuntap++)
endif()

set(LIBS
    GTest::gtest
    GTest::gtest_main
    Boost::boost
    OpenSSL::SSL
    OpenSSL::Crypto
    nlohmann_json::nlohmann_json
    jwt-cpp::jwt-cpp
    spdlog::spdlog
    fmt::fmt
    PcapPlusPlus::PcapPlusPlus
    fptn-protocol-lib_static
    ${TUNTAP_LIB})

# --- Channel test ---
add_executable(ChannelTest data/ChannelTest.cpp)
target_link_libraries(ChannelTest PRIVATE ${LIBS})
add_test(NAME ChannelTest COMMAND ChannelTest)

# --- IPv4 Generator test ---
add_executable(IPv4GeneratorTest network/IPv4GeneratorTest.cpp)
target_link_libraries(IPv4GeneratorTest PRIVATE ${LIBS})
add_test(NAME IPv4GeneratorTest COMMAND IPv4GeneratorTest)

# --- IPv6 Generator test ---
add_executable(IPv6GeneratorTest network/IPv6GeneratorTest.cpp)
target_link_libraries(IPv6GeneratorTest PRIVATE ${LIBS})
add_test(NAME IPv6GeneratorTest COMMAND IPv6GeneratorTest)
