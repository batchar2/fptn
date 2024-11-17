find_package(GTest REQUIRED)
find_package(Boost REQUIRED)
find_package(OpenSSL REQUIRED)
find_package(spdlog REQUIRED)
find_package(fmt REQUIRED)
find_package(PcapPlusPlus REQUIRED)
find_package(nlohmann_json REQUIRED)
find_package(jwt-cpp REQUIRED)

if (WIN32)
    set(TUNTAP_LIB Wintun rpcrt4)
else()
    set(TUNTAP_LIB tuntap++)
endif()

set(LIBS
    GTest::gtest GTest::gtest_main
    Boost::boost OpenSSL::SSL OpenSSL::Crypto nlohmann_json::nlohmann_json jwt-cpp::jwt-cpp
    spdlog::spdlog fmt::fmt PcapPlusPlus::PcapPlusPlus hv_static fptn_protocol
    ${TUNTAP_LIB}
)

# --- Channel test ---
add_executable(ChannelTest data/ChannelTest.cpp)
target_link_libraries(ChannelTest ${LIBS})
add_test(NAME ChannelTest COMMAND ChannelTest)

# --- IP Generator test ---
add_executable(IPGeneratorTest network/IPGeneratorTest.cpp)
target_link_libraries(IPGeneratorTest ${LIBS})
add_test(NAME IPGeneratorTest COMMAND IPGeneratorTest)
