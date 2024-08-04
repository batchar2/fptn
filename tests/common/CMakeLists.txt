find_package(GTest REQUIRED)
find_package(Boost REQUIRED)
find_package(OpenSSL REQUIRED)
find_package(glog REQUIRED)
find_package(fmt REQUIRED)
find_package(PcapPlusPlus REQUIRED)
find_package(nlohmann_json REQUIRED)
find_package(jwt-cpp REQUIRED)

set(LIBS
    GTest::gtest GTest::gtest_main
    Boost::boost OpenSSL::SSL OpenSSL::Crypto nlohmann_json::nlohmann_json jwt-cpp::jwt-cpp
    glog::glog fmt::fmt PcapPlusPlus::PcapPlusPlus tuntap++ hv_static fptn_protocol
)

# --- Channel test ---
add_executable(ChannelTest ChannelTest.cpp)
target_link_libraries(ChannelTest ${LIBS})
add_test(NAME ChannelTest COMMAND ChannelTest)
