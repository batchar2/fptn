find_package(GTest REQUIRED)
find_package(Boost REQUIRED)
find_package(OpenSSL REQUIRED)
find_package(glog REQUIRED)
find_package(fmt REQUIRED)
find_package(PcapPlusPlus REQUIRED)
find_package(nlohmann_json REQUIRED)
find_package(jwt-cpp REQUIRED)
find_package(prometheus-cpp REQUIRED)

if (WIN32)
    set(TUNTAP_LIB Wintun rpcrt4)
else()
    set(TUNTAP_LIB tuntap++)
endif()

set(LIBS
    GTest::gtest GTest::gtest_main
    Boost::boost OpenSSL::SSL OpenSSL::Crypto nlohmann_json::nlohmann_json jwt-cpp::jwt-cpp
    glog::glog fmt::fmt PcapPlusPlus::PcapPlusPlus hv_static fptn_protocol
    prometheus-cpp::prometheus-cpp
    ${TUNTAP_LIB}
)

include_directories(${FPTN_SERVER_PATH})

# --- MetricTest test ---
add_executable(MetricTest statistic/MetricTest.cpp ${FPTN_SERVER_PATH}/statistic/metrics.h ${FPTN_SERVER_PATH}/statistic/metrics.cpp)
target_link_libraries(MetricTest ${LIBS})
add_test(NAME MetricTest COMMAND MetricTest)
