#define BOOST_TEST_MAIN
#define BOOST_TEST_MODULE AddressConversion
#include <boost/test/unit_test.hpp>

#include "rcdcap/packet-headers.hh"

BOOST_AUTO_TEST_CASE( IPv4Conversion )
{
    RCDCap::ip_t orig_ip{ 172, 22, 10, 1 },
                 result_ip;
    std::stringstream ss;
    ss << orig_ip;
    
    BOOST_CHECK(ss.str() == "172.22.10.1");
    
    ss >> result_ip;
    
    BOOST_CHECK(ss.good());
    
    BOOST_CHECK(orig_ip == result_ip);
}

BOOST_AUTO_TEST_CASE( MacConversion )
{
    RCDCap::mac_t orig_mac{ 0x30, 0x85, 0xA9, 0x3A, 0x87, 0xE3 },
                  result_mac;
    std::stringstream ss;
    ss << orig_mac;
    
    auto mac = ss.str();
    BOOST_CHECK(mac == "30:85:A9:3A:87:E3");
    
    ss >> result_mac;
    BOOST_CHECK(ss.good());
    
    BOOST_CHECK(orig_mac == result_mac);
}

BOOST_AUTO_TEST_CASE( IPv6Conversion )
{
    RCDCap::ip6_t orig_ip{ 0x2001, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0001 },
                  result_ip;
    std::stringstream ss;
    ss << orig_ip;
    
    auto ip6 = ss.str();
    BOOST_CHECK(ip6 == "2001::1");
    
    ss >> result_ip;
    BOOST_CHECK(ss.good());
    
    BOOST_CHECK(orig_ip == result_ip);
}