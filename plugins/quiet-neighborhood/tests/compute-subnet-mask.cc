#define BOOST_TEST_MAIN
#define BOOST_TEST_MODULE ComputeSubnetTest
#include <boost/test/unit_test.hpp>

#include "network-cache.hh"

BOOST_AUTO_TEST_CASE( ComputeSubnetTestIPv4 )
{
    ip_t addr1{ 172, 22, 10, 255 };
    ip_t addr2{ 172, 22, 10,   3 };
    
    auto mask = RCDCap::ByteSwap(ComputeSubnetMask(addr1, addr2, ~0u));
    ip_t result_mask = reinterpret_cast<ip_t&>(mask);
    
    ip_t expected_mask{255, 255, 254, 0};
    
    BOOST_CHECK(result_mask == expected_mask);
}

BOOST_AUTO_TEST_CASE( ComputeSubnetTestIPv6 )
{
    ip6_t addr1{ 0xFF00, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0xFFFF };
    ip6_t addr2{ 0xFF00, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x3 };
    
    ipv6_int128_t val = 0;
    auto mask = RCDCap::ByteSwap(ComputeSubnetMask(addr1, addr2, ~val));
    ip6_t result_mask = reinterpret_cast<ip6_t&>(mask);
    
    ip6_t expected_mask{ 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFE, 0x0};
    
    BOOST_CHECK(result_mask == expected_mask);
}

