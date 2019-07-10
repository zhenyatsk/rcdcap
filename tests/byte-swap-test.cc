#define BOOST_TEST_MAIN
#define BOOST_TEST_MODULE ByteSwapTest
#include <boost/test/unit_test.hpp>

#include "rcdcap/packet-headers.hh"

BOOST_AUTO_TEST_CASE(ByteSwapTest)
{
    RCDCap::ip_t orig_ip{ 172, 22, 10, 1 };
    
    RCDCap::uint32 ip = reinterpret_cast<RCDCap::uint32&>(orig_ip);

    auto intermediate = RCDCap::ByteSwap(ip);
    
    BOOST_CHECK(ip != intermediate);
    
    BOOST_CHECK(ip == RCDCap::ByteSwap(intermediate));
    
    RCDCap::ip6_t orig_ip6{0xFF00, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0};
    int128 ip6 = reinterpret_cast<int128&>(orig_ip6);
   
    auto intermediate6 = RCDCap::ByteSwap(ip6);
    BOOST_CHECK(intermediate6 != ip6);
    
    BOOST_CHECK(ip6 == RCDCap::ByteSwap(intermediate6));
}
