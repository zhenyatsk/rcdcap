#define BOOST_TEST_MAIN
#define BOOST_TEST_MODULE NetworkCacheTest
#include <boost/test/unit_test.hpp>
#include <boost/concept_check.hpp>

#include "network-cache.hh"

#include <thread>
#include <future>
#include <chrono>
#include <limits>
#include <fstream>
#include <sstream>

BOOST_AUTO_TEST_CASE(NetworkCacheSynchronousTest)
{
    QuietNeighborhoodOptions opts;
    opts.VLANPoolSize = 2;
    opts.hostPoolSize = 5;
    opts.IPv4MinMask = opts.IPv4MaxMask = 24;
    opts.IPv6MinMask = opts.IPv6MaxMask = 64;
    opts.subnetPoolSize = 1;
    NetworkCache cache(opts);

    // We use a dummy IP because the cache doesn't care about empty
    // tables.
    ip_t dummy_ip{ 192, 168, 0, 1 };
    
    auto *vlan = cache.acquireVLAN(MonitorState::LEARNING_PHASE, 1);
    cache.acquireIP(MonitorState::LEARNING_PHASE, vlan, dummy_ip);
    BOOST_REQUIRE(vlan != nullptr);
    vlan = cache.acquireVLAN(MonitorState::MONITORING_PHASE, 2);
    BOOST_REQUIRE(vlan != nullptr);
    cache.acquireIP(MonitorState::MONITORING_PHASE, vlan, dummy_ip);
 
    // Here we have to start failing because we have depleted the pool.
    vlan = cache.acquireVLAN(MonitorState::MONITORING_PHASE, 3);
    BOOST_CHECK(vlan == nullptr);
    vlan = cache.acquireVLAN(MonitorState::LEARNING_PHASE, 4);
    BOOST_CHECK(vlan == nullptr);
    
    // On the other hand, we still want the old stuff.
    vlan = cache.acquireVLAN(MonitorState::MONITORING_PHASE, 1);
    BOOST_CHECK(vlan != nullptr);
    vlan = cache.acquireVLAN(MonitorState::LEARNING_PHASE, 2);
    BOOST_CHECK(vlan != nullptr);
    
    std::stringstream ss_legitimate, ss_suspicious;
    cache.saveCache(CacheFormat::JSON, ss_legitimate, ss_suspicious);
    
    std::string legit = ss_legitimate.str();
    std::string susp = ss_suspicious.str();
    
    BOOST_CHECK(legit.find(R"("vid": "1")") != std::string::npos);
    BOOST_CHECK(legit.find(R"("vid": "2")") == std::string::npos);
    BOOST_CHECK(legit.find(R"("vid": "3")") == std::string::npos);
    BOOST_CHECK(legit.find(R"("vid": "4")") == std::string::npos);
    
    BOOST_CHECK(susp.find(R"("vid": "1")") == std::string::npos);
    BOOST_CHECK(susp.find(R"("vid": "2")") != std::string::npos);
    BOOST_CHECK(susp.find(R"("vid": "3")") == std::string::npos);
    BOOST_CHECK(susp.find(R"("vid": "4")") == std::string::npos);
    
    ss_legitimate.seekp(0);
    ss_suspicious.seekp(0);
    
    NetworkCache cache2(opts);
    std::stringstream ss_legitimate2, ss_suspicious2;
    
    cache2.reloadCache(CacheFormat::JSON, ss_legitimate, ss_suspicious, false);
        
    cache.saveCache(CacheFormat::JSON, ss_legitimate2, ss_suspicious2);
    BOOST_CHECK(ss_legitimate.str() == ss_legitimate2.str());
    BOOST_CHECK(ss_suspicious.str() == ss_suspicious2.str());
}

RCDCap::uint32 ConvertToInteger(const ip_t& ip, size_t net_size)
{
    RCDCap::uint32 mask = ~0;
    mask <<= net_size;
    return RCDCap::ByteSwap(reinterpret_cast<const RCDCap::uint32&>(ip)) & mask;
}

ipv6_int128_t ConvertToInteger(const ip6_t& ip, size_t net_size)
{
    ipv6_int128_t mask = 0;
    mask = ~mask;
    mask <<= net_size;
    return RCDCap::ByteSwap(reinterpret_cast<const ipv6_int128_t&>(ip)) & mask;
}

template<class T>
void CacheTest(NetworkCache& cache, size_t vlan_size, const T& net_addr, size_t net_size, size_t host_pool, size_t polling_steps, std::promise<size_t> result)
{
    std::default_random_engine gen;
    
    auto int_net = ConvertToInteger(net_addr, net_size);
    
    assert(net_size/8 < sizeof(size_t));
    assert(host_pool < (1u<<net_size)-1u);
    
    std::uniform_int_distribution<vlan32> vlan_dist(1, vlan_size);
    std::uniform_int_distribution<size_t> host_dist(1, host_pool);

    auto start = std::chrono::high_resolution_clock::now();
    
    for(size_t i = 0; i < polling_steps; ++i)
    {
        auto vid = vlan_dist(gen);
        auto* vlan = cache.acquireVLAN(MonitorState::LEARNING_PHASE, vid);
        if(vlan == nullptr) 
            continue;
        auto host = host_dist(gen);
        auto host_ip = RCDCap::ByteSwap(int_net | static_cast<decltype(int_net)>(host));
        cache.acquireIP(MonitorState::LEARNING_PHASE, vlan, reinterpret_cast<const T&>(host_ip));
    }
    
    auto end = std::chrono::high_resolution_clock::now();
    auto diff = end - start;
    result.set_value(std::chrono::duration_cast<std::chrono::milliseconds>(diff).count());
}

BOOST_AUTO_TEST_CASE(NetworkCacheParallelTest)
{
    // Settings
    constexpr size_t max_pool_size = 250;
    constexpr size_t pool_enlarge_step = 10;
    constexpr size_t threads_of_exec = 2;
    constexpr size_t vlan_polling_size = 1;
    constexpr size_t subnet_size = 24;
    constexpr size_t polling_size = 1000000;
    constexpr ip_t netmask = { 192, 168, 123, 0 };
    
    constexpr size_t test_repeats = 10;
    
    QuietNeighborhoodOptions opts;
    opts.VLANPoolSize = 8;
    opts.hostPoolSize = 255;
    opts.IPv4MinMask = opts.IPv4MaxMask = 24;
    opts.IPv6MinMask = opts.IPv6MaxMask = 64;
    opts.subnetPoolSize = 1;
    
    // Testing
    std::fstream experiment_log("experiment_log.txt", std::ios::out);
    BOOST_REQUIRE(experiment_log.is_open());
    experiment_log << "# Experminetal data for cache insertion\n";
    for(size_t pool_size = pool_enlarge_step; pool_size <= max_pool_size; pool_size += pool_enlarge_step)
    {
        NetworkCache cache(opts);

        std::vector<std::thread> threads(threads_of_exec-1);
        std::vector<std::future<size_t>> results(threads_of_exec);

        size_t min = std::numeric_limits<size_t>::max(),
            max = std::numeric_limits<size_t>::min();
        RCDCap::int64 total = 0;
        for(size_t repeat = 0; repeat < test_repeats; ++repeat)
        {
            auto iresults = results.begin();
            static_assert(threads_of_exec > 0, "Should be more than zero");
            for(auto ith = threads.begin(), ith_end = threads.end(); ith != ith_end; ++ith, ++iresults)
            {
                std::promise<size_t> promise;
                *iresults = promise.get_future();
                *ith = std::thread(CacheTest<ip_t>, std::ref(cache), vlan_polling_size, netmask, 32 - subnet_size, pool_size, polling_size, std::move(promise));
            }
            
            // Analysis
            std::promise<size_t> promise;
            results.back() = promise.get_future();
            CacheTest<ip_t>(cache, vlan_polling_size, netmask, 32 - subnet_size, pool_size, polling_size, std::move(promise));
            for(auto ires = results.begin(), ires_end = results.end(); ires != ires_end; ++ires)
            {
                size_t _time = ires->get();
                if(_time > max)
                    max = _time;
                if(_time < min)
                    min = _time;
                total += _time;
            }
            
            for(auto i = threads.begin(), iend = threads.end(); i != iend; ++i)
                i->join();
        }
        
        experiment_log << pool_size << " " << total/threads_of_exec/test_repeats << " " << " " << min << " " << max << "\n";
    }
}