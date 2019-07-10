/*   RCDCap
 *   Copyright (C) 2013  Zdravko Velinov
 *
 *   This program is free software: you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation, either version 3 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "network-cache.hh"

#include "rcdcap/exception.hh"

#include <cassert>
#include <iterator>

#include <syslog.h>

#include <boost/property_tree/json_parser.hpp>
#include <boost/property_tree/xml_parser.hpp>
#include <boost/property_tree/info_parser.hpp>

using RCDCap::int64;
using RCDCap::int32;

// The diffent implementation of the hashing function.
#if NETWORK_CACHE_HASH_FUNCTION == XXHASH_FUNCTION
    extern "C"
    {
    #   include "xxhash.h"
    }
    FORCE_INLINE uint32 HashValue(vlan32 value)
    {
        return XXH32(&value, sizeof(vlan32), 0xEFFEC7);
    }

    FORCE_INLINE uint32 HashValue(const ip_t& value)
    {
        return XXH32(&value, sizeof(ip_t), 0xEFFEC7);
    }

    FORCE_INLINE uint32 HashValue(const ip6_t& value)
    {
        return XXH32(&value, sizeof(ip6_t), 0xEFFEC7);
    }
#elif NETWORK_CACHE_HASH_FUNCTION == MURMURHASH3_FUNCTION
#   include "MurmurHash3.h"
    FORCE_INLINE uint32 HashValue(vlan32 value)
    {
        uint32 result;
        MurmurHash3_x86_32(&value, sizeof(vlan32), 0xEFFEC7, &result);
        return result;
    }


    FORCE_INLINE uint32 HashValue(const ip_t& value)
    {
        uint32 result;
        MurmurHash3_x86_32(&value.front(), sizeof(ip_t), 0xEFFEC7, &result);
        return result;
    }

    FORCE_INLINE uint32 HashValue(const ip6_t& value)
    {
        uint32 result;
        MurmurHash3_x86_32(&value.front(), sizeof(ip6_t), 0xEFFEC7, &result);
        return result;
    }
#elif NETWORK_CACHE_HASH_FUNCTION == MURMURHASH3_FAST_FUNCTION
#   include "MurmurHash3.h"
    FORCE_INLINE uint32 HashValue(vlan32 value)
    {
        return fmix32(value);
    }

    FORCE_INLINE uint32 HashValue(const ip_t& value)
    {
        return fmix32(reinterpret_cast<const uint32&>(value.front()));
    }

    FORCE_INLINE uint32 HashValue(const ip6_t& value)
    {
        uint32 result;
        MurmurHash3_x86_32(&value.front(), sizeof(ip6_t), 0xEFFEC7, &result);
        return result;
    }
#elif defined(NETWORK_CACHE_HASH_FUNCTION)
#   error "Unknown hash function"
#endif


NetworkCache::NetworkCache(const QuietNeighborhoodOptions& opts)
    :   m_VLANPoolSize(opts.VLANPoolSize),
        m_HostPoolSize(opts.hostPoolSize),
        m_SubnetPoolSize(opts.subnetPoolSize),
        m_IPv4MinMask(~0u << (32 - opts.IPv4MinMask)),
        m_IPv4MaxMask(~0u << (32 - opts.IPv4MaxMask))        
{
    static_assert(sizeof(HostDescription<ip_t>) == 16, "Should be something which could be easily divided by 16 to ensure alignment");
    static_assert(sizeof(HostDescription<ip6_t>) == 32, "Should be something which could be easily divided by 16 to ensure alignment"); // Cache locality-wise it is terrible.

    ipv6_int128_t all_one = 0;
    all_one = ~all_one;
    assert(all_one + 1 == 0);
    
    m_IPv6MinMask = all_one << (128 - opts.IPv6MinMask);
    m_IPv6MaxMask = all_one << (128 - opts.IPv6MaxMask);
    
    size_t pool_size = m_VLANPoolSize*(m_HostPoolSize*(sizeof(HostDescription<ip_t>) + sizeof(HostDescription<ip6_t>)) +
                                       m_SubnetPoolSize*(sizeof(SubnetDescription<ip_t>) + sizeof(SubnetDescription<ip6_t>)) +
                                       sizeof(VLANEntry));
    m_MemoryPool = std::unique_ptr<NetworkCache::StorageType[]>(new StorageType[pool_size]);
    std::fill(m_MemoryPool.get(), m_MemoryPool.get() + pool_size, StorageType());
    
    size_t pool_counter = 0;
    m_IPv6Table = reinterpret_cast<HostDescription<ip6_t>*>(m_MemoryPool.get() + pool_counter);
    pool_counter += m_VLANPoolSize*m_HostPoolSize*sizeof(HostDescription<ip6_t>);
    
    m_IPv6SubnetTable = reinterpret_cast<SubnetDescription<ip6_t>*>(m_MemoryPool.get() + pool_counter);
    // This ensures that the mask always gets widened when computing the subnet
    SubnetDescription<ip6_t> invalid_ipv6_subnet{ 0, all_one };
    std::fill(m_IPv6SubnetTable, m_IPv6SubnetTable + m_VLANPoolSize*m_SubnetPoolSize, invalid_ipv6_subnet);
    pool_counter += m_VLANPoolSize*m_SubnetPoolSize*sizeof(SubnetDescription<ip6_t>);
    
    m_IPv4Table = reinterpret_cast<HostDescription<ip_t>*>(m_MemoryPool.get() + pool_counter);
    pool_counter += m_VLANPoolSize*m_HostPoolSize*sizeof(HostDescription<ip_t>);
     
    m_IPv4SubnetTable = reinterpret_cast<SubnetDescription<ip_t>*>(m_MemoryPool.get() + pool_counter);
    // This ensures that the mask always gets widened when computing the subnet
    for(size_t i = 0; i < m_VLANPoolSize*m_SubnetPoolSize; ++i)
    {
        m_IPv4SubnetTable[i].ID.store(0U, std::memory_order_relaxed);
        m_IPv4SubnetTable[i].mask.store(0xFFFFFFFFUL, std::memory_order_relaxed);
    }
    pool_counter += m_VLANPoolSize*m_SubnetPoolSize*sizeof(SubnetDescription<ip_t>);
    
    m_VLANTable = reinterpret_cast<VLANEntry*>(m_MemoryPool.get() + pool_counter);
    pool_counter += m_VLANPoolSize*sizeof(VLANEntry);
    
    assert(pool_counter == pool_size);
    
    // All services supported by this plug-in.
    m_ServiceMap["DNS"] = DNS_SERVICE;
    m_ServiceMap["DHCP"] = DHCP_SERVICE;
    m_ServiceMap["NTP"] = NTP_SERVICE;
    m_ServiceMap["SIP"] = SIP_SERVICE;
    m_ServiceMap["NIS"] = NIS_SERVICE;
    m_ServiceMap["ROUTIMG"] = ROUTING_SERVICE;
    m_ServiceMap["DHCPv6"] = DHCPV6_SERVICE;
    m_ServiceMap["NISP"] = NISP_SERVICE;
    m_ServiceMap["TP"] = TP_SERVICE;
    m_ServiceMap["NAME"] = NAME_SERVICE;
    m_ServiceMap["LOG"] = LOG_SERVICE;
    m_ServiceMap["COOKIE"] = COOKIE_SERVICE;
    m_ServiceMap["LPR"] = LPR_SERVICE;
    m_ServiceMap["IMPRESS"] = IMPRESS_SERVICE;
    m_ServiceMap["RLS"] = RLS_SERVICE;
    m_ServiceMap["NETBIOS_NAME"] = NETBIOS_NAME_SERVICE;
    m_ServiceMap["NETBIOS_DDS"] = NETBIOS_DDS_SERVICE;
    m_ServiceMap["XWSFS"] = XWSFS_SERVICE;
    m_ServiceMap["XWSDM"] = XWSDM_SERVICE;
    m_ServiceMap["SMTP"] = SMTP_SERVICE;
    m_ServiceMap["POP3"] = POP3_SERVICE;
    m_ServiceMap["NNTP"] = NNTP_SERVICE;
    m_ServiceMap["WWW"] = WWW_SERVICE;
    m_ServiceMap["FINGER"] = FINGER_SERVICE;
    m_ServiceMap["IRC"] = IRC_SERVICE;
    m_ServiceMap["STREETTALK"] = STREETTALK_SERVICE;
    m_ServiceMap["STDA"] = STDA_SERVICE;
    m_ServiceMap["BCMCS"] = BCMCS_SERVICE;
    m_ServiceMap["PANA"] = PANA_SERVICE;
}

NetworkCache::~NetworkCache()
{
}

typedef std::unordered_map<std::string, ServiceFlags> ServiceMap;

// Some functions that are used by the template algorithms.
// Because it is quite repetitive, I have decided to use separate
// functions instead of lambdas.
FORCE_INLINE bool IsAddressValid(size_t addr)
{
    return addr != 0;
} 

FORCE_INLINE bool IsAddressValid(const ip_t& addr)
{
    return reinterpret_cast<const RCDCap::uint32&>(addr) != 0;
}

FORCE_INLINE bool IsAddressValid(const ip6_t& addr)
{
    return reinterpret_cast<const ipv6_int128_t&>(addr) != 0;
}

template<class T>
FORCE_INLINE T AtomicLoad(const std::atomic<T>& var) { return var.load(); }

FORCE_INLINE ipv6_int128_t AtomicLoad(ipv6_int128_t var) { return var; }

FORCE_INLINE bool AtomicCompareAndSwap(std::atomic<uint32>& var, uint32 old_value, uint32 new_value)
{
    return var.compare_exchange_weak(old_value, new_value);
}

FORCE_INLINE bool AtomicCompareAndSwap(ipv6_int128_t& var, ipv6_int128_t old_value, ipv6_int128_t new_value)
{
    return __sync_val_compare_and_swap(&var, old_value, new_value) == old_value;
}

FORCE_INLINE bool TryInit(ipv6_int128_t& var, const ip6_t& next_val)
{
    return __sync_val_compare_and_swap(reinterpret_cast<ipv6_int128_t*>(&var), 0, reinterpret_cast<const ipv6_int128_t&>(next_val)) == 0;
}

FORCE_INLINE bool TryInit(std::atomic<uint32>& var, const ip_t& next_val)
{
    uint32 zero = 0;
    return var.compare_exchange_weak(zero, reinterpret_cast<const uint32&>(next_val));
}

FORCE_INLINE bool TryInit(std::atomic<vlan32>& var, vlan32 next_val)
{
    vlan32 zero = 0;
    return var.compare_exchange_weak(zero, next_val);
}


// Reloads the cached host table. It marks the services by applying the correct service_shift. 
template<class T, class TAcquireIP>
void ReloadCacheAddressTable(const ServiceMap& service_map, const boost::property_tree::ptree& pt, VLANEntry* vlan, size_t service_shift, const TAcquireIP& acquire_ip)
{
    using boost::property_tree::ptree;
    for(ptree::const_iterator i = pt.begin(), iend = pt.end(); i != iend; ++i)
    {
        auto& host_entry = i->second;
        auto ip = host_entry.get<T>("host_address");
        auto* host = acquire_ip(vlan, ip);
        if(host == nullptr)
        {
            LOG_MESSAGE(LOG_ERR, "Network cache error: The specified host pool could not fit the amount of hosts.");
            return;
        }
        auto services = host_entry.get_child_optional("services");
        if(services)
            for(ptree::const_iterator j = services->begin(), jend = services->end(); j != jend; ++j)
            {
                auto& service = j->second;
                auto service_name = service.get_value<std::string>();
                auto iter = service_map.find(service_name);
                if(iter == service_map.end())
                {
                    LOG_MESSAGE(LOG_ERR, "Network cache error: Unknown type of service(%s) specified for the following host: %d.%d.%d.%d.", 
                                    service_name.c_str(), static_cast<int>(ip[0]), static_cast<int>(ip[1]), static_cast<int>(ip[2]), static_cast<int>(ip[3]));
                    continue;
                }
                host->serviceFlags |= iter->second << service_shift;
            }
    }
}

// Reloads a complete VLAN table. Most of the stuff related to table state are hidden behind the acquire functions.
template<class TAcquireVLAN, class TAcquireIPv4, class TAcquireIPv6>
void ReloadCacheTable(CacheFormat fmt,
                      std::istream& fs,
                      VLANEntry* vlan_table,
                      const ServiceMap& service_map,
                      size_t service_shift,
                      const TAcquireVLAN& acquire_vlan,
                      const TAcquireIPv4& acquire_ipv4,
                      const TAcquireIPv6& acquire_ipv6)
{
    using boost::property_tree::ptree;
    ptree pt;
    
    switch(fmt)
    {
    case CacheFormat::JSON: boost::property_tree::json_parser::read_json(fs, pt); break;
    case CacheFormat::XML: boost::property_tree::xml_parser::read_xml(fs, pt); break;
    case CacheFormat::INFO: boost::property_tree::info_parser::read_info(fs, pt); break;
    }
    
    auto vlan_table_entry = pt.get_child("vlan_table");
    for(ptree::const_iterator i = vlan_table_entry.begin(), iend = vlan_table_entry.end(); i != iend; ++i)
    {
        auto& vlan_entry = i->second;
        auto vid = vlan_entry.get<size_t>("vid", UnassignedVLAN);
        auto* vlan = acquire_vlan(vlan_table, vid);
        if(vlan == nullptr)
        {
            LOG_MESSAGE(LOG_ERR, "Network cache error: The specified VLAN pool could not fit the amount of VLAN specified.");
            return;
        }
        
        ReloadCacheAddressTable<ip_t>(service_map, vlan_entry.get_child("ipv4_table"), vlan, service_shift, acquire_ipv4);
        ReloadCacheAddressTable<ip6_t>(service_map, vlan_entry.get_child("ipv6_table"), vlan, service_shift, acquire_ipv6);
    }
}


void NetworkCache::reloadCache(CacheFormat fmt, std::istream& fs_legitimate, std::istream& fs_suspicious, bool merge)
{
    try
    {
        auto acquire_vlan = [this](VLANEntry* vlan_table, size_t vid) { return this->acquire(vlan_table, this->m_VLANPoolSize, vid); };
        auto acquire_ipv4 = [this](VLANEntry* vlan_table, const ip_t& _ip) 
                            {
                                size_t offset = vlan_table - this->m_VLANTable;
                                HostDescription<ip_t>* ipv4_table;
                                getTable(offset, ipv4_table);
                                return this->acquire(ipv4_table, this->m_HostPoolSize, _ip);
                            };
        auto acquire_ipv6 = [this](VLANEntry* vlan_table, const ip6_t& _ip)
                            {
                                size_t offset = vlan_table - this->m_VLANTable;
                                HostDescription<ip6_t>* ipv6_table;
                                getTable(offset, ipv6_table);
                                return this->acquire(ipv6_table, this->m_HostPoolSize, _ip);
                            };
        
        
        ReloadCacheTable(fmt, fs_legitimate, m_VLANTable, m_ServiceMap, 0, acquire_vlan, acquire_ipv4, acquire_ipv6);
        
        if(!fs_suspicious)
            return;
        
        if(merge)
        {
            ReloadCacheTable(fmt, fs_suspicious, m_VLANTable, m_ServiceMap, 0, acquire_vlan, acquire_ipv4, acquire_ipv6);
        }
        else
        {
            // Mind the contents of these lambda functions. Some of them contain special marking when acquiring entries.
            auto acquire_suspicious_vlan = [this](VLANEntry* vlan_table, size_t vid) { return this->acquire(vlan_table, this->m_VLANPoolSize, vid | SuspiciousVLANBit); };
            auto acquire_suspicious_ipv4 = [this](VLANEntry* vlan_table, const ip_t& _ip)
                                           {
                                               size_t offset = vlan_table - this->m_VLANTable;
                                               HostDescription<ip_t>* ipv4_table;
                                               getTable(offset, ipv4_table);
                                               return this->acquire(ipv4_table, this->m_HostPoolSize, _ip);
                                           };
            auto acquire_suspicious_ipv6 = [this](VLANEntry* vlan_table, const ip6_t& _ip)
                                           {
                                               size_t offset = vlan_table - this->m_VLANTable;
                                               HostDescription<ip6_t>* ipv6_table;
                                               getTable(offset, ipv6_table);               
                                               return this->acquire(ipv6_table, this->m_HostPoolSize, _ip);
                                           };
            
            ReloadCacheTable(fmt, fs_suspicious, m_VLANTable, m_ServiceMap, 32,
                             acquire_suspicious_vlan, acquire_suspicious_ipv4, acquire_suspicious_ipv6);
        }
    }
    catch(const boost::property_tree::ptree_bad_data& e)
    {
        THROW_EXCEPTION("Failed to parse network cache: Invalid property tree data.");
    }
    catch(const boost::property_tree::ptree_bad_path& e)
    {
        THROW_EXCEPTION("Failed to parse network cache: Invalid property tree structure.");
    }
    catch(const RCDCap::Exception& e)
    {
        throw e;
    }
    catch(...)
    {
        THROW_EXCEPTION("Failed to parse network cache");
    }
}


template<class T>
void SaveCacheAddressTable(const ServiceMap& service_map, const std::string& table_name, const T* table, size_t host_pool_size, uint64 flag_shift, bool force_include, boost::property_tree::ptree& pt)
{
    pt.put(table_name, "");
    for(auto addr = table, addr_end = table + host_pool_size; addr != addr_end; ++addr)
    {
        if(!IsAddressValid(reinterpret_cast<const typename T::id_type&>(addr->ID)))
            continue;
        
        // Basically, we save the addresses to the correct table depending on the actual marking.
        auto flags = addr->serviceFlags.load();
        if(((flags >> flag_shift) & 0xFFFFFFFFULL) == 0 && (flag_shift != 0 || flags != 0) && !force_include)
            continue;
        flags >>= flag_shift;
        
        boost::property_tree::ptree ip_pt;
        ip_pt.put("host_address", reinterpret_cast<const typename T::id_type&>(addr->ID));
                
        // There is a service map which is used for determining the correct mask of each service.
        for(auto i = service_map.begin(), iend = service_map.end(); i != iend; ++i)
            if(flags & i->second)
                ip_pt.add("services.name", i->first);
        pt.add_child(table_name + ".host", ip_pt);
    }
}

template<class T>
void SaveSubnetTable(const std::string& table_name, const T* table, size_t subnet_pool_size, boost::property_tree::ptree& pt)
{
    pt.put(table_name, "");
    for(auto addr = table, addr_end = table + subnet_pool_size; addr != addr_end; ++addr)
    {
        if(!IsAddressValid(reinterpret_cast<const typename T::id_type&>(addr->ID)))
            continue;
        
        // The mask is transformed to integer representation by applying log2 operation.
        auto host_mask = ~addr->mask + 1;
        auto net_addr = RCDCap::ByteSwap(RCDCap::ByteSwap(AtomicLoad(addr->ID)) & addr->mask);
        
        boost::property_tree::ptree ip_pt;
        ip_pt.put("network", reinterpret_cast<const typename T::id_type&>(net_addr));
        ip_pt.put("mask", sizeof(host_mask)*8 - IntegerLog2(host_mask));        
        
        pt.add_child(table_name + ".host", ip_pt);
    }
}

void SaveCacheTable(CacheFormat fmt,
                    vlan32 vlan_type,
                    const ServiceMap& service_map,
                    const HostDescription<ip6_t>* ip6_table,
                    const SubnetDescription<ip6_t>* ip6_subnet_table,
                    const HostDescription<ip_t>* ip_table,
                    const SubnetDescription<ip_t>* ip_subnet_table,
                    const VLANEntry* vlan_table, 
                    size_t vlan_pool_size, size_t host_pool_size, size_t subnet_pool_size, uint64 flag_shift, std::ostream& fs)
{
    boost::property_tree::ptree pt;
        
    pt.put("vlan_table","");

    size_t count = 0;
    for(auto vlan = vlan_table; count < vlan_pool_size; ++vlan, ++count)
    {
        auto id = vlan->ID.load();
        if(!IsAddressValid(id) || (id & SuspiciousVLANBit) != vlan_type)
            continue;
        
        // This one forces all things on this VLAN to be considered as suspicious.
        // It is a bit of pessimistic algorithm.
        bool force_include = false;
        if((id & SuspiciousVLANBit) != 0)
        {
            if(flag_shift)
                force_include = true;
            else
                continue;
        }
        
        id &= ~SuspiciousVLANBit;
        
        boost::property_tree::ptree vlan_pt;
        if(id != UnassignedVLAN)
            vlan_pt.put("vid", id);
        
        SaveCacheAddressTable(service_map, "ipv4_table", ip_table + count*host_pool_size, host_pool_size, flag_shift, force_include, vlan_pt);
        SaveCacheAddressTable(service_map, "ipv6_table", ip6_table + count*host_pool_size, host_pool_size, flag_shift, force_include, vlan_pt);
        SaveSubnetTable("ipv4_subnet", ip_subnet_table + count*host_pool_size, subnet_pool_size, vlan_pt);
        SaveSubnetTable("ipv6_subnet", ip6_subnet_table + count*host_pool_size, subnet_pool_size, vlan_pt);
        if(!vlan_pt.get_child("ipv4_table").empty() || !vlan_pt.get_child("ipv6_table").empty())
            pt.add_child("vlan_table.vlan", vlan_pt);
    }
    switch(fmt)
    {
    case CacheFormat::JSON: boost::property_tree::json_parser::write_json(fs, pt); break;
    case CacheFormat::XML: boost::property_tree::xml_parser::write_xml(fs, pt); break;
    case CacheFormat::INFO: boost::property_tree::info_parser::write_info(fs, pt); break;
    }
}

void NetworkCache::saveCache(CacheFormat fmt, std::ostream& fs_legitimate, std::ostream& fs_suspicious)
{
    try
    {
        SaveCacheTable(fmt, 0, m_ServiceMap, m_IPv6Table, m_IPv6SubnetTable, m_IPv4Table,
                       m_IPv4SubnetTable, m_VLANTable, m_VLANPoolSize,
                       m_HostPoolSize, m_SubnetPoolSize, 0, fs_legitimate);
        if(fs_suspicious.good())
            SaveCacheTable(fmt, SuspiciousVLANBit, m_ServiceMap, m_IPv6Table, m_IPv6SubnetTable, m_IPv4Table, m_IPv4SubnetTable,
                           m_VLANTable, m_VLANPoolSize, m_HostPoolSize, m_SubnetPoolSize, 32, fs_suspicious);
    }
    catch(const boost::property_tree::ptree_bad_data& e)
    {
        THROW_EXCEPTION("Failed to parse network cache because bad data was specified");
    }
    catch(const boost::property_tree::ptree_bad_path& e)
    {
        THROW_EXCEPTION("Failed to parse network cache because bad tree path was specified");
    }
    catch(...)
    {
        THROW_EXCEPTION("Failed to parse network cache");
    }
}

#ifndef NETWORK_CACHE_HASH_FUNCTION
template<class TEntry>
TEntry* NetworkCache::acquire(TEntry* _table, size_t pool_size, const typename TEntry::id_type& value)
{
    typedef decltype(AtomicLoad(_table->ID)) key_type;
    size_t current_entry = 0;

    while(current_entry < pool_size)
    {
        auto cur_val = AtomicLoad(_table[current_entry].ID);
        if(IsAddressValid(cur_val))
        {
            if(cur_val == reinterpret_cast<const key_type&>(value))
                return _table + current_entry;
            else
                ++current_entry;
        }
        else if(TryInit(_table[current_entry].ID, value))
            return _table + current_entry;
    }
    return nullptr;
}
#else
template<class TEntry>
TEntry* NetworkCache::acquire(TEntry* _table, size_t pool_size, const typename TEntry::id_type& value)
{
    assert(pool_size);
    typedef decltype(AtomicLoad(_table->ID)) key_type;
    size_t initial_value = HashValue(value) % pool_size;
    size_t current_entry = initial_value;

    for(;;)
    {
        auto cur_val = AtomicLoad(_table[current_entry].ID);
        if(IsAddressValid(cur_val))
        {
            if(cur_val == reinterpret_cast<const key_type&>(value))
                return _table + current_entry;
            else
            {
                current_entry = (current_entry + 1) % pool_size;
                if(current_entry == initial_value)
                    break;
            }
        }
        else if(TryInit(_table[current_entry].ID, value))
            return _table + current_entry;
    }
    return nullptr;
}
#endif

template<class T>
SubnetDescription<T>* NetworkCache::subnetAggregate(SubnetDescription<T>* _table, const typename SubnetDescription<T>::id_type& value, typename SubnetDescription<T>::int_type mask)
{
    size_t current_entry = 0;

    decltype(AtomicLoad(_table[current_entry].ID)) cur_subnet, min_mask;
    
    // TODO: It is possible to do it with a single loop.
    do
    {
        while(current_entry < m_SubnetPoolSize && IsAddressValid(cur_subnet = AtomicLoad(_table[current_entry].ID)))
        {
            // First we compute the subnet mask.
            getMinMask(min_mask);
            auto subnet_mask = ComputeSubnetMask(value, reinterpret_cast<const typename SubnetDescription<T>::id_type&>(cur_subnet), min_mask);
            auto cur_subnet_mask = AtomicLoad(_table[current_entry].mask);
            
            // We just return it if there is no need to make it bigger.
            if((~subnet_mask & cur_subnet_mask) == 0)
                return _table + current_entry;
            
            // If it is bigger than the maximum subnet size, we search for some other subnet.
            if(!canAggregate(subnet_mask))
            {
                 ++current_entry;
                continue;
            }
            
            // Otherwise we proceed to widening the table.
            if(AtomicCompareAndSwap(_table[current_entry].mask, cur_subnet_mask, subnet_mask & mask))
                return _table + current_entry;
        }
        // Don't bother if the pool was depleted.
        if(current_entry == m_SubnetPoolSize)
            return nullptr;
    // If it is invalid address, try to replace it with a newer one.
    } while(!TryInit(_table[current_entry].ID, value));
    // We just initialize stuff that are all ones. Otherwise, someone has already computed a better mask. Therefore, we should not
    // do anything.
    initSubnetMask(_table[current_entry].mask, mask);
    return _table + current_entry;
}

template SubnetDescription<ip_t>* NetworkCache::subnetAggregate<ip_t>(SubnetDescription<ip_t>* _table, const ip_t& value, uint32 mask);
template SubnetDescription<ip6_t>* NetworkCache::subnetAggregate<ip6_t>(SubnetDescription<ip6_t>* _table, const ip6_t& value, ipv6_int128_t mask);

#ifndef NETWORK_CACHE_HASH_FUNCTION
// Linear search implementation.
VLANEntry* NetworkCache::acquireVLANImpl(vlan32 vid, vlan32 new_mask)
{
    decltype(m_VLANTable->ID) current_vid;        
    size_t current_entry = 0;
    
    // We try until the pool is depleted.
    while(current_entry < m_VLANPoolSize)
    {
        current_vid = AtomicLoad(m_VLANTable[current_entry].ID);
        // If it is valid we check whether we have a match.
        if(IsAddressValid(current_vid))
        {
            if((current_vid & ~SuspiciousVLANBit) == vid)
                return m_VLANTable + current_entry;
            else
                ++current_entry;
        }
        // Otherwise, we try to initialize it.
        else if(TryInit(m_VLANTable[current_entry].ID, vid|new_mask))
        {
            // We report any suspicious VLAN.
            if(new_mask & SuspiciousVLANBit)
            {
                std::stringstream ss;
                ss << "Misconfiguration detected: New VLAN detected(" << vid << "). All activities within this VLAN are considered illegal.\n";
                LOG_MESSAGE(LOG_ERR, "%s", ss.str().c_str());
            }
            return m_VLANTable + current_entry;
        }
    }
    return nullptr;
}
#else
// Hash map implementation.
VLANEntry* NetworkCache::acquireVLANImpl(vlan32 vid, vlan32 new_mask)
{
    assert(m_VLANPoolSize);
    size_t initial_value = HashValue(vid) % m_VLANPoolSize;
    size_t current_entry = initial_value;
    
    for(;;)
    {
        auto current_vid = AtomicLoad(m_VLANTable[current_entry].ID);
        if(IsAddressValid(current_vid))
        {
            // If it is valid we check whether it is the searched entry.
            if((current_vid & ~SuspiciousVLANBit) == vid)
                return m_VLANTable + current_entry;
            else
            {
                // Otherwise, we proceed with the next value.
                current_entry = (current_entry + 1) % m_VLANPoolSize;
                // If we ram ourselves in the initial value, then the VLAN pool was depleted. So we must report about it.
                if(current_entry == initial_value)
                {
                    LOG_MESSAGE(LOG_ERR, "Network options error: Not enough VLANs were specified. Check for any new unexpected VLAN."
                                         "The activities from the following VLAN were ignored: %d.", (int)vid);
                    break;
                }
            }
        }
        // Try to initialize the value.
        else if(TryInit(m_VLANTable[current_entry].ID, vid|new_mask))
        {
            // If it is in monitoring mode mark the value accordingly and report it.
            if(new_mask & SuspiciousVLANBit)
            {
                std::stringstream ss;
                ss << "Misconfiguration detected: New VLAN detected(" << vid << "). All activities within this VLAN are considered illegal.\n";
                LOG_MESSAGE(LOG_ERR, "%s", ss.str().c_str());
            }
            return m_VLANTable + current_entry;
        }
    }
    return nullptr;
}
#endif

VLANEntry* NetworkCache::acquireVLAN(MonitorState _state, vlan32 vid)
{
    VLANEntry* vlan = nullptr;
    
    // Oh, well -- I should probably delete that. It is kind of pointless.
    switch(_state)
    {
    case MonitorState::LEARNING_PHASE: vlan = acquireVLANImpl(vid, 0); break;
    case MonitorState::MONITORING_PHASE: vlan = acquireVLANImpl(vid, SuspiciousVLANBit); break;
    }
    
    return vlan;
}

template<class T>
void NetworkCache::subnetAggregateCheck(MonitorState _state, SubnetDescription<T>* subnet_table, const typename SubnetDescription<T>::id_type& _ip)
{
    switch(_state)
    {
    case MonitorState::LEARNING_PHASE:
    {
        // Assumes that the learning phase is only once at the beginning
        typename SubnetDescription<T>::int_type mask = 1;
        subnetAggregate(subnet_table, _ip, ~mask);
    } break;
    case MonitorState::MONITORING_PHASE:
    {
        typename SubnetDescription<T>::int_type mask = 0;
        auto* result = subnetAggregate(subnet_table, _ip, ~mask);
        if((result->ID & 1) == 1)
        {
            // It is marked; therefore, we must report it.
            std::stringstream ss;
            auto subnet = RCDCap::ByteSwap(reinterpret_cast<const decltype(mask)&>(result->ID));
            subnet &= result->mask;
            subnet = RCDCap::ByteSwap(subnet);
            auto subnet_ip = reinterpret_cast<const typename SubnetDescription<T>::id_type&>(subnet);
            ss << "Invalid subnet detected: " << subnet_ip;
            syslog(LOG_ERR, "%s", ss.str().c_str());
        }
    } break;
    }

}

template void NetworkCache::subnetAggregateCheck(MonitorState _state, SubnetDescription<ip_t>* subnet_table, const ip_t& ip);
template void NetworkCache::subnetAggregateCheck(MonitorState _state, SubnetDescription<ip6_t>* subnet_table, const ip6_t& ip);

template<class T>
HostDescription<T>* NetworkCache::acquireIP(MonitorState _state, VLANEntry* vlan, const T& _ip)
{
    auto offset = vlan - m_VLANTable;
    assert(offset < m_VLANPoolSize);
    
    if(RCDCap::IsMulticast(_ip) || RCDCap::IsBroadcast(_ip))
    {
        std::stringstream ss;
        ss << "Multicast or broadcast detected when populating host address table: " << _ip;
        LOG_MESSAGE(LOG_ERR, "%s", ss.str().c_str());
    }
    HostDescription<T>* table;
    SubnetDescription<T>* subnet_table;
    getTable(offset, subnet_table);
    getTable(offset, table);
    // First, it checks the subnet.
    subnetAggregateCheck(_state, subnet_table, _ip);
    // Then it acquires the IP address.
    auto* ip = acquire(table, m_HostPoolSize, _ip);
    if(ip == nullptr)
        LOG_MESSAGE(LOG_ERR, "Network options error: The specified IP pool was depleted. You might be a subject of an ongoing attack to starve the IP pool.");
    return ip;
}

template HostDescription<ip_t>* NetworkCache::acquireIP<ip_t>(MonitorState _state, VLANEntry* vlan, const ip_t& _ip);
template HostDescription<ip6_t>* NetworkCache::acquireIP<ip6_t>(MonitorState _state, VLANEntry* vlan, const ip6_t& _ip);

template<class T>
HostDescription<T>* NetworkCache::acquireServiceIP(MonitorState _state, VLANEntry* vlan, const T& _ip, size_t service_flags)
{
    auto offset = vlan - m_VLANTable;
    assert(offset < m_VLANPoolSize);
    if(RCDCap::IsMulticast(_ip) || RCDCap::IsBroadcast(_ip))
    {
        std::stringstream ss;
        ss << "Multicast or broadcast detected when populating host address table: " << _ip;
        LOG_MESSAGE(LOG_ERR, "%s", ss.str().c_str());
    }
 
    HostDescription<T>* table;
    SubnetDescription<T>* subnet_table;
    getTable(offset, table);
    getTable(offset, subnet_table);
    // First, it checks the subnet.
    subnetAggregateCheck(_state, subnet_table, _ip);
    HostDescription<T>* host = nullptr;
    switch(_state)
    {
    case MonitorState::LEARNING_PHASE:
    {
        host = acquire(table, m_HostPoolSize, _ip);
        if(host == nullptr)
        {
            LOG_MESSAGE(LOG_ERR, "Network options error: The specified IP pool was depleted. You might be a subject of an ongoing attack to starve the IP pool.");
            return nullptr;
        }
        // We try to set the service with current type of marking.
        if(host->serviceFlags.fetch_or(service_flags) & (service_flags << 32))
            // If someone has set some other type, we must revert it.
            host->serviceFlags.fetch_and(~service_flags);
    } break;
    case MonitorState::MONITORING_PHASE:
    {
        host = acquire(table, m_HostPoolSize, _ip);
        if(host == nullptr)
        {
            LOG_MESSAGE(LOG_ERR, "Network options error: The specified IP pool was depleted. You might be a subject of an ongoing attack to starve the IP pool.");
            return nullptr;
        }
        // We try to set the service with current type of marking.
        if(host->serviceFlags.fetch_or(service_flags << 32) & service_flags)
            // If someone has set some other type, we must revert it.
            host->serviceFlags.fetch_and(~(service_flags << 32));
        else
        {
            // It turns out that it is a new service. We must report it immediately.
            std::stringstream ss;
            ss << "Network service error: Suspicious ";
            for(auto i = m_ServiceMap.begin(), iend = m_ServiceMap.end(); i != iend; ++i)
                if(service_flags & i->second)
                    ss << i->first << " ";
                
            ss << "service associated with following IP address is being advertised: " << _ip;
            LOG_MESSAGE(LOG_ERR, "%s", ss.str().c_str());
            return nullptr;
        }
    } break;
    }
    return host;
}

template HostDescription<ip_t>* NetworkCache::acquireServiceIP<ip_t>(MonitorState _state, VLANEntry* vlan, const ip_t& _ip, size_t service_flags);
template HostDescription<ip6_t>* NetworkCache::acquireServiceIP<ip6_t>(MonitorState _state, VLANEntry* vlan, const ip6_t& _ip, size_t service_flags);
