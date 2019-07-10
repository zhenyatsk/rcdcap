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

#ifndef _QN_NETWORK_CACHE_HH_
#define _QN_NETWORK_CACHE_HH_

#include "quiet-neighborhood.hh"
#include "rcdcap/packet-headers.hh"

#include <atomic>
#include <limits>
#include <memory>
#include <unordered_map>

#include <xmmintrin.h>

#define FORCE_INLINE inline __attribute__((__always_inline__))

using RCDCap::uint32;
using RCDCap::uint64;
using RCDCap::ip_t;
using RCDCap::ip6_t;

//! Flags that describe network services advertised by DHCP servers.
enum ServiceFlags
{
    DNS_SERVICE          = 1 << 0,  //!< Domain Name Service
    DHCP_SERVICE         = 1 << 1,  //!< Dynamic Host Configuration Protocol (DHCP) service
    NTP_SERVICE          = 1 << 2,  //!< Network Time Protocol service
    SIP_SERVICE          = 1 << 3,  //!< Session Initiation Protocol service
    NIS_SERVICE          = 1 << 4,  //!< Network Information Service (NIS)
    ROUTING_SERVICE      = 1 << 5,  //!< Packet routing
    DHCPV6_SERVICE       = 1 << 6,  //!< DHCPv6 service
    NISP_SERVICE         = 1 << 7,  //!< NIS+
    TP_SERVICE           = 1 << 8,  //!< Time Protocol service
    NAME_SERVICE         = 1 << 9,  //!< ARPA Name service (obsolete)
    LOG_SERVICE          = 1 << 10, //!< Log service
    COOKIE_SERVICE       = 1 << 11, //!< Cookie service
    LPR_SERVICE          = 1 << 12, //!< Line Printer service
    IMPRESS_SERVICE      = 1 << 13, //!< Impress service (obsolete)
    RLS_SERVICE          = 1 << 14, //!< Resource Location Service
    NETBIOS_NAME_SERVICE = 1 << 15, //!< NetBIOS over TCP/IP Name Service
    NETBIOS_DDS_SERVICE  = 1 << 16, //!< NetBIOS over TCP/IP Datagram Distribution Service
    XWSFS_SERVICE        = 1 << 17, //!< X Window System Font Service
    XWSDM_SERVICE        = 1 << 18, //!< X Window System Display Manager
    SMTP_SERVICE         = 1 << 19, //!< Simple Mail Transfer Protocol
    POP3_SERVICE         = 1 << 20, //!< Post Office Protocol service
    NNTP_SERVICE         = 1 << 21, //!< Network News Transfer Protocol service
    WWW_SERVICE          = 1 << 22, //!< Default World Wide Web service
    FINGER_SERVICE       = 1 << 23, //!< Finger service
    IRC_SERVICE          = 1 << 24, //!< Internet Relay Chat service
    STREETTALK_SERVICE   = 1 << 25, //!< StreetTalk service
    STDA_SERVICE         = 1 << 26, //!< StreetTalk Directory Assistance service
    BCMCS_SERVICE        = 1 << 27, //!< Broadcast and multicast service
    PANA_SERVICE         = 1 << 28  //!< Protocol for carrying Authentication for Network Access service
};

#define XXHASH_FUNCTION           1
#define MURMURHASH3_FUNCTION      2
#define MURMURHASH3_FAST_FUNCTION 3

//! Integer value representing IPv6 address.
typedef __int128 ipv6_int128_t;

//! Integer value representing marked VLAN identifier.
typedef uint32 vlan32;

//! Suspicious bit marking.
constexpr vlan32 SuspiciousVLANBit = 1 << 31;

//! Unassigned VLAN value.
constexpr vlan32 UnassignedVLAN = ~SuspiciousVLANBit;

/*! \brief Host description table entry.
 *  
 *  \tparam T   the address type which is associated with this entry.
 */
template<class T>
struct HostDescription;

//! Description of IPv4 host.
template<>
struct HostDescription<ip_t>
{
    std::atomic<uint32> ID;           //!< IPv4 address of this host.
    uint32              padding;      //!< Padding to guarantee alignment.
    std::atomic<uint64> serviceFlags; //!< Flags which indicate what kind of services are offered by this host.
    
    typedef ip_t        id_type;      //!< The type of the IP address.
};

//! Description of IPv6 host.
template<>
struct HostDescription<ip6_t>
{
    ipv6_int128_t       ID;           //!< IPv6 address of this host.
    uint64              padding;      //!< Padding to guarantee alignment.
    std::atomic<uint64> serviceFlags; //!< Flags which indicate what kind of services are offered by this host.
    
    typedef ip6_t       id_type;      //!< The type of the IP address.
};

//! Description of subnet.
template<class T> struct SubnetDescription;

//! Description of IPv4 subnet.
template<>
struct SubnetDescription<ip_t>
{
    std::atomic<uint32>   ID;       //!< The base address of IPv4 subnet.
    std::atomic<uint32>   mask;     //!< The IPv4 subnet address mask.
    
    typedef ip_t          id_type;  //!< The type of the base subnet address.
    typedef uint32        int_type; //!< The integer type used for address computations.
};

//! Description of IPv6 subnet.
template<>
struct SubnetDescription<ip6_t>
{
    ipv6_int128_t         ID;       //!< The base address of IPv6 subnet.
    ipv6_int128_t         mask;     //!< The IPv6 subnet address mask.
    
    typedef ip6_t         id_type;  //!< The type of the base subnet address.
    typedef ipv6_int128_t int_type; //!< The integer type used for address computations.
};

//! Description VLAN.
struct VLANEntry
{
    std::atomic<vlan32>   ID;      //!< VLAN identifier and marking.

    typedef vlan32        id_type; //!< The type of the VLAN identifier.
};

/*! \brief Computes subnet that could accommodate the two IPv4 addresses.
 * 
 *  The computation is done by finding the difference between the two addresses. It also
 *  widens it if one of the addresses is actually a broadcast address according
 *  to the computed subnet mask.
 * 
 *  \param ip1      the first IP address used in the computation.
 *  \param ip2      the second IP address used in the computation.
 *  \param min_mask the minimum mask which prevents networks that are too small.
 */
FORCE_INLINE uint32 ComputeSubnetMask(const ip_t& ip1, const ip_t& ip2, uint32 min_mask)
{
    uint32 lhs_val = RCDCap::ByteSwap(reinterpret_cast<const uint32&>(ip1[0]));
    uint32 rhs_val = RCDCap::ByteSwap(reinterpret_cast<const uint32&>(ip2[0]));
    uint32 val = lhs_val ^ rhs_val;
    val |= val >> 1;
    val |= val >> 2;
    val |= val >> 4;
    val |= val >> 8;
    val |= val >> 16;
    val |= (lhs_val & val) + 1;
    val |= (rhs_val & val) + 1;
    return ~val & min_mask;
}

/*! \brief Computes subnet that could accommodate the two IPv6 addresses.
 *
 *  The computation is done by finding the difference between the two addresses. It also
 *  widens it if one of the addresses is actually a broadcast address according
 *  to the computed subnet mask.
 * 
 *  \param ip1      the first IP address used in the computation.
 *  \param ip2      the second IP address used in the computation.
 *  \param min_mask the minimum mask which prevents networks that are too small.
 */
FORCE_INLINE ipv6_int128_t ComputeSubnetMask(const ip6_t& ip1, const ip6_t& ip2, ipv6_int128_t min_mask)
{
    ipv6_int128_t lhs_val = RCDCap::ByteSwap(reinterpret_cast<const ipv6_int128_t&>(ip1[0]));
    ipv6_int128_t rhs_val = RCDCap::ByteSwap(reinterpret_cast<const ipv6_int128_t&>(ip2[0]));
    ipv6_int128_t val = lhs_val ^ rhs_val;
    val |= val >> 1;
    val |= val >> 2;
    val |= val >> 4;
    val |= val >> 8;
    val |= val >> 16;
    val |= val >> 32;
    val |= val >> 64;
    val |= (lhs_val & val) + 1;
    val |= (rhs_val & val) + 1;
    return ~val & min_mask;
}

//! Computes log base 2 of an 32-bit integer value
FORCE_INLINE uint32 IntegerLog2(const uint32 x)
{
    uint32_t y;
    asm ( "\tbsr %1, %0\n"
        : "=r"(y)
        : "r" (x)
    );
    return y;
}

//! Computes log base 2 of an 128-bit integer value
FORCE_INLINE uint32 IntegerLog2(ipv6_int128_t x)
{
    ipv6_int128_t r,
                  shift;
    r     = (x > 0xFFFFFFFFFFFFFFFFULL) << 6; x >>= r;
    shift = (x > 0xFFFFFFFFULL)         << 5; x >>= shift; r |= shift;
    shift = (x > 0xFFFFULL)             << 4; x >>= shift; r |= shift;
    shift = (x > 0xFFULL)               << 3; x >>= shift; r |= shift;
    shift = (x > 0xFULL)                << 2; x >>= shift; r |= shift;
    shift = (x > 0x3ULL)                << 1; x >>= shift; r |= shift;
                                                           r |= (x >> 1);
    return r;
}

/*! \brief Contains information about the network that is being monitored.
 * 
 *  The network table contains information about all host that are part of the monitored
 *  table. The description contains the IPv4 and IPv6 address of each host. To protect the
 *  table from address explosion when the application is under attack the table has fixed size.
 *  The table uses lock-free hashing algorithm with linear probing. It has reasonable performance
 *  and scales to multiple threads. The information kept for every host is whether it is
 *  legitimate or suspicious. That is done through special marking. For example an IEEE 802.1Q 
 *  VLAN identifier is only 12-bit value. The rest of the bits are free, so they could be used
 *  for marking. On the other hand, there are not subnets with masks that are just ones or zeros,
 *  so that could also be used for marking. The other type of marking is services associated with
 *  the specified host. That's usually accumulated over time; therefore, it is fine to just set
 *  flags separately.
 * 
 */
class NetworkCache
{
    typedef std::aligned_storage<1, 16>::type StorageType;
    
    uint32                         m_VLANPoolSize,      //!< The size of the VLAN table.
                                   m_HostPoolSize;      //!< The size of each host table.
    std::unique_ptr<StorageType[]> m_MemoryPool;        //!< The memory pool which used for allocating the table.

    uint32                         m_SubnetPoolSize;    //!< The size of each subnet table.
    
    ipv6_int128_t                  m_IPv6MinMask;       //!< The minimum mask used for computing IPv6 subnets.
    ipv6_int128_t                  m_IPv6MaxMask;       //!< The maximum mask which puts upper bound on the size of the subnets.
    uint32                         m_IPv4MinMask;       //!< The minimum mask used for computing IPv4 subnets.
    uint32                         m_IPv4MaxMask;       //!< The maximum mask which puts upper bound on the size of the subnets.
   
    HostDescription<ip6_t>*        m_IPv6Table;         //!< Pointer to all the IPv6 host tables used in this network cache.
    SubnetDescription<ip6_t>*      m_IPv6SubnetTable;   //!< Pointer to all the IPv6 subnet tables used in this network cache.
    HostDescription<ip_t>*         m_IPv4Table;         //!< Pointer to all the IPv4 host tables used in this network cache.
    SubnetDescription<ip_t>*       m_IPv4SubnetTable;   //!< Pointer to all the IPv4 subnet tables used in this network cache.
    VLANEntry*                     m_VLANTable;
   
    std::unordered_map<std::string, ServiceFlags> m_ServiceMap; //!< Map for translating services from string representation to integer.
public:
    /*! \brief Initializes the network cache.
     * 
     *  It initializes the network table out of a manually allocated memory pool, so that everything
     *  is nice and compact and all the entries have proper alignment.
     * 
     *  \param opts     contains all options used by the Quiet Neighborhood plug-in.
     */
    NetworkCache(const QuietNeighborhoodOptions& opts);
    
    //! Destructor.
     ~NetworkCache();

    /*! \brief Reloads the contents of the network caches from input stream.
     * 
     *  It is possible to load the contents split as legitimate and suspicious or merge them as both
     *  legitimate. Have in mind that it could make legitimate some hosts that are not part of your
     *  autoconfiguration set up.
     * 
     *  \param fmt              the format of the persistent storage file.
     *  \param fs_legitimate    the input stream containing information about the legitimate hosts in this network.
     *  \param fs_suspicious    the input stream containing information about the suspicious hosts in this network.
     *  \param merge            indicates whether the suspicious hosts are actually legitimate and should get merged.
     */     
    void reloadCache(CacheFormat fmt, std::istream& fs_legitimate, std::istream& fs_suspicious, bool merge);
    
    /*! \brief Saves the contents of the network cache to persistent storage.
     *
     *  The data gets split depending on its marking. Namely, there are two tables: table of the legitimate hosts and
     *  table of the suspicious hosts.
     * 
     *  There is an option to save the network cache in different file formats, so that it is more
     *  comfortable for the end user. On the other hand, the data could be made available for other
     *  applications in this manner.
     * 
     *  \param fmt              the format that must be used to save the table to persistent storage.
     *  \param fs_legitimate    the output stream to which the legitimate hosts, subnets and VLANs are going to be outputted.
     *  \param fs_suspicious    the output stream to which the suspicious hosts, subnets and VLANs are going to be outputted.
     */    
    void saveCache(CacheFormat fmt, std::ostream& fs_legitimate, std::ostream& fs_suspicious);
     
    /*! \brief Acquires an unique VLAN entry with the proper marking.
     * 
     *  The data is acquired from lock-free structure, so it scales well and you don't need to do any
     *  other optimizations. The marking is dependent on the state passed to this function. If the VLAN
     *  was already inserted in the network table no additional marking gets applied.
     * 
     *  \param _state       the state of the Quiet Neighborhood pipeline.
     *  \param vid          the requested VLAN identifier.
     *  \returns VLAN entry associated with this VLAN identifier. It is used for indexing in the other tables.
     */
    VLANEntry* acquireVLAN(MonitorState _state, vlan32 vid);
    
    /*! \brief Acquires an unique entry for the specified host in the specified VLAN.
     * 
     *  The data is stored in lock-free fashion, so no additional optimizations are required outside of
     *  this function. Have in mind that the host pool should be big enough and there is some performance
     *  penalties when the hash table gets filled up.
     * 
     *  \tparam T       the type of IP address (IPv4 or IPv6).
     *  \param _state   the state of the Quiet Neighborhood pipeline.
     *  \param vlan     the VLAN entry which is used for indexing into the IP address table.
     *  \param _ip      the requested IP address.
     *  \returns Host description associated with this IP address.
     */
    template<class T>
    HostDescription<T>* acquireIP(MonitorState _state, VLANEntry* vlan, const T& _ip);
    
    /*! \brief Acquires an unique entry for the specified host in the specified VLAN which offers a particular
     *         service.
     * 
     *  See NetworkCache::acquireIP for more information about the actual table.
     * 
     *  \remarks There exists one case that does not result in setting up service flag. That's when there
     *           is parallel execution of learning and monitoring phase threads. The result is ambiguous, so
     *           it just reverts the changes. Afterwards, if the activity proceeds, it is going to mark it
     *           as suspicious.
     * 
     *  \tparam T       the type of IP address (IPv4 or IPv6).
     *  \param _state   the state of the Quiet Neighborhood pipeline.
     *  \param vlan     the VLAN entry which is used for indexing into the IP address table.
     *  \param _ip      the requested IP address.
     *  \param service_flags
     */
    template<class T>
    HostDescription<T>* acquireServiceIP(MonitorState _state, VLANEntry* vlan, const T& _ip, size_t service_flags);
    
private:
    /*! \brief The actual implementation of the function for acquiring the VLAN identifier.
     * 
     *  This function should be called with proper marking depending on the state of the Quiet Neighborhood pipeline.
     * 
     *  \param vid      the requested VLAN.
     *  \param new_mask the actual marking used when inserting a new entry.
     *  \returns VLAN entry associated with this VLAN identifier.
     */
    VLANEntry* acquireVLANImpl(vlan32 vid, vlan32 new_mask);
    
    /*! \brief Acquires a unique entry from the network table.
     * 
     *  This function is used for entries that are not marked or for pure information loading.
     * 
     *  \tparam TEntry      the type of the entry.
     *  \param pool_size    how big is the table that is being searched.
     *  \param value        the unique value associated with searched entry.
     *  \returns Unique entry associated with the specified value.
     */   
    template<class TEntry>
    TEntry* acquire(TEntry* _table, size_t pool_size, const typename TEntry::id_type& value);
    
    /*! \brief Performs subnet aggregation based on the passed IP addresses.
     * 
     *  The subnet aggregation is based on address comparison through bitwise operations and some additional bit twiddling
     *  to ensure that it does not aggregate broadcast addresses. See ComputeSubnetMask for more information. The information
     *  is stored in linear table because it is expected that the actual entries are going to be within one cache line, so
     *  it is pointless to do hashing. There are minimum and maximum mask that limit minimum and maximum subnet size.
     * 
     *  \param subnet_table a pointer to the subnet table that is aggregating subnets based on the passed IP addresses.
     *  \param ip           IP address which is going to be aggregated in the subnet returned by this function.
     *  \param mask         mask used for marking the subnet depending on the Quiet Neighborhood pipeline state.
     *  \returns Subnet entry which aggregates the specified IP address.
     */
    template<class T>
    SubnetDescription<T>* subnetAggregate(SubnetDescription<T>* subnet_table, const typename SubnetDescription<T>::id_type& ip, typename SubnetDescription<T>::int_type mask);
    
    /*! \brief Performs subnet aggregation based on the passed IP addresses and reports any new suspicious subnet.
     *  
     *  The actual implementation is NetworkCache::subnetAggregate. This function is just performing checks on the acquired
     *  subnet.
     * 
     *  \param _state       the state of the Quiet Neighborhood pipeline.
     *  \param subnet_table a pointer to the subnet table that is aggregating subnets based on the passed IP addresses.
     *  \param ip           IP address which is going to be aggregated in the subnet returned by this function.
     */
    template<class T>
    void subnetAggregateCheck(MonitorState _state, SubnetDescription<T>* subnet_table, const typename SubnetDescription<T>::id_type& ip);
    
    //! Determines whether an IPv4 mask exceeds the maximum network size.
    FORCE_INLINE bool canAggregate(uint32 subnet_mask) { return (~subnet_mask & m_IPv4MaxMask) == 0; }
    
    //! Determines whether an IPv6 mask exceeds the maximum network size.
    FORCE_INLINE bool canAggregate(ipv6_int128_t subnet_mask) { return (~subnet_mask & m_IPv6MaxMask) == 0; }
    
    //! Initializes an IPv4 subnet mask, only if it is the initial invalid mask.
    FORCE_INLINE void initSubnetMask(std::atomic<uint32>& subnet_mask, uint32 mask)
    {
        uint32 f_wall = 0xFFFFFFFF;
        subnet_mask.compare_exchange_strong(f_wall, m_IPv4MinMask & mask);
    }
    
    //! Initializes an IPv6 subnet mask, only if it is the initial invalid mask.
    FORCE_INLINE void initSubnetMask(ipv6_int128_t& subnet_mask, ipv6_int128_t mask)
    {
        ipv6_int128_t zero = 0;
        __sync_val_compare_and_swap(&subnet_mask, ~zero, m_IPv6MinMask & mask);
    }
    
    //! Returns the minimum IPv6 subnet mask.
    FORCE_INLINE void getMinMask(ipv6_int128_t& min_mask) { min_mask = m_IPv6MinMask; }
    
    //! Returns the minimum IPv4 subnet mask.
    FORCE_INLINE void getMinMask(uint32& min_mask) { min_mask = m_IPv4MinMask; }
    
    //! Gets the entry at the specified offset.
    FORCE_INLINE void getTable(size_t offset, HostDescription<ip_t>*& table) { table = m_IPv4Table + offset*m_HostPoolSize; }
    
    //! Gets the entry at the specified offset.
    FORCE_INLINE void getTable(size_t offset, SubnetDescription<ip_t>*& table) { table = m_IPv4SubnetTable + offset*m_SubnetPoolSize; }
    
    //! Gets the entry at the specified offset.
    FORCE_INLINE void getTable(size_t offset, HostDescription<ip6_t>*& table) { table = m_IPv6Table + offset*m_HostPoolSize; }
    
    //! Gets the entry at the specified offset.
    FORCE_INLINE void getTable(size_t offset, SubnetDescription<ip6_t>*& table) { table = m_IPv6SubnetTable + offset*m_SubnetPoolSize; }
};

#endif // _QN_NETWORK_CACHE_HH_