/*   RCDCap
 *   Copyright (C) 2012  Zdravko Velinov
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

#include "rcdcap/packet-headers.hh"
#include "rcdcap/byte-order.hh"

#include <boost/regex.hpp>

#include <cstddef>
#include <sstream>

namespace RCDCap
{
MACHeader::MACHeader()
{
    static_assert(sizeof(MACHeader) == 14, "invalid header size");
}
    
mac_t MACHeader::getDMacAddress() const
{
    return m_DstMAC;
}

mac_t MACHeader::getSMacAddress() const
{
    return m_SrcMAC;
}

EtherType MACHeader::getEtherType() const
{
    return m_EtherType;
}

void MACHeader::setDMacAddress(const mac_t& mac)
{
    m_DstMAC = mac;
}

void MACHeader::setSMacAddress(const mac_t& mac)
{
    m_SrcMAC = mac;
}

void MACHeader::setEtherType(EtherType eth_type)
{
    m_EtherType = eth_type;
}

MACHeader802_1Q::MACHeader802_1Q() { static_assert(sizeof(MACHeader802_1Q) == 18, "invalid header size"); }
    
uint8 MACHeader802_1Q::getVLANPriority() const
{
    return static_cast<uint8>(m_VLANTag.get<0>());
}

bool MACHeader802_1Q::getVLANCanonical() const
{
    return static_cast<bool>(m_VLANTag.get<1>());
}

uint16 MACHeader802_1Q::getVLANIdentifier() const
{
    return m_VLANTag.get<2>();
}

mac_t MACHeader802_1Q::getDMacAddress() const
{
    return m_DstMAC;
}
mac_t MACHeader802_1Q::getSMacAddress() const
{
    return m_SrcMAC;
}

EtherType MACHeader802_1Q::getEtherType() const
{
    return m_EtherType;
}
    
void MACHeader802_1Q::setVLANTPID()
{
    m_TPID = EtherType::RCDCAP_ETHER_TYPE_802_1Q;
}

void MACHeader802_1Q::setVLANPriority(uint8 pcp)
{
    m_VLANTag.set<0>(static_cast<uint16>(pcp));
}

void MACHeader802_1Q::setVLANCanonical(bool cfi)
{
    m_VLANTag.set<1>(static_cast<uint16>(cfi));
}

void MACHeader802_1Q::setVLANIdentifier(uint16 vid)
{
    m_VLANTag.set<2>(vid);
}

void MACHeader802_1Q::setDMacAddress(const mac_t& mac)
{
    m_DstMAC = mac;
}

void MACHeader802_1Q::setSMacAddress(const mac_t& mac)
{
    m_SrcMAC = mac;
}

void MACHeader802_1Q::setEtherType(EtherType eth_type)
{
    m_EtherType = eth_type;
}

IPv4Header::IPv4Header() { static_assert(sizeof(IPv4Header) == 20, "invalid header size"); }
    
uint8 IPv4Header::getVersion() const
{
    return m_IHL_Version.get<0>();
}

uint8 IPv4Header::getIHL() const
{
    return m_IHL_Version.get<1>();
}

uint16 IPv4Header::getTotalLength() const
{
    return m_TotalLength;
}

uint16 IPv4Header::getIdentification() const
{
    return m_Identification;
}

uint16 IPv4Header::getFragment() const
{
    return m_Flags_Fragment.get<1>();
}

uint8 IPv4Header::getFlags() const
{
    return static_cast<uint8>(m_Flags_Fragment.get<0>());
}

uint8 IPv4Header::getTTL() const
{
    return m_TTL;
}

ProtocolType IPv4Header::getProtocol() const
{
    return m_Protocol;
}

uint16 IPv4Header::getChecksum() const
{
    return m_Checksum;
}

ip_t IPv4Header::getSourceIP() const
{
    return m_SrcIP;
}

ip_t IPv4Header::getDestinationIP() const
{
    return m_DstIP;
}

void IPv4Header::setVersion(uint8 ver)
{
    m_IHL_Version.set<0>(ver);
}

void IPv4Header::setIHL(uint8 ihl)
{
    m_IHL_Version.set<1>(ihl);
}

void IPv4Header::setTotalLength(uint16 len)
{
    m_TotalLength = len;
}

void IPv4Header::setIdentification(uint16 id)
{
    m_Identification = id;
}

void IPv4Header::setFragment(uint16 fragment)
{
    m_Flags_Fragment.set<1>(fragment);
}

void IPv4Header::setFlags(uint8 flags)
{
    m_Flags_Fragment.set<0>(flags);
}

void IPv4Header::setTTL(uint8 ttl)
{
    m_TTL = ttl;
}

void IPv4Header::setProtocol(ProtocolType protocol_type)
{
    m_Protocol = protocol_type;
}

void IPv4Header::setChecksum(uint16 checksum)
{
    m_Checksum = checksum;
}

void IPv4Header::setSourceIP(const ip_t& src_ip)
{
    m_SrcIP = src_ip;
}

void IPv4Header::setDestinationIP(const ip_t& dst_ip)
{
    m_DstIP = dst_ip;
}

IPv6Header::IPv6Header()
{
    static_assert(sizeof(IPv6Header) == 40, "invalid header size");
}
    
uint32 IPv6Header::getVersion() const
{
    return m_Ver_TC_FL.get<0>();
}

uint32 IPv6Header::getTrafficClass() const
{
    return m_Ver_TC_FL.get<1>();
}

uint32 IPv6Header::getFlowLabel() const
{
    return m_Ver_TC_FL.get<2>();
}

uint16 IPv6Header::getPayloadLength() const
{
    return m_Length;
}

ProtocolType IPv6Header::getNextHeader() const
{
    return m_NextHeader;
}

uint8 IPv6Header::getHopLimit() const
{
    return m_HopLimit;
}

ip6_t IPv6Header::getSourceIP() const
{
    return m_SrcIP;
}

ip6_t IPv6Header::getDestinationIP() const
{
    return m_DstIP;
}

void IPv6Header::setVersion(uint32 ver)
{
    m_Ver_TC_FL.set<0>(ver);
}

void IPv6Header::setTrafficClass(uint32 traffic_class)
{
    m_Ver_TC_FL.set<1>(traffic_class);
}

void IPv6Header::setFlowLabel(uint32 flow_label)
{
    m_Ver_TC_FL.set<2>(flow_label);
}

void IPv6Header::setPayloadLength(uint16 payload_length)
{
    m_Length = payload_length;
}

void IPv6Header::setNextHeader(ProtocolType protocol_type)
{
    m_NextHeader = protocol_type;
}

void IPv6Header::setHopLimit(uint8 hop_limit)
{
    m_HopLimit = hop_limit;
}

void IPv6Header::setSourceIP(const ip6_t& src_ip)
{
    m_SrcIP = src_ip;
}

void IPv6Header::setDestinationIP(const ip6_t& dst_ip)
{
    m_DstIP = dst_ip;
}

uint8 RouterAdvertisementHeader::getCurHopLimit() const
{
    return m_CurHopLimit;
}

bool RouterAdvertisementHeader::isManagedEnabled() const
{
    return m_Flags.get<BF_M_FLAG>();
}

bool RouterAdvertisementHeader::isOtherEnabled() const
{
    return m_Flags.get<BF_O_FLAG>();
}

uint16 RouterAdvertisementHeader::getRouterLifetime() const
{
    return m_RouterLifetime;
}

uint32 RouterAdvertisementHeader::getRechableTime() const
{
    return m_RechableTime;
}

uint32 RouterAdvertisementHeader::getRetransTime() const
{
    return m_RetransTime;
}

void RouterAdvertisementHeader::setCurHopLimit(uint8 hop_limit)
{
    m_CurHopLimit = hop_limit;
}

void RouterAdvertisementHeader::setManaged(bool is_enabled)
{
    m_Flags.set<BF_M_FLAG>(is_enabled);
}

void RouterAdvertisementHeader::setOther(bool is_enabled)
{
    m_Flags.set<BF_O_FLAG>(is_enabled);
}

void RouterAdvertisementHeader::setRouterLifetime(uint16 lifetime)
{
    m_RouterLifetime = lifetime;
}

void RouterAdvertisementHeader::setRechableTime(uint32 reachable)
{
    m_RechableTime = reachable;
}

void RouterAdvertisementHeader::setRetransTime(uint32 retrans)
{
    m_RetransTime = retrans;
}


uint16 UDPHeader::getSourcePort() const
{
    return m_SrcPort;
}

uint16 UDPHeader::getDestinationPort() const
{
    return m_DstPort;
}

uint16 UDPHeader::getLength() const
{
    return m_Length;
}

uint16 UDPHeader::getChecksum() const
{
    return m_Checksum;
}

void UDPHeader::setSourcePort(uint16 src_port)
{
    m_SrcPort = src_port;
}

void UDPHeader::setDestinationPort(uint16 dst_port)
{
    m_DstPort = dst_port;
}

void UDPHeader::setLength(uint16 len)
{
    m_Length = len;
}

void UDPHeader::setChecksum(uint16 checksum)
{
    m_Checksum = checksum;
}

ARPHardwareType ARPHeader::getHardwareType() const
{
    return m_HardwareType;
}

EtherType ARPHeader::getProtocolType() const
{
    return m_ProtocolType;
}

uint8 ARPHeader::getHardwareAddressLength() const
{
    return m_HardwareAddressLength;
}

uint8 ARPHeader::getProtocolAddressLength() const
{
    return m_ProtocolAddressLength;
}

ARPOpcode ARPHeader::getOpcode() const
{
    return m_Opcode;
}

void ARPHeader::setHardwareType(ARPHardwareType hw_type)
{
    m_HardwareType = hw_type;
}

void ARPHeader::setProtocolType(EtherType proto_type)
{
    m_ProtocolType = proto_type;
}

void ARPHeader::setHardwareAddressLength(uint8 hw_addr)
{
    m_HardwareAddressLength = hw_addr;
}

void ARPHeader::setProtocolAddressLength(uint8 proto_addr)
{
    m_ProtocolAddressLength = proto_addr;
}

void ARPHeader::setOpcode(ARPOpcode opcode)
{
    m_Opcode = opcode;
}

mac_t ARPIPv4ReplyFields::getSourceHardwareAddress() const
{
    return m_SrcMAC;
}

ip_t ARPIPv4ReplyFields::getSourceProtocolAddress() const
{
    return m_SrcIP;
}

mac_t ARPIPv4ReplyFields::getDestinationHardwareAddress() const
{
    return m_DstMAC;
}

ip_t ARPIPv4ReplyFields::getDestinationProtocolAddress() const
{
    return m_DstIP;
}

void ARPIPv4ReplyFields::setSourceHardwareAddress(const mac_t& src)
{
    m_SrcMAC = src;
}

void ARPIPv4ReplyFields::setSourceProtocolAddress(const ip_t& src)
{
    m_SrcIP = src;
}

void ARPIPv4ReplyFields::setDestinationHardwareAddress(const mac_t& dst)
{
    m_DstMAC = dst;
}

void ARPIPv4ReplyFields::setDestinationProtocolAddress(const ip_t& dst)
{
    m_DstIP = dst;
}

mac_t ARPIPv4RequestFields::getSourceHardwareAddress() const
{
    return m_SrcMAC;
}

ip_t ARPIPv4RequestFields::getSourceProtocolAddress() const
{
    return m_SrcIP;
}

void ARPIPv4RequestFields::setSourceHardwareAddress(const mac_t& src)
{
    m_SrcMAC = src;
}

void ARPIPv4RequestFields::setSourceProtocolAddress(const ip_t& src)
{
    m_SrcIP = src;
}

ICMPv6MessageType ICMPv6Header::getType() const
{
    return m_Type;
}

uint8 ICMPv6Header::getCode() const
{
    return m_Code;
}

uint16 ICMPv6Header::getChecksum() const
{
    return m_Checksum;
}
    
void ICMPv6Header::setType(ICMPv6MessageType _type)
{
    m_Type = _type;
}

void ICMPv6Header::setCode(uint8 _code)
{
    m_Code = _code;
}

void ICMPv6Header::setChecksum(uint16 _checksum)
{
    m_Checksum = _checksum;
}

bool NeighborAdvertisementHeader::getRouterFlag() const
{
    return m_RSO.get<ROUTER_FLAG>();
}

bool NeighborAdvertisementHeader::getSolicitedFlag() const
{
    return m_RSO.get<SOLICITED_FLAG>();
}

bool NeighborAdvertisementHeader::getOverrideFlag() const
{
    return m_RSO.get<OVERRIDE_FLAG>();
}

ip6_t NeighborAdvertisementHeader::getTargetAddress() const
{
    return m_TargetAddress;
}

void NeighborAdvertisementHeader::setRouterFlag(bool flag)
{
    m_RSO.set<ROUTER_FLAG>(flag);
}

void NeighborAdvertisementHeader::setSolicitedFlag(bool flag)
{
    m_RSO.set<SOLICITED_FLAG>(flag);
}

void NeighborAdvertisementHeader::setOverrideFlag(bool flag)
{
    m_RSO.set<OVERRIDE_FLAG>(flag);
}

void NeighborAdvertisementHeader::setTargetAddress(const ip6_t& _ip)
{
    m_TargetAddress = _ip;
}

bool IsMulticast(const ip_t& address)
{
    return 224 <= address[0] && address[0] <= 239;
}

bool IsBroadcast(const ip_t& address)
{
    return (address[0] == 0 && address[1] == 0 && address[2] == 0 && address[3] == 0) ||
           (address[0] == 255 && address[1] == 255 && address[2] == 255 && address[3] == 255);
}

bool IsMulticast(const ip6_t& address)
{
    return (address[0] & 0xFF00) == 0xFF00;
}

bool IsBroadcast(const ip6_t& address)
{
    return address[0] == 0 && address[1] == 0 && address[2] == 0 && address[3] == 0 &&
           address[4] == 0 && address[5] == 0 && address[6] == 0 && address[7] == 0;
}
}

// HACK ! HACK ! HACK ! HACK ! HACK ! HACK ! HACK ! HACK !
namespace std
{
std::ostream& operator<<(std::ostream& o, const RCDCap::ip_t& ip)
{
    o << std::dec << (short)ip[0] << "." << (short)ip[1] << "." << (short)ip[2] << "." << (short)ip[3];
    return o;
}

std::ostream& operator<<(std::ostream& o, const RCDCap::ip6_t& ip)
{
    size_t semicolon = 0;
    o << std::uppercase << std::hex;
    if(ip[0])
        o << ip[0];
    o << ":", ++semicolon;
    if(ip[1])
        o << ip[1], semicolon = 0;
    o << ":", ++semicolon;
    if(ip[2])
        o << ip[2], semicolon = 0;
    if(semicolon < 2)
        o << ":", ++semicolon;
    if(ip[3])
        o << ip[3], semicolon = 0;
    if(semicolon < 2)
        o << ":", ++semicolon;
    if(ip[4])
        o << ip[4], semicolon = 0;
    if(semicolon < 2)
        o << ":", ++semicolon;
    if(ip[5])
        o << ip[5], semicolon = 0;
    if(semicolon < 2)
        o << ":", ++semicolon;
    if(ip[6])
        o << ip[6], semicolon = 0;
    if(semicolon < 2)
        o << ":", ++semicolon;
    if(ip[7])
        o << ip[7], semicolon = 0;
    return o;
}

std::ostream& operator<<(std::ostream& o, const RCDCap::mac_t& mac)
{
    o << std::uppercase << std::hex
      << std::setfill('0')
      << std::setw(2) << (short)mac[0] << ":"
      << std::setw(2) << (short)mac[1] << ":"
      << std::setw(2) << (short)mac[2] << ":"
      << std::setw(2) << (short)mac[3] << ":"
      << std::setw(2) << (short)mac[4] << ":"
      << std::setw(2) << (short)mac[5];
    return o;
}

// The performance of these functions is irrelevant because they are
// used when initializing the application.
std::istream& operator>>(std::istream& in, RCDCap::ip_t& ip)
{
    boost::regex rx("([0-9]+)\\.([0-9]+)\\.([0-9]+)\\.([0-9]+)");
    boost::match_results<std::string::iterator> mr;
    std::string str(std::istreambuf_iterator<char>(in),
                    (std::istreambuf_iterator<char>()));
    auto ret = boost::regex_match(str.begin(), str.end(),
                                  mr, rx, boost::regex_constants::match_default);
    if(!ret)
    {
        in.setstate(std::ios::failbit);
        return in;
    }
    
    size_t idx = 0, num;

    for(auto i = mr.begin()+1, iend = mr.end(); i != iend; ++i)
    {
        string str(i->first, i->second);
        std::stringstream ss;
        ss << str;
        ss >> num;
        if(!ss || num > 255)
            in.setstate(std::ios::failbit);
        ip[idx++] = static_cast<RCDCap::uint8>(num);
    }
    return in;
}

std::istream& operator>>(std::istream& in, RCDCap::ip6_t& ip)
{
    size_t idx = 0;
    char current = '\0', prev = '\0';
    constexpr size_t ip6_end = std::tuple_size<RCDCap::ip6_t>::value;
    size_t split = ip6_end, num = 0;
    
    // Basically, we parse everything sequentially until we reach
    // a split, i.e. double semicolon. Then we mark it and proceed.
    // There could not be more than a single split because it is
    // ambiguous.
    for(; current = in.get(), in.good(); prev = current)
    {
        if(isalnum(current))
        {
            size_t cur_num;
            if('0' <= current && current <= '9')
                cur_num = current - '0';
            else if('a' <= current && current <= 'f')
                cur_num = current - 'a' + 10;
            else if('A' <= current && current <= 'F')
                cur_num = current - 'A' + 10;
            else
                assert(false);
            
            num = num*0x10 + cur_num;
            if(num > 0xFFFF)
            {
                in.setstate(std::ios::failbit);
                return in;
            }
        }
        else if(current == ':')
        {
            if(idx >= 8)
            {
                in.setstate(std::ios::failbit);
                return in;
            }
            if(prev == ':')
            {
                if(split != ip6_end)
                {
                    in.setstate(std::ios::failbit);
                    return in;
                }
                split = idx;
            }
            else
            {
                ip[idx++] = num;
                num = 0;
            }
        }
        else
        {
            in.setstate(std::ios::failbit);
            return in;
        }
    }
    if(idx != ip6_end - 1 && split == ip6_end)
    {
        in.setstate(std::ios::failbit);
        return in;
    }
    ip[idx++] = num;
    if(split != ip6_end)
    {
        std::copy(ip.begin() + split, ip.begin() + idx, ip.end() - (idx - split));
        std::fill(ip.begin() + split, ip.end() - (idx - split), 0);
    }
    in.clear(std::ios::goodbit);
    
    return in;
}

std::istream& operator>>(std::istream& in, RCDCap::mac_t& mac)
{
    boost::regex rx("([0-9a-fA-F][0-9a-fA-F]):"
                    "([0-9a-fA-F][0-9a-fA-F]):"
                    "([0-9a-fA-F][0-9a-fA-F]):"
                    "([0-9a-fA-F][0-9a-fA-F]):"
                    "([0-9a-fA-F][0-9a-fA-F]):"
                    "([0-9a-fA-F][0-9a-fA-F])");
    boost::match_results<std::string::iterator> mr;
    std::string str(std::istreambuf_iterator<char>(in),
                    (std::istreambuf_iterator<char>()));
    boost::regex_match(str.begin(), str.end(),
                       mr, rx, boost::regex_constants::match_default);
    size_t idx = 0, num;
    for(auto i = mr.begin()+1, iend = mr.end(); i != iend; ++i)
    {
        string str(i->first, i->second);
        std::stringstream ss;
        ss << str;
        ss >> std::hex >> num;
        if(!ss || num > 255)
            in.setstate(std::ios::failbit);
        mac[idx++] = static_cast<RCDCap::uint8>(num);
    }
    return in;
}
// HACK ! HACK ! HACK ! HACK ! HACK ! HACK ! HACK ! HACK !
}