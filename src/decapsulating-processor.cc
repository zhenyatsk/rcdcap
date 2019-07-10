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

#include "rcdcap/decapsulating-processor.hh"
#include "rcdcap/packet-headers.hh"

namespace RCDCap
{
DecapsulatingProcessor::DecapsulatingProcessor(boost::asio::io_service& io_service, CommonBuffer& buf)
    :   m_IOService(io_service),
        m_CommonBuffer(buf)
{
}

bool DecapsulatingProcessor::getProtocolOffset(PacketInfo* packet_info, size_t& offset, ProtocolType& proto)
{
    auto&   pcap_header = packet_info->getPCAPHeader();
    auto*   packet = GetPacket(packet_info);
    auto    caplen = pcap_header.getCapturedLength();
    offset = 0;
    
    EtherType eth_type;
    switch(packet_info->getLinkType())
    {
    case DLT_EN10MB:
    {
        if(caplen < sizeof(MACHeader))
            return false;
        auto& eth_packet = reinterpret_cast<const MACHeader&>(packet[offset]);
        eth_type = eth_packet.getEtherType();
        if(eth_type == EtherType::RCDCAP_ETHER_TYPE_802_1Q)
        {
            if(caplen < sizeof(MACHeader802_1Q))
                return false;
            auto& eth802_1Q_packet = reinterpret_cast<const MACHeader802_1Q&>(packet[offset]);
            eth_type = eth802_1Q_packet.getEtherType();
            offset += sizeof(MACHeader802_1Q);
        }
        else
            offset += sizeof(MACHeader);
    }   break;
    default:
        return false;
    }
    
    switch(eth_type)
    {
    case EtherType::RCDCAP_ETHER_TYPE_IPv4:
    {
        if(caplen < sizeof(IPv4Header) + offset)
            return false;
        auto& ip_packet = reinterpret_cast<const IPv4Header&>(packet[offset]);
        offset += ip_packet.getIHL()*4;
        if(caplen < offset)
            return false;
        proto = ip_packet.getProtocol();
    } break;
    case EtherType::RCDCAP_ETHER_TYPE_IPv6:
    {
        if(caplen < sizeof(IPv6Header) + offset)
            return false;
        auto& ip_packet = reinterpret_cast<const IPv6Header&>(packet[offset]);
        offset += sizeof(IPv6Header);
        proto = ip_packet.getNextHeader();
        // TODO: extension headers
    } break;
    default:
        return false;
    }
    
    return true;
}
}