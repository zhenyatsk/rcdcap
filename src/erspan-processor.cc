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

#include "rcdcap/erspan-processor.hh"
#include "rcdcap/gre-processor.hh"
#include "rcdcap/packet-headers.hh"

#include <boost/scope_exit.hpp>

#include <algorithm>

namespace RCDCap
{
ERSPANProcessor::ERSPANProcessor(boost::asio::io_service& io_service, CommonBuffer& buf, bool vlan_enabled)
    :   DecapsulatingProcessor(io_service, buf),
        m_VLANEnabled(vlan_enabled)
{
}

void ERSPANProcessor::notify(PacketInfo* packet_info, size_t packets)
{
    m_IOService.post(std::bind(&ERSPANProcessor::process, this, packet_info, packets));
}

void ERSPANProcessor::process(PacketInfo* packet_info, size_t packets)
{
    PacketInfo* current_packet = packet_info;
    for(size_t i = 0; i < packets; ++i, current_packet = m_CommonBuffer.next(current_packet))
    {
        this->processImpl(current_packet);
    }
    if(m_Sink)
    	m_Sink->notify(packet_info, packets);
}

void ERSPANProcessor::processImpl(PacketInfo* packet_info)
{
    auto&           pcap_header = packet_info->getPCAPHeader();
    auto*           packet = GetPacket(packet_info);
    auto            caplen = pcap_header.getCapturedLength();
    auto            origlen = pcap_header.getOriginalLength();
    size_t          offset;
    ProtocolType    proto;
    if(!this->getProtocolOffset(packet_info, offset, proto))
        return;
    
    if(proto != ProtocolType::RCDCAP_PROTOCOL_TYPE_GRE ||
       caplen < sizeof(GREHeader) + offset)
        return;
    auto& gre_header = reinterpret_cast<const GREHeader&>(packet[offset]);
    auto gre_proto = gre_header.getProtocolType();
    if(gre_proto != RCDCAP_GRE_ERSPAN)
        return;
    offset += sizeof(GREHeader);
    if(gre_header.isCheksumPresent())
    {
        if(caplen < sizeof(GREChecksumField) + offset)
            return;
        offset += sizeof(GREChecksumField);
    }
    if(gre_header.isSeqNumPresent())
    {
        if(caplen < sizeof(GRESeqNumField) + offset)
            return;
        offset += sizeof(GRESeqNumField);

        if(caplen < sizeof(ERSPANHeader) + offset)
            return;
            
        auto& erspan_header = reinterpret_cast<const ERSPANHeader&>(packet[offset]);
        auto priority = erspan_header.getPriority();
        auto vlan_id = erspan_header.getVLAN();
        offset += sizeof(ERSPANHeader);
        if(m_VLANEnabled)
        {
            std::copy_n(&packet[offset], MACHeader802_1Q::getVLANTagOffset(), packet);
            std::copy(&packet[offset + MACHeader802_1Q::getVLANTagOffset()],
                    &packet[caplen], &packet[MACHeader802_1Q::getVLANTagOffset()+MACHeader802_1Q::getVLANTagSize()]);
            auto& eth_header = *reinterpret_cast<MACHeader802_1Q*>(packet);
            eth_header.setVLANTPID();
            eth_header.setVLANPriority(priority);
            eth_header.setVLANCanonical(false);
            eth_header.setVLANIdentifier(vlan_id);
            offset -= MACHeader802_1Q::getVLANTagSize();
        }
        else
            std::copy(&packet[offset], &packet[caplen], packet);
    }
    else // Juniper - Thanks to Walter Schober
        std::copy(&packet[offset], &packet[caplen], packet);
    pcap_header.setCapturedLength(caplen - offset);
    pcap_header.setOriginalLength(origlen - offset);
}
}