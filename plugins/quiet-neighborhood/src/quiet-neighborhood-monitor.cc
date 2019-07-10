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

#include "quiet-neighborhood-monitor.hh"

#include "rcdcap/packet-headers.hh"
#include "rcdcap/exception.hh"

#include <syslog.h>

QuietNeighborhoodMonitor::QuietNeighborhoodMonitor(
    boost::asio::io_service& io_service,
    RCDCap::DataSource& src,
    const QuietNeighborhoodOptions& opts)
    :   m_IOService(io_service),
        m_DataSource(src),
        m_State(MonitorState::LEARNING_PHASE),
        m_DHCPServerPort(opts.DHCPServerPort),
        m_DHCPClientPort(opts.DHCPClientPort),
        m_DHCPv6ServerPort(opts.DHCPv6ServerPort),
        m_DHCPv6ClientPort(opts.DHCPv6ClientPort),
        m_StateSwitchTimer(io_service),
        m_NetworkCacheFormat(opts.networkCacheFormat),
        m_CacheFile(opts.networkCache),
        m_SuspiciousHostsCacheFile(opts.networkViolationCache),
        m_NetworkCache(opts)
{
    // Opens a new connection to syslog.
    openlog("rcdcap", LOG_PID, LOG_LOCAL0);
    
    // The application always starts in learning phase when there is not a valid network cache.
    // Otherwise, it is possible to force it to run in learning phase instead of monitoring phase.
    // The network cache can be optionally ignored.
    std::fstream fs_legitimate(m_CacheFile.c_str(), std::ios::in),
                 fs_suspicious(m_SuspiciousHostsCacheFile.c_str(), std::ios::in);
    if(fs_legitimate.is_open() && (opts.flags & IGNORE_CACHE) == 0)
    {
        m_NetworkCache.reloadCache(m_NetworkCacheFormat, fs_legitimate, fs_suspicious, (opts.flags & MERGE_VIOLATING) != 0);
        m_State = MonitorState::MONITORING_PHASE;
    }
        
    if((opts.flags & FORCE_LEARNING_PHASE) != 0 || m_State == MonitorState::LEARNING_PHASE)
    {
        m_StateSwitchTimer.expires_from_now(boost::posix_time::seconds(opts.learningPhase));
        m_StateSwitchTimer.async_wait(std::bind(&QuietNeighborhoodMonitor::transitionToAlertState, this));
    }
}
    
QuietNeighborhoodMonitor::~QuietNeighborhoodMonitor()
{
    try
    {
        // TODO: That's just asking for bugs. Find better solution.
        std::fstream fs_legitimate(m_CacheFile.c_str(), std::ios::out),
                    fs_suspicious(m_SuspiciousHostsCacheFile.c_str(), std::ios::out);
        m_NetworkCache.saveCache(m_NetworkCacheFormat, fs_legitimate, fs_suspicious);
    }
    catch(...)
    {
    }
}

void QuietNeighborhoodMonitor::transitionToAlertState()
{
    // Not a huge deal if some packets slip up immediately after
    // the timer runs out.
    m_State = MonitorState::MONITORING_PHASE;
    // We save it immediately because otherwise the application may crash and we
    // might be left without any data.
    std::fstream fs_legitimate(m_CacheFile.c_str(), std::ios::out),
                 fs_suspicious(m_SuspiciousHostsCacheFile.c_str(), std::ios::out);
    if(!fs_legitimate.is_open())
        THROW_EXCEPTION("Could not save cache file: " + m_CacheFile);
    m_NetworkCache.saveCache(m_NetworkCacheFormat, fs_legitimate, fs_suspicious);
}


void QuietNeighborhoodMonitor::notify(RCDCap::PacketInfo* packet_info, size_t packets)
{
    // It schedules a new task for processing the contents of the packet burst.
    m_IOService.post(std::bind(&QuietNeighborhoodMonitor::process, this, packet_info, packets));
}

void QuietNeighborhoodMonitor::processImpl(RCDCap::PacketInfo* packet_info)
{
    size_t          offset = 0;
    
    auto&           pcap_header = packet_info->getPCAPHeader();
    auto*           packet = GetPacket(packet_info);
    auto            caplen = pcap_header.getCapturedLength();
    
    // It is impossible to process. Don't even bother.
    if(caplen < sizeof(RCDCap::MACHeader))
        return;
    size_t vid = UnassignedVLAN;
    auto* eth_packet = reinterpret_cast<const RCDCap::MACHeader*>(packet + offset);
    auto eth_type = eth_packet->getEtherType();
    if(eth_type == RCDCap::EtherType::RCDCAP_ETHER_TYPE_802_1Q)
    {
        if(caplen < sizeof(RCDCap::MACHeader802_1Q))
            return;
        auto* eth802_1Q_packet = reinterpret_cast<const RCDCap::MACHeader802_1Q*>(packet + offset);
        eth_type = eth802_1Q_packet->getEtherType();
        vid = eth802_1Q_packet->getVLANIdentifier();
        offset += sizeof(RCDCap::MACHeader802_1Q);
    }
    else
        offset += sizeof(RCDCap::MACHeader);
    
    switch(eth_type)
    {
    // IPv4 hosts are usually autoconfigured by using DHCP. So that's the main protocol that
    // is treated separately in this case.
    case RCDCap::EtherType::RCDCAP_ETHER_TYPE_IPv4:
    {
        if(caplen < sizeof(RCDCap::IPv4Header) + offset)
            return;
        auto* ipv4_header = reinterpret_cast<RCDCap::IPv4Header*>(packet + offset);
        offset += sizeof(RCDCap::IPv4Header);
        if(ipv4_header->getProtocol() != RCDCap::ProtocolType::RCDCAP_PROTOCOL_TYPE_UDP ||
           caplen < sizeof(RCDCap::UDPHeader) + offset)
            return;
        auto* udp_header = reinterpret_cast<RCDCap::UDPHeader*>(packet + offset);
        processDHCP(vid, ipv4_header, udp_header, caplen - sizeof(RCDCap::UDPHeader) - offset);
    } break;
    case RCDCap::EtherType::RCDCAP_ETHER_TYPE_IPv6:
    {
        if(caplen < sizeof(RCDCap::IPv6Header) + offset)
            return;
        auto* ipv6_header = reinterpret_cast<RCDCap::IPv6Header*>(packet + offset);
        offset += sizeof(RCDCap::IPv6Header);
        auto proto_type = ipv6_header->getNextHeader();
        // TODO: Extension header support
        switch(proto_type)
        {
        case RCDCap::ProtocolType::RCDCAP_PROTOCOL_TYPE_IPv6_ICMP:
        {
            if(caplen < sizeof(RCDCap::ICMPv6Header) + offset)
                return;
            auto* icmpv6_header = reinterpret_cast<RCDCap::ICMPv6Header*>(packet + offset);
            offset += sizeof(RCDCap::ICMPv6Header);
            processNDP(vid, ipv6_header, icmpv6_header, caplen - offset);
        } break;
        case RCDCap::ProtocolType::RCDCAP_PROTOCOL_TYPE_UDP:
        {
            if(caplen < sizeof(RCDCap::UDPHeader) + offset)
                break;
            auto* udp_header = reinterpret_cast<RCDCap::UDPHeader*>(packet + offset);
            offset += sizeof(RCDCap::UDPHeader);
            processDHCPv6(vid, ipv6_header, udp_header, caplen - offset);
        } break;
        default: break;
        }
    } break;
    case RCDCap::EtherType::RCDCAP_ETHER_TYPE_ARP:
    {
        if(caplen < sizeof(RCDCap::ARPHeader) + offset)
            return;
        auto* arp_header = reinterpret_cast<RCDCap::ARPHeader*>(packet + offset);
        processARP(vid, arp_header, caplen - offset - sizeof(RCDCap::ARPHeader));
    } break;
    default: break; // Not exactly the target of this plug-in. However,
                    // MPLS support would be nice for some relay DHCP servers or something.
    }
}

void QuietNeighborhoodMonitor::process(RCDCap::PacketInfo* packet_info, size_t packets)
{
    // We don't deal with non-Ethernet networks.
    if(packet_info->getLinkType() != DLT_EN10MB)
        return;

    auto* current_packet = packet_info;
    auto& buffer = m_DataSource.getBuffer();
    for(size_t i = 0; i < packets; ++i, current_packet = buffer.next(current_packet))
        this->processImpl(current_packet);
    if(m_Sink)
        m_Sink->notify(packet_info, packets);
}



