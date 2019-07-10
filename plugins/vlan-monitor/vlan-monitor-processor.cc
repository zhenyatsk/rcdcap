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

#include "vlan-monitor-processor.hh"

#include <boost/make_shared.hpp>

#include <syslog.h>

#include <sstream>

// Defines all functions required for interfacing with RCDCap.
RCDCAP_PLUGIN(VLANMonitorPlugin)

VLANMonitorPlugin::VLANMonitorPlugin()
    :   m_IOService(0)
{
}

VLANMonitorPlugin::~VLANMonitorPlugin()
{
}

void VLANMonitorPlugin::init(boost::asio::io_service& io_service,
                             popt::options_description& opts)
{
    // Saves a reference to the Boost ASIO I/O Service, which it later passes
    // to the plug-in processor.
    m_IOService = &io_service;
    // Adds new command line options to RCDCap.
    opts.add_options()
        ("alert-untagged", "alert about untagged Ethernet frames")
        ("permitted-vlans",
            popt::value<std::vector<unsigned>>(&m_PermittedVLANs)->multitoken(),
            "set the VLAN identifiers which are permitted to be "
            "received by the monitored network node")
    ;
}

ProcessorPtr VLANMonitorPlugin::hasProcessor(DataSource& src,
                                             const popt::variables_map& vm)
{
    // Initializes a new plug-in processor only if --alert-untagged,
    // --permitted-vlans or both are specified.
    assert(m_IOService);
    auto auc = vm.count("alert-untagged");
    bool enable_untagged = !auc;
    auto pvlanc = vm.count("permitted-vlans");
    if(auc || pvlanc)
        return boost::make_shared<VLANMonitor>(*m_IOService,
                                             src, m_PermittedVLANs,
                                             enable_untagged);
    return ProcessorPtr();
}

VLANMonitor::VLANMonitor(boost::asio::io_service& io_service,
                         DataSource& src, std::vector<unsigned> vlans,
                         bool enable_untagged)
    :   m_IOService(io_service),
        m_DataSource(src),
        m_PermittedVLANs(std::move(vlans)),
        m_UntaggedEnabled(enable_untagged) 
{
    // Opens a new connection to syslog.
    openlog("rcdcap", LOG_PID, LOG_LOCAL0);
}

VLANMonitor::~VLANMonitor()
{
    // Closes the connection to syslog.
    closelog();
}

void VLANMonitor::notify(PacketInfo* packet_info, size_t packets)
{
    // Enqueues a new analysis task.
    m_IOService.post(std::bind(&VLANMonitor::analyze, this, packet_info, packets));
}

void VLANMonitor::analyze(PacketInfo* packet_info, size_t packets)
{
    PacketInfo* current_packet = packet_info;
    auto& buffer = m_DataSource.getBuffer();
    for(size_t i = 0; i < packets; ++i, current_packet = buffer.next(current_packet))
        this->analyzeImpl(current_packet);
	if(m_Sink)
    	m_Sink->notify(packet_info, packets);
}

void VLANMonitor::analyzeImpl(PacketInfo* packet_info)
{
    // The processor currently supports only Ethernet.
    switch(m_DataSource.getLinkType())
    {
    case DLT_EN10MB:
    {
        // The offset used for dissecting the headers.
        size_t            offset = 0;
        // A pointer to the packet contents.
        auto*             packet = GetPacket(packet_info);
        // A reference to the PCAP header.
        auto&             pcap_header = packet_info->getPCAPHeader();
        // How many bytes were captured from the packet.
        auto              caplen = pcap_header.getCapturedLength();
        // Sanity check.
        if(caplen < sizeof(MACHeader))
            return;
        // Casts the beginning of the packet to an Ethernet header.
        auto&             eth_header = reinterpret_cast<MACHeader&>(*packet);
        // Extracts the source and destination MAC addresses.
        auto              dmac = eth_header.getDMacAddress(),
                          smac = eth_header.getSMacAddress();
        // Extracts the protocol type.
        EtherType         eth_type = eth_header.getEtherType();

        // This string stream may contain the report; if that is the case, it
        // gets printed to syslog.
        std::stringstream ss;
        // Checks whether the Ethernet frame is actually an IEEE 802.1Q frame.
        if(eth_type ==
            RCDCap::EtherType::RCDCAP_ETHER_TYPE_802_1Q)
        {
            // Sanity check.
            if(caplen < sizeof(MACHeader802_1Q))
                return;
            // Recasts the Ethernet header to IEEE 802.1Q header.
            auto& vlan_header = reinterpret_cast<MACHeader802_1Q&>(eth_header);
            // Extracts the VLAN identifier.
            auto vid = static_cast<size_t>(vlan_header.getVLANIdentifier());
            // Extracts the Ethernet type inside the IEEE 802.1Q header.
            eth_type = vlan_header.getEtherType();
            // Finds whether the VLAN identifier is in the list of the permitted.
            // ones.
            auto i = std::find(m_PermittedVLANs.begin(),
                               m_PermittedVLANs.end(), vid);
            // Writes an report, if the VLAN identifier is not part of the
            // list
            if(i == m_PermittedVLANs.end())
            {
                ss << "arp-monitor: "
                      "a packet has been received from unknown VLAN "
                   << vid << ": "
                   << "Source MAC address: "
                   << smac
                   << "; Destination MAC address: "
                   << dmac;
            }
            // Moves the offset past the IEEE 802.1Q header.
            offset = sizeof(MACHeader802_1Q);
        }
        else
        {
            // Writes an report, if untagged Ethernet frames are forbidden.
            if(!m_UntaggedEnabled)
            {
                ss << "arp-monitor: "
                      "untagged Ethernet frame detected: "
                      "Source MAC address: " << smac
                   << "; Destination MAC address: " << dmac;
            }
            // Moves the offset past the Ethernet header.
            offset = sizeof(MACHeader);
        }
        // Checks whether it is an ARP packet and also performs a sanity check.
        if(eth_type == EtherType::RCDCAP_ETHER_TYPE_ARP &&
           caplen >= sizeof(ARPHeader) + offset)
        {
            // Casts the contents of the packet at the offset to an ARP header.
            auto& arp_header = reinterpret_cast<ARPHeader&>(packet[offset]);
            // Extracts the protocol and hardware address length.
            auto protolen = arp_header.getProtocolAddressLength(),
                 hwlen = arp_header.getHardwareAddressLength();
            // Currently, it supports only IPv4 and Ethernet.
            if(arp_header.getHardwareType() ==
                   ARPHardwareType::RCDCAP_ARP_HW_Ethernet &&
               hwlen == sizeof(mac_t) &&
               arp_header.getProtocolType() ==
                   EtherType::RCDCAP_ETHER_TYPE_IPv4 &&
               protolen == sizeof(ip_t))
            {
                // Moves the offset past the ARP header.
                offset += sizeof(ARPHeader);
                // Checks the type of the ARP message.
                switch(arp_header.getOpcode())
                {
                // It extracts the destination MAC and IP. Then it enters them
                // into the processor's ARP table.
                case ARPOpcode::RCDCAP_ARP_REPLY: {
                    if(caplen >= offset + 2*(protolen + hwlen))
                    {
                        auto& dstmac =
                            reinterpret_cast<mac_t&>(packet[offset +
                                                            protolen +
                                                            hwlen]);
                        auto& dstip =
                            reinterpret_cast<ip_t&>(packet[offset +
                                                           protolen +
                                                           2*hwlen]);
                        m_ARPTable[dstmac] = dstip;
                    }
                } // fall-through
                // It extracts the source MAC and IP. Then it enters them
                // into the processor's ARP table.
                case ARPOpcode::RCDCAP_ARP_REQUEST: {
                    if(caplen >= offset + protolen + hwlen)
                    {
                        auto& srcmac = reinterpret_cast<mac_t&>(packet[offset]);
                        auto& srcip = reinterpret_cast<ip_t&>(packet[offset +
                                                                     hwlen]);
                        m_ARPTable[srcmac] = srcip;
                    }
                } break;
                default:
                    break;
                }
            }
        }
        // If there is a report, it gets outputted to syslog with some additional
        // information.
        if(ss.rdbuf()->in_avail())
        {
            // Checks whether the source MAC address is inside the ARP table.
            // If that is true, it outputs the IP address.
            auto srcip = m_ARPTable.find(smac);
            if(srcip == m_ARPTable.end())
                ss << "; Source (L2) IP: Unknown";
            else
                ss << "; Source (L2) IP: " << srcip->second;
            // Checks whether the destination MAC address is inside the ARP table.
            // If that is true, it outputs the IP address.
            auto dstip = m_ARPTable.find(dmac);
            if(dstip == m_ARPTable.end())
                ss << "; Destination (L2) IP: Unknown";
            else
                ss << "; Destination (L2) IP: " << dstip->second;
            // Also, if it is an IPv4 packet, the actual source and
            // destination IP get extracted.
            if(eth_type == EtherType::RCDCAP_ETHER_TYPE_IPv4 &&
               caplen >= offset + sizeof(IPv4Header))
            {
                auto& ip_header = reinterpret_cast<IPv4Header&>(packet[offset]);
                ss << "; Source (L3) IP: " << ip_header.getSourceIP()
                   << "; Destination (L3) IP: " << ip_header.getDestinationIP();
            }
            // Finally, it writes the report to syslog.
            syslog(LOG_WARNING, "%s", ss.str().c_str());
        }
    } break;
    }
}