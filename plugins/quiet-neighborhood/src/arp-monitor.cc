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

using RCDCap::mac_t;

void QuietNeighborhoodMonitor::processARP(size_t vid, const RCDCap::ARPHeader* arp_header, size_t payload_len)
{
    // Extracts the protocol and hardware address length.
    size_t protolen = arp_header->getProtocolAddressLength(),
           hwlen = arp_header->getHardwareAddressLength();
    // Currently, it supports only IPv4 and Ethernet.
    if(arp_header->getHardwareType() == RCDCap::ARPHardwareType::RCDCAP_ARP_HW_Ethernet &&
        hwlen == sizeof(mac_t) &&
        arp_header->getProtocolType() == RCDCap::EtherType::RCDCAP_ETHER_TYPE_IPv4 &&
        protolen == sizeof(ip_t) &&
        arp_header->getOpcode() == RCDCap::ARPOpcode::RCDCAP_ARP_REPLY &&
        payload_len >= 2*(protolen + hwlen))
    {
        auto* vlan = m_NetworkCache.acquireVLAN(m_State, vid);
        if(vlan == nullptr)
            return;
        
        auto* packet = reinterpret_cast<const char*>(arp_header + 1);
        m_NetworkCache.acquireIP(m_State, vlan, reinterpret_cast<const ip_t&>(packet[protolen + 2*hwlen]));
    }
}