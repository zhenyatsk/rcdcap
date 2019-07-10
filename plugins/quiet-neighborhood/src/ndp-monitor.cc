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

#include <syslog.h>

void QuietNeighborhoodMonitor::processNDP(size_t vid, const RCDCap::IPv6Header* ipv6_header, const RCDCap::ICMPv6Header* header, size_t payload_len)
{
    auto _type = header->getType();
    switch(_type)
    {
    case RCDCap::ICMPv6MessageType::RCDCAP_ICMPv6_ROUTER_ADVERTISEMENT:
    {
        auto* vlan = m_NetworkCache.acquireVLAN(m_State, vid);
        if(vlan == nullptr)
            return;
        
        // We register the current IP as one that offers routing service.
        auto* ip = m_NetworkCache.acquireServiceIP(m_State, vlan, ipv6_header->getSourceIP(), ROUTING_SERVICE);
        if(ip == nullptr)
            return;

        if(payload_len < sizeof(RCDCap::RouterAdvertisementHeader))
            return;
        
        auto* router_advertisement = reinterpret_cast<const RCDCap::RouterAdvertisementHeader*>(header + 1);
        
        for(auto* iter = reinterpret_cast<const char*>(router_advertisement + 1), *iter_end = reinterpret_cast<const char*>(header + 1) + payload_len; iter < iter_end;)
        {
            auto* ndp_option_field = reinterpret_cast<const RCDCap::NDPOptionField*>(iter);
            // DNS servers are registered in the network cache.
            if(ndp_option_field->getType() == RCDCap::NDPOption::RECURSIVE_DNS_SERVER)
            {
                auto* rdnss_option = reinterpret_cast<const RCDCap::RDNSSOption*>(ndp_option_field);
                auto len = (rdnss_option->getLength()-1)/2;
                if(rdnss_option->getLength() > payload_len - (reinterpret_cast<const char*>(header + 1) - iter))
                {
                    LOG_MESSAGE(LOG_WARNING, "Packet parsing warning: Incomplete packet. Can't parse the rest of the contents. Some DHS server were skipped as a consequence.");
                    return;
                }
                for(auto* addr_iter = reinterpret_cast<const ip6_t*>(rdnss_option + 1), *addr_iter_end = addr_iter + len;
                    addr_iter != addr_iter_end; ++addr_iter)
                {
                    m_NetworkCache.acquireServiceIP(m_State, vlan, *addr_iter, DNS_SERVICE);
                }
            } 
            iter_end += 8*ndp_option_field->getLength();
        }
    } break;
    // We just insert values about new IPs. The subnet checks are performed under the hood.
    case RCDCap::ICMPv6MessageType::RCDCAP_ICMPv6_NEIGHBOR_ADVERTISEMNT:
    {
        auto* vlan = m_NetworkCache.acquireVLAN(m_State, vid);
        if(vlan == nullptr)
            return;
        
        if(payload_len < sizeof(RCDCap::RouterAdvertisementHeader) - sizeof(RCDCap::ICMPv6Header))
            return;
        auto* neigh_adv = reinterpret_cast<const RCDCap::NeighborAdvertisementHeader*>(header);
        
        auto* ip = m_NetworkCache.acquireIP(m_State, vlan, neigh_adv->getTargetAddress());
        if(ip == nullptr)
            return;
    } break;
    default:
        break;
    }
}