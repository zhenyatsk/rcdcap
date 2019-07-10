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

#include <syslog.h>

void QuietNeighborhoodMonitor::processDHCPService(VLANEntry* vlan, const RCDCap::DHCPOptionField* dhcp_option, size_t service_flag, size_t payload, size_t& offset)
{
    auto len = dhcp_option->getLength();
    if(len % 4)
    {
        syslog(LOG_ERR, "Protocol parsing error: The list of DNS servers is not multiple of 4, i.e. it contains at least one incomplete IPv4 address.");
        return;
    }
    if(len > offset - payload)
    {
        LOG_MESSAGE(LOG_WARNING, "Packet parsing warning: Incomplete packet. Can't parse the rest of the contents. Some DHS server were skipped as a consequence.");
        return;
    }
    for(auto* addr_iter = reinterpret_cast<const ip_t*>(dhcp_option + 1), *addr_iter_end = addr_iter + len/4;
        addr_iter != addr_iter_end; ++addr_iter)
    {
        m_NetworkCache.acquireServiceIP(m_State, vlan, *addr_iter, service_flag);
    }
    offset += dhcp_option->getLength() + sizeof(RCDCap::DHCPOptionField);
}

void QuietNeighborhoodMonitor::processDHCPv6Service(VLANEntry* vlan, const RCDCap::DHCPv6OptionField* dhcpv6_option, size_t service_flag)
{
    auto len = dhcpv6_option->getLength();
    if(len % 16)
    {
        LOG_MESSAGE(LOG_ERR, "Protocol parsing error: The list of DNS servers is not multiple of 4, i.e. it contains at least one incomplete IPv4 address.");
        return;
    }
    for(auto* current_ip6 = reinterpret_cast<const ip6_t*>(dhcpv6_option + 1), 
            * last_ip6 = current_ip6 + len/16;
        current_ip6 < last_ip6; ++current_ip6)
    {
        m_NetworkCache.acquireServiceIP(m_State, vlan, *current_ip6, service_flag);
    }
}

void QuietNeighborhoodMonitor::processDHCP(size_t vid, const RCDCap::IPv4Header* ipv4_header, const RCDCap::UDPHeader* udp_header, size_t payload_len)
{
    // The minimum requirement is to have DHCP header which has a valid options field cookie
    // and at least one option that contains the DHCP message type.
    if(payload_len < sizeof(RCDCap::DHCPHeader) + sizeof(uint32) + 3)
        return;

    if(udp_header->getSourcePort() == m_DHCPServerPort)
    {
        auto* dhcp_header = reinterpret_cast<const RCDCap::DHCPHeader*>(udp_header + 1);
        auto* dhcp_cookie = reinterpret_cast<const uint32*>(dhcp_header + 1);
        if(*dhcp_cookie != RCDCap::DHCPMagicCookie1 && *dhcp_cookie != RCDCap::DHCPMagicCookie2)
        {
            LOG_MESSAGE(LOG_ERR, "Protocol error: Unexpected DHCP cookie: %x", *dhcp_cookie);
            return;
        }

        auto* vlan = m_NetworkCache.acquireVLAN(m_State, vid);
        if(vlan == nullptr)
            return;
        
        auto* options = reinterpret_cast<const char*>(dhcp_cookie + 1);
        for(size_t offset = 0,
                   options_size = payload_len - sizeof(RCDCap::DHCPHeader) - sizeof(uint32);
            offset < options_size;)
        {
            auto* dhcp_option = reinterpret_cast<const RCDCap::DHCPOptionField*>(options + offset);
            auto _tag = dhcp_option->getTag();
            // We have one byte guaranteed form the check above.
            if(_tag == RCDCap::DHCPOptionTag::PAD_OPTION || _tag == RCDCap::DHCPOptionTag::END_OPTION)
                ++offset;
            // Otherwise we need at least one complete option.
            else if(offset + sizeof(RCDCap::DHCPOptionField) > options_size)
                return;

            switch(_tag)
            {
            case RCDCap::DHCPOptionTag::DHCP_MESSAGE_TYPE_OPTION:
            {
                auto* dhcp_msg_type = reinterpret_cast<const RCDCap::DHCPMessageType*>(dhcp_option + 1);
                switch(*dhcp_msg_type)
                {
                // Basically, that's probably a DHCP server that must be checked and
                // enlisted if there is some violation.
                case RCDCap::DHCPMessageType::DHCPACK:
                case RCDCap::DHCPMessageType::DHCPNAK:
                case RCDCap::DHCPMessageType::DHCPOFFER:
                {
                    // We don't throw away IPs because we need them to look for attacks that try to
                    // starve the IP pool.
                    auto* ip = m_NetworkCache.acquireServiceIP(m_State, vlan, ipv4_header->getSourceIP(), DHCP_SERVICE);
                    if(ip == nullptr)
                        return;
                } break;
                case RCDCap::DHCPMessageType::DHCPDISCOVER:
                case RCDCap::DHCPMessageType::DHCPDECLINE:
                case RCDCap::DHCPMessageType::DHCPRELEASE:
                case RCDCap::DHCPMessageType::DHCPINFORM:
                case RCDCap::DHCPMessageType::DHCPREQUEST:
                {
                    LOG_MESSAGE(LOG_ERR, "DHCP server that is requesting automatic configuration. That should not happen at all.");
                    break;
                }
                }
                offset += dhcp_option->getLength() + sizeof(RCDCap::DHCPOptionField);
            } break;
            case RCDCap::DHCPOptionTag::OPTION_PANA_AGENT: processDHCPService(vlan, dhcp_option, PANA_SERVICE, options_size, offset); break;
            case RCDCap::DHCPOptionTag::STDA_SERVER_OPTION: processDHCPService(vlan, dhcp_option, STDA_SERVICE, options_size, offset); break;
            case RCDCap::DHCPOptionTag::STREETTALK_SERVER_OPTION: processDHCPService(vlan, dhcp_option, STREETTALK_SERVICE, options_size, offset); break;
            case RCDCap::DHCPOptionTag::DEFAULT_IRC_SERVER_OPTION: processDHCPService(vlan, dhcp_option, IRC_SERVICE, options_size, offset); break;
            case RCDCap::DHCPOptionTag::DEFAULT_FINGER_SERVER_OPTION: processDHCPService(vlan, dhcp_option, FINGER_SERVICE, options_size, offset); break;
            case RCDCap::DHCPOptionTag::DEFAULT_WWW_SERVER_OPTION: processDHCPService(vlan, dhcp_option, WWW_SERVICE, options_size, offset); break;
            case RCDCap::DHCPOptionTag::NNTP_SERVER_OPTION: processDHCPService(vlan, dhcp_option, NNTP_SERVICE, options_size, offset); break;
            case RCDCap::DHCPOptionTag::POP3_SERVER_OPTION: processDHCPService(vlan, dhcp_option, POP3_SERVICE, options_size, offset); break;
            case RCDCap::DHCPOptionTag::SMTP_SERVER_OPTION: processDHCPService(vlan, dhcp_option, SMTP_SERVICE, options_size, offset); break;
            case RCDCap::DHCPOptionTag::NISP_SERVERS_OPTION: processDHCPService(vlan, dhcp_option, NISP_SERVICE, options_size, offset); break;
            case RCDCap::DHCPOptionTag::X_WINDOW_SYSTEM_DISPLAY_MANAGER_OPTION: processDHCPService(vlan, dhcp_option, XWSDM_SERVICE, options_size, offset); break;
            case RCDCap::DHCPOptionTag::X_WINDOW_FONT_SERVER_OPTION: processDHCPService(vlan, dhcp_option, XWSFS_SERVICE, options_size, offset); break;
            case RCDCap::DHCPOptionTag::NETBIOS_OVER_TCP_IP_DDS_OPTION: processDHCPService(vlan, dhcp_option, NETBIOS_DDS_SERVICE, options_size, offset); break;
            case RCDCap::DHCPOptionTag::NETBIOS_OVER_TCP_IP_NAME_SERVER_OPTION: processDHCPService(vlan, dhcp_option, NETBIOS_NAME_SERVICE, options_size, offset); break;
            case RCDCap::DHCPOptionTag::NTP_SERVERS_OPTION: processDHCPService(vlan, dhcp_option, NTP_SERVICE, options_size, offset); break;
            case RCDCap::DHCPOptionTag::NIS_OPTION: processDHCPService(vlan, dhcp_option, NIS_SERVICE, options_size, offset); break;
            case RCDCap::DHCPOptionTag::RESOURCE_LOCATION_SERVER_OPTION: processDHCPService(vlan, dhcp_option, RLS_SERVICE, options_size, offset); break;
            case RCDCap::DHCPOptionTag::IMPRESS_SERVER_OPTION: processDHCPService(vlan, dhcp_option, IMPRESS_SERVICE, options_size, offset); break;
            case RCDCap::DHCPOptionTag::LPR_SERVER_OPTION: processDHCPService(vlan, dhcp_option, LPR_SERVICE, options_size, offset); break;
            case RCDCap::DHCPOptionTag::COOKIE_SERVER_OPTION: processDHCPService(vlan, dhcp_option, COOKIE_SERVICE, options_size, offset); break;
            case RCDCap::DHCPOptionTag::LOG_SERVER_OPTION: processDHCPService(vlan, dhcp_option, LOG_SERVICE, options_size, offset); break;
            case RCDCap::DHCPOptionTag::NAME_SERVER_OPTION: processDHCPService(vlan, dhcp_option, NAME_SERVICE, options_size, offset); break;
            case RCDCap::DHCPOptionTag::TIME_SERVER_OPTION: processDHCPService(vlan, dhcp_option, TP_SERVICE, options_size, offset); break;
            case RCDCap::DHCPOptionTag::ROUTER_OPTION: processDHCPService(vlan, dhcp_option, ROUTING_SERVICE, options_size, offset); break;
            case RCDCap::DHCPOptionTag::DNS_OPTION: processDHCPService(vlan, dhcp_option, DNS_SERVICE, options_size, offset); break;
            default:
                offset += dhcp_option->getLength() + sizeof(RCDCap::DHCPOptionField);
            }
        }
    }
}

void QuietNeighborhoodMonitor::processDHCPv6(size_t vid, const RCDCap::IPv6Header* ipv6_header, const RCDCap::UDPHeader* udp_header, size_t payload_len)
{
    if(payload_len < sizeof(RCDCap::DHCPv6Header) + sizeof(RCDCap::DHCPv6OptionField))
        return;
	
	if(udp_header->getSourcePort() == m_DHCPv6ServerPort)
    {
		auto* dhcpv6_header = reinterpret_cast<const RCDCap::DHCPv6Header*>(udp_header + 1);
        auto _type = dhcpv6_header->getType();
		switch(_type)
        {
        case RCDCap::DHCPv6MessageType::ADVERTISE:
        case RCDCap::DHCPv6MessageType::REPLY:
        case RCDCap::DHCPv6MessageType::RECONFIGURE:
        {
            auto* vlan = m_NetworkCache.acquireVLAN(m_State, vid);
            if(vlan == nullptr)
                return;
            
            // We don't throw away IPs because we need them to look for attacks that try to
            // starve the IP pool.
            auto* ip = m_NetworkCache.acquireServiceIP(m_State, vlan, ipv6_header->getSourceIP(), DHCPV6_SERVICE);
            if(ip == nullptr)
                return;
                         
            for(const char* current_packet = reinterpret_cast<const char*>(dhcpv6_header + 1),
                          * packet_end = current_packet + payload_len - sizeof(RCDCap::DHCPv6Header);
                current_packet < packet_end;)
            {
                auto* dhcpv6_option = reinterpret_cast<const RCDCap::DHCPv6OptionField*>(current_packet);
                auto len = dhcpv6_option->getLength();
                auto _type = dhcpv6_option->getOptionCode();
                if(current_packet + len > packet_end)
                {
                    LOG_MESSAGE(LOG_WARNING, "Incomplete DHCPv6 packet");
                    break;
                }
                switch(_type)
                {
                case RCDCap::DHCPv6OptionCode::OPTION_DNS_SERVERS: processDHCPv6Service(vlan, dhcpv6_option, DNS_SERVICE); break;
                case RCDCap::DHCPv6OptionCode::OPTION_SIP_SERVER_A: processDHCPv6Service(vlan, dhcpv6_option, SIP_SERVICE); break;
                case RCDCap::DHCPv6OptionCode::OPTION_NIS_SERVERS: processDHCPv6Service(vlan, dhcpv6_option, NIS_SERVICE); break;
                case RCDCap::DHCPv6OptionCode::OPTION_NISP_SERVERS: processDHCPv6Service(vlan, dhcpv6_option, NISP_SERVICE); break;
                case RCDCap::DHCPv6OptionCode::OPTION_SNTP_SERVERS: processDHCPv6Service(vlan, dhcpv6_option, NTP_SERVICE); break;
                case RCDCap::DHCPv6OptionCode::OPTION_BCMCS_SERVER_A: processDHCPv6Service(vlan, dhcpv6_option, BCMCS_SERVICE); break;
                case RCDCap::DHCPv6OptionCode::OPTION_PANA_AGENT: processDHCPv6Service(vlan, dhcpv6_option, PANA_SERVICE); break;
                default:
                    break;
                }
                current_packet += len + sizeof(RCDCap::DHCPv6OptionField);
            }
        } break;
        case RCDCap::DHCPv6MessageType::RELAY_REPL:
        {
            
        } break;
        
        // TODO:
        case RCDCap::DHCPv6MessageType::SOLICIT:
        case RCDCap::DHCPv6MessageType::REQUEST:
        case RCDCap::DHCPv6MessageType::CONFIRM:
        case RCDCap::DHCPv6MessageType::RENEW:
        case RCDCap::DHCPv6MessageType::REBIND:
        case RCDCap::DHCPv6MessageType::RELEASE:
        case RCDCap::DHCPv6MessageType::DECLINE:
        case RCDCap::DHCPv6MessageType::INFORMATION_REQUEST:
        case RCDCap::DHCPv6MessageType::RELAY_FORW:
            break;
        }
	}
}
