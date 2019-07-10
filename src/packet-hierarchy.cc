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

#include "rcdcap/packet-hierarchy.hh"

namespace RCDCap
{
UDPHeader& UDP::header()
{
    return reinterpret_cast<UDPHeader&>(*this);
}

unsigned char* UDP::nextHeader()
{
    return reinterpret_cast<unsigned char*>(this) + sizeof(UDPHeader);
}

size_t UDP::size() const
{
    return sizeof(UDPHeader);
}

IPv4Header& IPv4::header()
{
    return reinterpret_cast<IPv4Header&>(*this);
}

unsigned char* IPv4::nextHeader()
{
    return reinterpret_cast<unsigned char*>(this) + header().getIHL()*4;
}

size_t IPv4::size() const
{
    return sizeof(IPv4Header);
}

UDP& IPv4::udp()
{
    return *reinterpret_cast<UDP*>(nextHeader());
}

IPv6Header& IPv6::header()
{
    return reinterpret_cast<IPv6Header&>(*this);
}

unsigned char* IPv6::nextHeader()
{
    return reinterpret_cast<unsigned char*>(this) + sizeof(IPv6Header);
}

size_t IPv6::size() const
{
    return sizeof(IPv6Header);
}

UDP& IPv6::udp()
{
    return *reinterpret_cast<UDP*>(nextHeader());
}

ARPHeader& ARP::header()
{
    return *reinterpret_cast<ARPHeader*>(this);
}

unsigned char* ARP::nextHeader()
{
    return reinterpret_cast<unsigned char*>(this) + sizeof(ARPHeader);
}

size_t ARP::size() const
{
    return sizeof(ARPHeader);
}

ARPIPv4RequestFields& ARP::ipv4Request()
{
    return *reinterpret_cast<ARPIPv4RequestFields*>(nextHeader());
}

ARPIPv4ReplyFields& ARP::ipv4Reply()
{
    return *reinterpret_cast<ARPIPv4ReplyFields*>(nextHeader());
}

MACHeader& Ethernet::header()
{
    return reinterpret_cast<MACHeader&>(*this);
}

unsigned char* Ethernet::nextHeader()
{
    return reinterpret_cast<unsigned char*>(this) + sizeof(MACHeader);
}

size_t Ethernet::size() const
{
    return sizeof(MACHeader);
}

IPv4& Ethernet::ipv4()
{
    return *reinterpret_cast<IPv4*>(nextHeader());
}

IPv6& Ethernet::ipv6()
{
    return *reinterpret_cast<IPv6*>(nextHeader());
}


ARP& Ethernet::arp()
{
    return *reinterpret_cast<ARP*>(nextHeader());
}

MACHeader802_1Q& IEEE802_1Q::header()
{
    return reinterpret_cast<MACHeader802_1Q&>(*this);
}

unsigned char* IEEE802_1Q::nextHeader()
{
    return reinterpret_cast<unsigned char*>(this) + sizeof(MACHeader802_1Q);
}

size_t IEEE802_1Q::size() const
{
    return sizeof(MACHeader802_1Q);
}

IPv4& IEEE802_1Q::ipv4()
{
    return *reinterpret_cast<IPv4*>(nextHeader());
}

IPv6& IEEE802_1Q::ipv6()
{
    return *reinterpret_cast<IPv6*>(nextHeader());
}

ARP& IEEE802_1Q::arp()
{
    return *reinterpret_cast<ARP*>(nextHeader());
}

Ethernet& PacketHierarchy::ethernet()
{
    return reinterpret_cast<Ethernet&>(*this);
}

IEEE802_1Q& PacketHierarchy::dotQ()
{
    return reinterpret_cast<IEEE802_1Q&>(*this);
}
}