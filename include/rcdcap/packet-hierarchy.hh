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

#ifndef _RCDCAP_PACKET_HIERARCHY_HH_
#define _RCDCAP_PACKET_HIERARCHY_HH_

#include "rcdcap/packet-headers.hh"
#include "rcdcap/common-buffer.hh"

namespace RCDCap
{
//! Encapsulates all operations associated with extracting data from an UDP packet.
class UDP
{
public:
    //! Extracts the header.
    UDPHeader& header();

    //! Extracts the next header.
    unsigned char* nextHeader();

    //! Returns the UDP header size.
    size_t size() const;
};

//! Encapsulates all operations associated with extracting data from an IPv4 packet.
class IPv4
{
public:
    //! Extracts the header.
    IPv4Header& header();

    //! Extracts the next header.
    unsigned char* nextHeader();

    //! Returns the IPv4 header size.
    size_t size() const;

    /*! \brief Extracts the next header as an UDP header.
     *  \warning You must perform checks before using this function. It is not
     *           guaranteed that the next header is actually an UDP header.
     */
    UDP& udp();
};

//! Encapsulates all operations associated with extracting data from an IPv6 packet.
class IPv6
{
public:
    //! Extracts the header.
    IPv6Header& header();

    //! Extracts the next header.
    unsigned char* nextHeader();

    //! Returns the IPv6 header size.
    size_t size() const;

    /*! \brief Extracts the next header as an UDP header.
     *  \warning You must perform checks before using this function. It is not
     *           guaranteed that the next header is actually an UDP header.
     */
    UDP& udp();
};

//! Encapsulates all operations associated with extracting data from an ARP packet.
class ARP
{
public:
    //! Extracts the header.
    ARPHeader& header();

    //! Extracts the next header.
    unsigned char* nextHeader();

    //! Returns the IPv6 header size.
    size_t size() const;

    /*! \brief Extracts the information following this header as an IPv4-based
     *         ARP Request.
     *  \warning You must perform checks before using this function. It is not
     *           guaranteed that the actual data resemble an ARP Request.
     */
    ARPIPv4RequestFields& ipv4Request();

    /*! \brief Extracts the information following this header as an IPv4-based
     *         ARP Reply.
     *  \warning You must perform checks before using this function. It is not
     *           guaranteed that the actual data resemble an ARP Reply.
     */
    ARPIPv4ReplyFields& ipv4Reply();
};

//! Encapsulates all operations associated with extracting data from an Ethernet II frame.
class Ethernet
{
public:
    //! Extracts the header.
    MACHeader& header();

    //! Extracts the next header.
    unsigned char* nextHeader();

    //! Returns the Ethernet II header size.
    size_t size() const;

    /*! \brief Extracts the next header as an IPv4 header.
     *  \warning You must perform checks before using this function. It is not
     *           guaranteed that the next header is actually an IPv4 header.
     */
    IPv4& ipv4();

    /*! \brief Extracts the next header as an IPv6 header.
     *  \warning You must perform checks before using this function. It is not
     *           guaranteed that the next header is actually an IPv6 header.
     */
    IPv6& ipv6();

    /*! \brief Extracts the next header as an ARP header.
     *  \warning You must perform checks before using this function. It is not
     *           guaranteed that the next header is actually an ARP header.
     */
    ARP& arp();
};

//! Encapsulates all operations associated with extracting data from an IEEE 802.1Q frame.
class IEEE802_1Q
{
public:
    //! Extracts the header.
    MACHeader802_1Q& header();

    //! Extracts the next header.
    unsigned char* nextHeader();

    //! Returns the Ethernet II header size.
    size_t size() const;

    /*! \brief Extracts the next header as an IPv4 header.
     *  \warning You must perform checks before using this function. It is not
     *           guaranteed that the next header is actually an IPv4 header.
     */
    IPv4& ipv4();

    /*! \brief Extracts the next header as an IPv6 header.
     *  \warning You must perform checks before using this function. It is not
     *           guaranteed that the next header is actually an IPv6 header.
     */
    IPv6& ipv6();

    /*! \brief Extracts the next header as an ARP header.
     *  \warning You must perform checks before using this function. It is not
     *           guaranteed that the next header is actually an ARP header.
     */
    ARP& arp();
};

//! Encapsulates all operations associated with extracting data from packets.
class PacketHierarchy
{
public:
    //! Extracts the first header as an Ethernet II header.
    Ethernet& ethernet();

    //! Extracts the first header as an IEEE 802.1Q header.
    IEEE802_1Q& dotQ();
};

//! Extracts the packet contents in the hierarchic PacketHierarchy form.
inline PacketHierarchy& GetPacketHierarchy(PacketInfo* packet_info)
{
    return *reinterpret_cast<PacketHierarchy*>(GetPacket(packet_info));
}
}

#endif /* _RCDCAP_PY_PACKET_HIERARCHY_HH_ */