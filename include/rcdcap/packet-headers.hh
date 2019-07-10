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

#ifndef _RCDCAP_PACKET_HEADERS_HH_
#define _RCDCAP_PACKET_HEADERS_HH_

#include "rcdcap/global.hh"
#include "rcdcap/types.hh"
#include "rcdcap/byte-order.hh"

#include <array>
#include <iostream>
#include <iomanip>

#include <stddef.h>

#ifdef _WIN32
typedef __m128 int128;
inline bool operator!=(int128 lhs, int128 rhs)
{
    auto cmp = _mm_castps_si128(_mm_cmpeq_ps(lhs, rhs));
    auto mask = _mm_movemask_epi8(cmp);
    return mask != 0;
}

inline bool operator==(int128 lhs, int128 rhs)
{
    auto cmp = _mm_castps_si128(_mm_cmpneq_ps(lhs, rhs));
    auto mask = _mm_movemask_epi8(cmp);
    return mask != 0;
}
#else
typedef __int128 int128;
#endif

namespace RCDCap
{
//! Contains some of the available values of the EtherType field in the Ethernet header.
enum class EtherType: uint16
{
    RCDCAP_ETHER_TYPE_PARC              = 0x0200, //!< Xerox PARC Universal Protocol (PUP).
    RCDCAP_ETHER_TYPE_IPv4              = 0x0800, //!< Internet Protocol.
    RCDCAP_ETHER_TYPE_ARP               = 0x0806, //!< Address Resolution Protocol (ARP).
    RCDCAP_ETHER_TYPE_DECnetIV          = 0x6003, //!< DECnet Phase IV Route.
    RCDCAP_ETHER_TYPE_RARP              = 0x8035, //!< Reverse Address Resolution Protocol (RARP).
    RCDCAP_ETHER_TYPE_EtherTalk         = 0x809B, //!< EtherTalk (AppleTalk over Ethernet).
    RCDCAP_ETHER_TYPE_AARP              = 0x80F3, //!< AppleTalk Address Resolution Protocol.
    RCDCAP_ETHER_TYPE_802_1Q            = 0x8100, //!< 802.1Q tagged Ethernet frame.
    RCDCAP_ETHER_TYPE_IPX               = 0x8137, //!< Novell NetWare IPX.
    RCDCAP_ETHER_TYPE_Novell            = 0x8138, //!< Novell, Inc.
    RCDCAP_ETHER_TYPE_QNX               = 0x8204, //!< Quantum Software Systems, Inc.
    RCDCAP_ETHER_TYPE_IPv6              = 0x86DD, //!< Internet Protocol version 6.
    RCDCAP_ETHER_TYPE_MPCP              = 0x8808, //!< Multi-Point Control Protocol.
    RCDCAP_ETHER_TYPE_MPLS_unicast      = 0x8847, //!< Multi-Protocol Label Switching (unicast).
    RCDCAP_ETHER_TYPE_MPLS_multicast    = 0x8848, //!< Multi-Protocol Label Switching (multicast).
    RCDCAP_ETHER_TYPE_PPPoE_Discovery   = 0x8863, //!< PPP over Ethernet (Discovery stage).
    RCDCAP_ETHER_TYPE_PPPoE_Session     = 0x8864, //!< PPP over Ethernet (PPP Session stage).
    RCDCAP_ETHER_TYPE_NLB               = 0x886F, //!< Network Load Balancing.
    RCDCAP_ETHER_TYPE_Jumbo             = 0x8870, //!< Jumbo frame.
    RCDCAP_ETHER_TYPE_EAPoL             = 0x888E, //!< EAP over LAN.
    RCDCAP_ETHER_TYPE_PROFINET          = 0x8892, //!< PROFINET Protocol.
    RCDCAP_ETHER_TYPE_HyperSCSI         = 0x889A, //!< SCSI over Ethernet.
    RCDCAP_ETHER_TYPE_ATAoE             = 0x88A2, //!< ATA over Ethernet.
    RCDCAP_ETHER_TYPE_EtherCAT          = 0x88A4, //!< EtherCAT Protocol.
    RCDCAP_ETHER_TYPE_ProviderBridging  = 0x88A8, //!< Provider bridging (IEEE 802.1ad).
    RCDCAP_ETHER_TYPE_Powerlink         = 0x88AB, //!< Ethernet Powerlink.
    RCDCAP_ETHER_TYPE_LLDP              = 0x88CC, //!< Link Layer Discovery Protocol (LLDP).
    RCDCAP_ETHER_TYPE_SERCOSIII         = 0x88CD, //!< SERCOS interface real-time protocol.
    RCDCAP_ETHER_TYPE_MEF_8             = 0x88D8, //!< The Metro Ethernet Forum's MEF 8.
    RCDCAP_ETHER_TYPE_HomePlug          = 0x88E1, //!< HomePlug protocols.
    RCDCAP_ETHER_TYPE_MRP               = 0x88E3, //!< Medium Redundancy Protocol.
    RCDCAP_ETHER_TYPE_MACsecu           = 0x88E5, //!< Part of 802.1ae.
    RCDCAP_ETHER_TYPE_PTime             = 0x88F7, //!< Precision Clock Synchronization Protocol.
    RCDCAP_ETHER_TYPE_FCoE              = 0x8906  //!< Fibre Channel over Ethernet.
};

/*! Contains some of the available values of the ProtocolType field in the IPv4 header and the
 *  NextHeader field in the IPv6 header.
 */
enum class ProtocolType: uint8
{
    RCDCAP_PROTOCOL_TYPE_HOPOPT         = 0x00, //!< IPv6 Hop-by-Hop option.
    RCDCAP_PROTOCOL_TYPE_ICMP           = 0x01, //!< Internet Control Message Protocol.
    RCDCAP_PROTOCOL_TYPE_IGMP           = 0x02, //!< Internet Group Management Protocol.
    RCDCAP_PROTOCOL_TYPE_GGP            = 0x03, //!< Gateway-to-Gateway Protocol.
    RCDCAP_PROTOCOL_TYPE_IPv4           = 0x04, //!< IPv4 (encapsulation).
    RCDCAP_PROTOCOL_TYPE_ST             = 0x05, //!< Internet Stream Protocol.
    RCDCAP_PROTOCOL_TYPE_TCP            = 0x06, //!< Transmission Control Protocol.
    RCDCAP_PROTOCOL_TYPE_CBT            = 0x07, //!< Core-based trees.
    RCDCAP_PROTOCOL_TYPE_EGP            = 0x08, //!< Exterior Gateway Protocol.
    RCDCAP_PROTOCOL_TYPE_IGP            = 0x09, //!< Interior Gateway Protocol.
    RCDCAP_PROTOCOL_TYPE_BBN_RCC_MON    = 0x0A, //!< BBN RCC Monitoring.
    RCDCAP_PROTOCOL_TYPE_NVP_II         = 0x0B, //!< Network Voice Protocol.
    RCDCAP_PROTOCOL_TYPE_PUP            = 0x0C, //!< Xerox PUP.
    RCDCAP_PROTOCOL_TYPE_ARGUS          = 0x0D, //!< ARGUS.
    RCDCAP_PROTOCOL_TYPE_EMCON          = 0x0E, //!< EMCON.
    RCDCAP_PROTOCOL_TYPE_XNET           = 0x0F, //!< Cross Net Debugger.
    RCDCAP_PROTOCOL_TYPE_CHAOS          = 0x10, //!< Chaos.
    RCDCAP_PROTOCOL_TYPE_UDP            = 0x11, //!< User Datagram Protocol.
    RCDCAP_PROTOCOL_TYPE_MUX            = 0x12, //!< Multiplexing.
    RCDCAP_PROTOCOL_TYPE_DCN_MEAS       = 0x13, //!< DCN Measurement Subsystems.
    RCDCAP_PROTOCOL_TYPE_HMP            = 0x14, //!< Host Monitoring Protocol.
    RCDCAP_PROTOCOL_TYPE_PRM            = 0x15, //!< Packet Radio Measurement.
    RCDCAP_PROTOCOL_TYPE_XNS_IDP        = 0x16, //!< XEROX NS IDP.
    RCDCAP_PROTOCOL_TYPE_TRUNK_1        = 0x17, //!< Trunk-1.
    RCDCAP_PROTOCOL_TYPE_TRUNK_2        = 0x18, //!< Trunk-2.
    RCDCAP_PROTOCOL_TYPE_LEAF_1         = 0x19, //!< Leaf-1.
    RCDCAP_PROTOCOL_TYPE_LEAF_2         = 0x1A, //!< Leaf-2.
    RCDCAP_PROTOCOL_TYPE_RDP            = 0x1B, //!< Reliable Datagram Protocol.
    RCDCAP_PROTOCOL_TYPE_IRTP           = 0x1C, //!< Internet Reliable Transaction Protocol.
    RCDCAP_PROTOCOL_TYPE_ISO_TP4        = 0x1D, //!< ISO Transport Protocol Class 4.
    RCDCAP_PROTOCOL_TYPE_NETBLT         = 0x1E, //!< Bulk Data Transfer Protocol.
    RCDCAP_PROTOCOL_TYPE_MFE_NSP        = 0x1F, //!< MFE Network Services Protocol.
    RCDCAP_PROTOCOL_TYPE_MERIT_INP      = 0x20, //!< MERIT Internodal Protocol.
    RCDCAP_PROTOCOL_TYPE_DCCP           = 0x21, //!< Datagram Congestion Control Protocol.
    RCDCAP_PROTOCOL_TYPE_3PC            = 0x22, //!< Third Party Connect Protocol.
    RCDCAP_PROTOCOL_TYPE_IDPR           = 0x23, //!< Inter-Domain Policy Routing.
    RCDCAP_PROTOCOL_TYPE_XTP            = 0x24, //!< Xpress Transport Protocol.
    RCDCAP_PROTOCOL_TYPE_DDP            = 0x25, //!< Datagram Delivery Protocol.
    RCDCAP_PROTOCOL_TYPE_IDPR_CMTP      = 0x26, //!< IDPR Control Message Transport Protocol.
    RCDCAP_PROTOCOL_TYPE_TPXX           = 0x27, //!< TP++ Transport Protocol.
    RCDCAP_PROTOCOL_TYPE_IL             = 0x28, //!< IL Transport Protocol.
    RCDCAP_PROTOCOL_TYPE_IPv6           = 0x29, //!< IPv6 (encapsulation).
    RCDCAP_PROTOCOL_TYPE_SDRP           = 0x2A, //!< Source Demand Routing Protocol.
    RCDCAP_PROTOCOL_TYPE_IPv6_Route     = 0x2B, //!< Routing Header for IPv6.
    RCDCAP_PROTOCOL_TYPE_IPv6_Flag      = 0x2C, //!< Fragmentt Header for IPv6.
    RCDCAP_PROTOCOL_TYPE_IDRP           = 0x2D, //!< Inter-Domain Routing Protocol.
    RCDCAP_PROTOCOL_TYPE_RSVP           = 0x2E, //!< Resource ReserVation Protocol.
    RCDCAP_PROTOCOL_TYPE_GRE            = 0x2F, //!< Generic Routing Encapsulation.
    RCDCAP_PROTOCOL_TYPE_DSR            = 0x30, //!< Mobile Host Routing Protocol.
    RCDCAP_PROTOCOL_TYPE_BNA            = 0x31, //!< BNA.
    RCDCAP_PROTOCOL_TYPE_ESP            = 0x32, //!< Encapsulating Security Payload.
    RCDCAP_PROTOCOL_TYPE_AH             = 0x33, //!< Authentication Header.
    RCDCAP_PROTOCOL_TYPE_I_NLSP         = 0x34, //!< Integrated Net Layer.
    RCDCAP_PROTOCOL_TYPE_SWIPE          = 0x35, //!< SwIPe.
    RCDCAP_PROTOCOL_TYPE_NARP           = 0x36, //!< NBMA Address Resolution Protocol.
    RCDCAP_PROTOCOL_TYPE_MOBILE         = 0x37, //!< IP Mobility (Min Encap).
    RCDCAP_PROTOCOL_TYPE_TLSP           = 0x38, //!< Transport Layer Security.
    RCDCAP_PROTOCOL_TYPE_SKIP           = 0x39, //!< Simple Key-Management Protocol.
    RCDCAP_PROTOCOL_TYPE_IPv6_ICMP      = 0x3A, //!< ICMP for IPv6.
    RCDCAP_PROTOCOL_TYPE_IPv6_NoNxt     = 0x3B, //!< No Next Header for IPv6.
    RCDCAP_PROTOCOL_TYPE_IPv6_Opts      = 0x3C, //!< Destination Options for IPv6.
    RCDCAP_PROTOCOL_TYPE_CFTP           = 0x3E, //!< CFTP.
    RCDCAP_PROTOCOL_TYPE_SAT_EXPAK      = 0x40, //!< SATNET and Backroom EXPAK.
    RCDCAP_PROTOCOL_TYPE_KRYPTOLAN      = 0x41, //!< Kryptolan.
    RCDCAP_PROTOCOL_TYPE_RVD            = 0x42, //!< MIT Remote Virtual Disk Protocol.
    RCDCAP_PROTOCOL_TYPE_IPPC           = 0x43, //!< Internet Pluribus Packet Core.
    RCDCAP_PROTOCOL_TYPE_SAT_MON        = 0x45, //!< SATNET Monitoring.
    RCDCAP_PROTOCOL_TYPE_VISA           = 0x46, //!< VISA Protocol.
    RCDCAP_PROTOCOL_TYPE_IPCV           = 0x47, //!< Internet Packet Core Utility.
    RCDCAP_PROTOCOL_TYPE_CPNX           = 0x48, //!< Computer Protocol Network Executive.
    RCDCAP_PROTOCOL_TYPE_CPHB           = 0x49, //!< Computer Protocol Heart Beat.
    RCDCAP_PROTOCOL_TYPE_WSN            = 0x4A, //!< Wang Span Network.
    RCDCAP_PROTOCOL_TYPE_PVP            = 0x4B, //!< Packet Video Protocol.
    RCDCAP_PROTOCOL_TYPE_BR_SAT_MON     = 0x4C, //!< Backroom SATNET Monitoring.
    RCDCAP_PROTOCOL_TYPE_SUN_ND         = 0x4D, //!< SUN ND Protocol-Temporary.
    RCDCAP_PROTOCOL_TYPE_WB_MON         = 0x4E, //!< WIDEBAND Monitoring.
    RCDCAP_PROTOCOL_TYPE_WB_EXPAK       = 0x4F, //!< WIDEBAND EXPAK.
    RCDCAP_PROTOCOL_TYPE_ISO_IP         = 0x50, //!< ISO Internet Protocol.
    RCDCAP_PROTOCOL_TYPE_VMTP           = 0x51, //!< Versatile Message Transaction Protocol.
    RCDCAP_PROTOCOL_TYPE_SECURE_VMTP    = 0x52, //!< Secure Versatile Message Transaction Protocol.
    RCDCAP_PROTOCOL_TYPE_VINES          = 0x53, //!< VINES.
    RCDCAP_PROTOCOL_TYPE_TTP            = 0x54, //!< TTP.
    RCDCAP_PROTOCOL_TYPE_IPTM           = 0x55, //!< Internet Protocol Traffic Manager.
    RCDCAP_PROTOCOL_TYPE_NSFNET_IGP     = 0x56, //!< NSFNET-IGP.
    RCDCAP_PROTOCOL_TYPE_DGP            = 0x57, //!< Dissimilar Gateway Protocol.
    RCDCAP_PROTOCOL_TYPE_EIGRP          = 0x58, //!< EIGRP.
    RCDCAP_PROTOCOL_TYPE_OSPFIGP        = 0x59, //!< Open Shortest Path First.
    RCDCAP_PROTOCOL_TYPE_Sprite_RPC     = 0x5A, //!< Sprite RPC Protocol.
    RCDCAP_PROTOCOL_TYPE_LARP           = 0x5B, //!< Locus Address Resolution Protocol.
    RCDCAP_PROTOCOL_TYPE_MTP            = 0x5C, //!< Multicast Transport Protocol.
    RCDCAP_PROTOCOL_TYPE_AX25           = 0x5D, //!< AX.25.
    RCDCAP_PROTOCOL_TYPE_IPIP           = 0x5E, //!< IP-within-IP Encapsulation Protocol.
    RCDCAP_PROTOCOL_TYPE_MICP           = 0x5F, //!< Mobile Internetworking Control Protocol.
    RCDCAP_PROTOCOL_TYPE_SCC_SP         = 0x60, //!< Semaphore Communications Sec. Pro.
    RCDCAP_PROTOCOL_TYPE_ETHERIP        = 0x61, //!< Ethernet-within-IP Encapsulation.
    RCDCAP_PROTOCOL_TYPE_ENCAP          = 0x62, //!< Encapsulation Header.
    RCDCAP_PROTOCOL_TYPE_GMTP           = 0x64, //!< GMTP.
    RCDCAP_PROTOCOL_TYPE_IFMP           = 0x65, //!< Ipsilon Flow Management Protocol.
    RCDCAP_PROTOCOL_TYPE_PNNI           = 0x66, //!< PNNI over IP.
    RCDCAP_PROTOCOL_TYPE_PIM            = 0x67, //!< Protocol Independent Multicast.
    RCDCAP_PROTOCOL_TYPE_ARIS           = 0x68, //!< IBM's Aggregate Route IP Switching Protocol.
    RCDCAP_PROTOCOL_TYPE_SCPS           = 0x69, //!< Space Communications Protocol Standards.
    RCDCAP_PROTOCOL_TYPE_QNX            = 0x6A, //!< QNX.
    RCDCAP_PROTOCOL_TYPE_AN             = 0x6B, //!< Active Networks.
    RCDCAP_PROTOCOL_TYPE_IPComp         = 0x6C, //!< IP Payload Compression Protocol.
    RCDCAP_PROTOCOL_TYPE_SNP            = 0x6D, //!< Sitara Networks Protocol.
    RCDCAP_PROTOCOL_TYPE_Compaq_Peer    = 0x6E, //!< Compaq Peer Protocol.
    RCDCAP_PROTOCOL_TYPE_IPX_in_IP      = 0x6F, //!< IPX in IP.
    RCDCAP_PROTOCOL_TYPE_VRRP           = 0x70, //!< Virtual Router Redundancy Protocol.
    RCDCAP_PROTOCOL_TYPE_PGM            = 0x71, //!< PGM Reliable Transport Protocol.
    RCDCAP_PROTOCOL_TYPE_L2TP           = 0x73, //!< Layer Two Tunneling Protocol version 3.
    RCDCAP_PROTOCOL_TYPE_DDX            = 0x74, //!< D-II Data Exchange (DDX).
    RCDCAP_PROTOCOL_TYPE_IATP           = 0x75, //!< Interactive Agent Transfer Protocol.
    RCDCAP_PROTOCOL_TYPE_STP            = 0x76, //!< Schedule Transfer Protocol.
    RCDCAP_PROTOCOL_TYPE_SRP            = 0x77, //!< SpectraLink Radio Protocol.
    RCDCAP_PROTOCOL_TYPE_UTI            = 0x78, //!< UTI.
    RCDCAP_PROTOCOL_TYPE_SMP            = 0x79, //!< Simple Message Protocol.
    RCDCAP_PROTOCOL_TYPE_SM             = 0x7A, //!< SM.
    RCDCAP_PROTOCOL_TYPE_PTP            = 0x7B, //!< Performance Transparency Protocol.
    RCDCAP_PROTOCOL_TYPE_ISIS_over_IPv4 = 0x7C, //!< IS-IS over IPv4.
    RCDCAP_PROTOCOL_TYPE_FIRE           = 0x7D, //!< FIRE.
    RCDCAP_PROTOCOL_TYPE_CRTP           = 0x7E, //!< Combat Radio Transport Protocol.
    RCDCAP_PROTOCOL_TYPE_CRUDP          = 0x7F, //!< Combat Radio User Datagram.
    RCDCAP_PROTOCOL_TYPE_SSCOPMCE       = 0x80, //!< SSCOPMCE.
    RCDCAP_PROTOCOL_TYPE_IPLT           = 0x81, //!< IPLT.
    RCDCAP_PROTOCOL_TYPE_SPS            = 0x82, //!< Secure Packet Shield.
    RCDCAP_PROTOCOL_TYPE_PIPE           = 0x83, //!< Private IP Encapsulation within IP.
    RCDCAP_PROTOCOL_TYPE_SCTP           = 0x84, //!< Stream Control Transmission Protocol.
    RCDCAP_PROTOCOL_TYPE_FC             = 0x85, //!< Fibre Channel.
    RCDCAP_PROTOCOL_TYPE_RSVP_E2E_IGNORE = 0x86, //!< RSVP-E2E-IGNORE.
    RCDCAP_PROTOCOL_TYPE_Mobility_Header = 0x87, //!< Mobility Header.
    RCDCAP_PROTOCOL_TYPE_UDPLite        = 0x88, //!< UDP Lite.
    RCDCAP_PROTOCOL_TYPE_MPLS_in_IP     = 0x89, //!< MPLS-in-IP.
    RCDCAP_PROTOCOL_TYPE_manet          = 0x8A, //!< MANET Protocols.
    RCDCAP_PROTOCOL_TYPE_HIP            = 0x8B, //!< Host Identity Protocol.
    RCDCAP_PROTOCOL_TYPE_Shim6          = 0x8C, //!< Site Multihoming by IPv6 Intermediation.
    RCDCAP_PROTOCOL_TYPE_WESP           = 0x8D, //!< Wrapped Encapsulating Security Payload.
    RCDCAP_PROTOCOL_TYPE_ROHC           = 0x8E  //!< Robust Header Compression.
};

//! The type that is used for representing an IPv4 address.
typedef std::array<uint8,  4>   ip_t;

//! The type that is used for representing an IPv6 address.
typedef std::array<NetworkByteOrder<uint16>, 8>   ip6_t;

//! The type that is used for representing an MAC address.
typedef std::array<uint8,  6>   mac_t;

bool IsMulticast(const ip_t& address);
bool IsBroadcast(const ip_t& address);
bool IsMulticast(const ip6_t& address);
bool IsBroadcast(const ip6_t& address);

#pragma pack(push, 1)
//! Specifies the fields in the Ethernet II header.
class MACHeader
{
//  uint8       m_Preamble;
    mac_t                                       m_DstMAC;       //!< The destination physical address.
    mac_t                                       m_SrcMAC;       //!< The source physical address.
    NetworkByteOrder<EtherType>                 m_EtherType;    //!< The protocol that is carried by a Ethernet frame.
public:
    //! Constructor.
    MACHeader();

    //! Returns the destination physical address.
    mac_t getDMacAddress() const;

    //! Returns the source physical address.
    mac_t getSMacAddress() const;

    //! Returns the protocol that is carried by a Ethernet frame.
    EtherType getEtherType() const;

    //! Sets the destination physical address to the one that is passed to this function.
    void setDMacAddress(const mac_t& mac);

    //! Sets the source physical address to the one that is passed to this function.
    void setSMacAddress(const mac_t& mac);

    //! Sets the identifier of the protocol that is carried by this Ethernet frame to the one that is passed to this function.
    void setEtherType(EtherType eth_type);
};

//! Specifies the fields in the IEEE 802.1Q Ethernet header.
class MACHeader802_1Q
{
//  uint8   m_Preamble;
    mac_t                                       m_DstMAC;       //!< The destination physical address.
    mac_t                                       m_SrcMAC;       //!< The source physical address.
    NetworkByteOrder<EtherType>                 m_TPID;         //!< The 802.1Q Tag Protocol Identifier.
    NetworkByteOrderBitfield<uint16, 3, 1, 12>  m_VLANTag;      //!< The variable that is holding the VLAN bit fields.
    NetworkByteOrder<EtherType>                 m_EtherType;    //!< The protocol that is carried by a Ethernet frame.
public:
    //! Constructor.
    MACHeader802_1Q();
    
    //! Returns the offset of the VLAN tag in the 802.1Q Ethernet header.
    static constexpr size_t getVLANTagOffset() { return offsetof(MACHeader802_1Q, m_TPID); }
    
    //! Returns the VLAN tag size in bytes.
    static constexpr size_t getVLANTagSize() { return 4; }
    
    //! Returns the 802.1Q priority field.
    uint8 getVLANPriority() const;
    
    //! Returns true if the 802.1Q canonical format indicator is set.
    bool getVLANCanonical() const;
    
    //! Returns the 802.1Q VLAN identifier.
    uint16 getVLANIdentifier() const;
    
    //! Returns destination physical address.
    mac_t getDMacAddress() const;
    
    //! Returns source physical address.
    mac_t getSMacAddress() const;
    
    //! Returns the protocol that is carried by a Ethernet frame.
    EtherType getEtherType() const;
    
    //! Sets the 802.1Q Tag Protocol Identifier to its default value.
    void setVLANTPID();
    
    //! Sets the priority to the one that is passed to this function.
    void setVLANPriority(uint8 pcp);
    
    //! Enables or disables the Canonical Format Indicator depending on the value that is passed to this function.
    void setVLANCanonical(bool cfi);
    
    //! Sets the VLAN Identifier to the one that is passed to this function.
    void setVLANIdentifier(uint16 vid);
    
    //! Sets the destination physical address to the one that is passed to this function.
    void setDMacAddress(const mac_t& mac);
    
    //! Sets the source physical address to the one that is passed to this function.
    void setSMacAddress(const mac_t& mac);
    
    //! Sets the identifier of the protocol that is carried by this Ethernet frame to the one that is passed to this function.
    void setEtherType(EtherType eth_type);
};

//! Specifies the fields in the IPv4 header.
class IPv4Header
{
    NetworkByteOrderBitfield<uint8, 4, 4>       m_IHL_Version;      //!< The variable that is holding the IP Header Length and the Version bit fields of the IPv4 header.
    NetworkByteOrder<uint8>                     m_TypeOfService;    //!< The Type of Service field of the IPv4 header.
    NetworkByteOrder<uint16>                    m_TotalLength;      //!< The Total Length field of the IPv4 header.
    NetworkByteOrder<uint16>                    m_Identification;   //!< The Identification field of the IPv4 header.
    NetworkByteOrderBitfield<uint16, 3, 13>     m_Flags_Fragment;   //!< The variable that is holding the flags and the fragmentation related bit fields of the IPv4 header.
    NetworkByteOrder<uint8>                     m_TTL;              //!< The TTL field of the IPv4 header.
    NetworkByteOrder<ProtocolType>              m_Protocol;         //!< The Protocol Type field of the IPv4 header.
    NetworkByteOrder<uint16>                    m_Checksum;         //!< The Checksum field of the IPv4 header.
    ip_t                                        m_SrcIP;            //!< The Source IP field of the IPv4 header.
    ip_t                                        m_DstIP;            //!< The Destination IP field of the IPv4 header.
public:
    //! Constructor.
    IPv4Header();

    //! Returns the value of the Version field of the IPv4 header.
    uint8 getVersion() const;

    //! Returns the value of the IP Header Length field of the IPv4 header.
    uint8 getIHL() const;

    //! Returns the value of the Total Length field of the IPv4 header.
    uint16 getTotalLength() const;

    //! Returns the value of the Identification field of the IPv4 header.
    uint16 getIdentification() const;

    //! Returns the values that are kept in the fragmentation part of the IPv4 header.
    uint16 getFragment() const;

    //! Returns the flags that are kept in the IPv4 header.
    uint8 getFlags() const;

    //! Returns the TTL field of the IPv4 header.
    uint8 getTTL() const;

    //! Returns the Protocol Type field of the IPv4 header.
    ProtocolType getProtocol() const;

    //! Returns the Checksum field of the IPv4 header.
    uint16 getChecksum() const;

    //! Returns the source IP field of the IPv4 header.
    ip_t getSourceIP() const;

    //! Returns the destination IP field of the IPv4 header.
    ip_t getDestinationIP() const;

    //! Sets the value of the Version field of the IPv4 header.
    void setVersion(uint8 ver);

    //! Sets the value of the IP Header Length field of the IPv4 header.
    void setIHL(uint8 ihl);

    //! Sets the value of the Total Length field of the IPv4 header.
    void setTotalLength(uint16 len);

    //! Sets the value of the Identification field of the IPv4 header.
    void setIdentification(uint16 id);

    //! Sets the values that are kept in the fragmentation part of the IPv4 header.
    void setFragment(uint16 fragment);

    //! Sets the flags that are kept in the IPv4 header.
    void setFlags(uint8 flags);

    //! Sets the TTL field of the IPv4 header.
    void setTTL(uint8 ttl);

    //! Sets the Protocol Type field of the IPv4 header.
    void setProtocol(ProtocolType protocol_type);

    //! Sets the Checksum field of the IPv4 header.
    void setChecksum(uint16 checksum);

    //! Sets the source IP field of the IPv4 header.
    void setSourceIP(const ip_t& src_ip);

    //! Sets the destination IP field of the IPv4 header.
    void setDestinationIP(const ip_t& dst_ip);
};

//! Specifies the fields in the IPv6 header.
class IPv6Header
{
    NetworkByteOrderBitfield<uint32, 4, 8, 20>  m_Ver_TC_FL;    //!< A variable that is holding some of the bit fields in the IPv6 header.
    NetworkByteOrder<uint16>                    m_Length;       //!< The Payload Length field of the IPv6 header.
    NetworkByteOrder<ProtocolType>              m_NextHeader;   //!< The Next Header field of the IPv6 header.
    NetworkByteOrder<uint8>                     m_HopLimit;     //!< The Hop Limit field of the IPv6 header.
    ip6_t                                       m_SrcIP;        //!< The Source IP field of the IPv6 header.
    ip6_t                                       m_DstIP;        //!< The Destination IP field of the IPv6 header.
public:
    //! Constructor.
    IPv6Header();

    //! Returns the value of the Version bit field of the IPv6 header.
    uint32 getVersion() const;

    //! Returns the value of the Traffic Class bit field of the IPv6 header.
    uint32 getTrafficClass() const;

    //! Returns the value of the Flow Label bit field of the IPv6 header.
    uint32 getFlowLabel() const;

    //! Returns the value of the Payload Length field of the IPv6 header.
    uint16 getPayloadLength() const;

    //! Returns the value of the Next Header field of the IPv6 header.
    ProtocolType getNextHeader() const;

    //! Returns the value of the Hop Limit field of the IPv6 header.
    uint8 getHopLimit() const;

    //! Returns the value of the source IP field of the IPv6 header.
    ip6_t getSourceIP() const;

    //! Returns the value of the destination IP field of the IPv6 header.
    ip6_t getDestinationIP() const;

    //! Sets the value of the Version bit field of the IPv6 header.
    void setVersion(uint32 ver);

    //! Sets the value of the Traffic Class bit field of the IPv6 header.
    void setTrafficClass(uint32 traffic_class);

    //! Sets the value of the Flow Label bit field of the IPv6 header.
    void setFlowLabel(uint32 flow_label);

    //! Sets the value of the Payload Length field of the IPv6 header.
    void setPayloadLength(uint16 payload_length);

    //! Sets the value of the Next Header field of the IPv6 header.
    void setNextHeader(ProtocolType protocol_type);

    //! Sets the value of the Hop Limit field of the IPv6 header.
    void setHopLimit(uint8 hop_limit);

    //! Sets the value of the source IP field of the IPv6 header.
    void setSourceIP(const ip6_t& src_ip);

    //! Sets the value of the destination IP field of the IPv6 header.
    void setDestinationIP(const ip6_t& dst_ip);
};

//! Specifies the types of ICMPv6 messages.
enum class ICMPv6MessageType
{
    RCDCAP_ICMPv6_DESTINATION_UNREACHABLE = 1,   //!< Notification about packet that can't be delivered.
    RCDCAP_ICMPv6_PACKET_TOO_BIG          = 2,   //!< Notification about packet that exceeds MTU.
    RCDCAP_ICMPv6_TIME_EXCEEDED           = 3,   //!< Notification about packet that has exceeded its hop limit.
    RCDCAP_ICMPv6_PARAMETER_PROBLEM       = 4,   //!< Notification about IPv6 packet that can't be processed.
    RCDCAP_ICMPv6_ECHO_REQUEST            = 128, //!< Ping message.
    RCDCAP_ICMPv6_ECHO_REPLY_MESSAGE      = 129, //!< Pong message.
    RCDCAP_ICMPv6_ROUTER_SOLICITATION     = 133, //!< Request for router advertisement information.
    RCDCAP_ICMPv6_ROUTER_ADVERTISEMENT    = 134, //!< Information about network prefixes.
    RCDCAP_ICMPv6_NEIGHBOR_SOLICITATION   = 135, //!< Query about a particular neighbor or the availability about particular address. 
    RCDCAP_ICMPv6_NEIGHBOR_ADVERTISEMNT   = 136, //!< Response to neighbor solicitation message or unsolicitated message about link-address change.
    RCDCAP_ICMPv6_REDIRECT_MESSAGE        = 137  //!< Information about better next hop.
};

//! Specifies the fields in the ICMPv6 header.
class ICMPv6Header
{
    NetworkByteOrder<ICMPv6MessageType>     m_Type;		//!< Indicates the type of message.
    NetworkByteOrder<uint8>                 m_Code;		//!< Type of message specific code that is used for finer granularity.
    NetworkByteOrder<uint16>                m_Checksum; //!< Used to detect data corruption.
public:
	//! Returns the type of ICMPv6 message.
    ICMPv6MessageType getType() const;

	//! Returns the code associated with this type of message.
    uint8 getCode() const;

	//! Returns the checksum.
    uint16 getChecksum() const;
    
	//! Sets the value of the message type field.
    void setType(ICMPv6MessageType _type);

	//! Sets the value of the message code field.
    void setCode(uint8 _code);

	//! Sets the checksum.
    void setChecksum(uint16 _checksum);
};

//! The part of the ICMPv6 packet that describes a Router Advertisement message.
class RouterAdvertisementHeader: public ICMPv6Header
{
    enum
    {
        BF_M_FLAG, //!< Managed Address Configuration Flag.
        BF_O_FLAG  //!< Other Configuration Flag.
    };
    
    //! Hop Count field.
    NetworkByteOrder<uint8>                  m_CurHopLimit;
    
    //! Compound bitfield representing the available flags.
    NetworkByteOrderBitfield<uint8, 1, 1, 6> m_Flags;
    
    //! The time of validity of the router.
    NetworkByteOrder<uint16>                 m_RouterLifetime;
    
    //! The time of validity of the reachability information.
    NetworkByteOrder<uint32>                 m_RechableTime;
    
    //! The time between of retransmission of Neighbor Solicitation.
    NetworkByteOrder<uint32>                 m_RetransTime;
public:
    //! Returns the current hop count.
    uint8 getCurHopLimit() const;
    
    //! Returns the value of the Managed flag.
    bool isManagedEnabled() const;
    
    //! Returns the value of the Other flag.
    bool isOtherEnabled() const;
    
    //! Returns the time of validity of the router.
    uint16 getRouterLifetime() const;
    
    //! Returns the time of validity of the reachability information.
    uint32 getRechableTime() const;
    
    //! Returns the time between retransmissions of NS messages.
    uint32 getRetransTime() const;
    
    //! Sets the current hop count.
    void setCurHopLimit(uint8 hop_limit);
    
    //! Sets the Managed flag.
    void setManaged(bool is_enabled);
    
    //! Sets the Other flag.
    void setOther(bool is_enabled);
    
    //! Sets the time of validity of the particular router.
    void setRouterLifetime(uint16 lifetime);
    
    //! Sets the time of validity of reachability information.
    void setRechableTime(uint32 reachable);
    
    //! Sets the retransmission time.
    void setRetransTime(uint32 retrans);
};

//! The part of the ICMPv6 packet that describes a Neighbor Advertisement message.
class NeighborAdvertisementHeader: public ICMPv6Header
{
    enum
    {
        ROUTER_FLAG,    //!< Indicates that the sender is a router.
        SOLICITED_FLAG, //!< Indicates response to Neighbor Solicitation.
        OVERRIDE_FLAG   //!< Indicates that it should override existing cache entry.
    };
    
    //!
    NetworkByteOrderBitfield<uint32, 1, 1, 1, 29> m_RSO;
    
    //! The Target Address in the Neighbor Solicitation message that prompted this advertisement.
    ip6_t                                         m_TargetAddress;
public:
    //! Returns whether the sender is a router.
    bool getRouterFlag() const;
    
    //! Returns whether this message is in response to Neighbor Solicitation.
    bool getSolicitedFlag() const;
    
    //! Returns whether existing cache entry should be overriden.
    bool getOverrideFlag() const;
    
    //! Returns the Target Address in the Neighbor Solicitation message that prompted this advertisement.
    ip6_t getTargetAddress() const;
    
    //! Sets whether the sender is a router.
    void setRouterFlag(bool flag);
    
    //! Sets whether this message is in response to Neighbor Solicitation.
    void setSolicitedFlag(bool flag);
    
    //! Sets whether existing cache entry should be overriden.
    void setOverrideFlag(bool flag);
    
    //! Sets the Target Address which was entered in the Neighbor Solicitation message that prompted this advertisement.
    void setTargetAddress(const ip6_t& _ip);
};

//! Describes the available NDP options.
enum class NDPOption : uint8
{
    SOURCE_LINK_LAYER_ADDRESS             = 1,  //!< Source Link-layer Address             [RFC4861]
    TARGET_LINK_LAYER_ADDRESS             = 2,  //!< Target Link-layer Address             [RFC4861]
    PREFIX_INFORMATION                    = 3,  //!< Prefix Information                    [RFC4861]
    REDIRECTED_HEADER                     = 4,  //!< Redirected Header                     [RFC4861]
    MTU                                   = 5,  //!< Message Transfer Unit                 [RFC4861]
    NBMA_SHORTCUT_LIMIT                   = 6,  //!< NBMA Shortcut Limit                   [RFC2491]
    ADVERTISEMENT_INTERVAL                = 7,  //!< Advertisement Interval                [RFC6275]
    HOME_AGENT_INFORMATION                = 8,  //!< Home Agent Information                [RFC6275]
    SOURCE_ADDRESS_LIST                   = 9,  //!< Source Address List                   [RFC3122]
    TARGET_ADDRESS_LIST                   = 10, //!< Target Address List                   [RFC3122]
    CGA_OPTION                            = 11, //!< Cryptographically Generated Addresses [RFC3971]
    RSA_SIGNATURE                         = 12, //!< Rivest-Shamir-Adleman (RSA) Signature [RFC3971]
    TIMESTAMP                             = 13, //!< Timestamp                             [RFC3971]
    NONCE                                 = 14, //!< Nonce                                 [RFC3971]
    TRUST_ANCHOR                          = 15, //!< Trust Anchor                          [RFC3971]
    CERTIFICATION                         = 16, //!< Certificate                           [RFC3971]
    IP_ADDRESS_PREFIX                     = 17, //!< IP Address/Prefix                     [RFC5568]
    NEW_ROUTER_PREFIX_INFORMATION         = 18, //!< New Router Prefix Information         [RFC4068]
    LINK_LAYER_ADDRESS                    = 19, //!< Link-layer Address                    [RFC5568]
    NEIGHBOR_ADVERTISEMENT_ACKNOWLEDGMENT = 20, //!< Neighbor Advertisement Acknowledgment [RFC5568]
    MAP                                   = 23, //!< Mobility Anchor Point                 [RFC4140]
    ROUTE_INFORMATION                     = 24, //!< Route Information                     [RFC4191]
    RECURSIVE_DNS_SERVER                  = 25, //!< Recursive DNS Server                  [RFC5006][RFC6106]
    RA_FLAGS_EXTENSION                    = 26, //!< Router Advertisement Flags Extension  [RFC5175]
    HANDOVER_KEY_REQUEST                  = 27, //!< Handover Key Request                  [RFC5269]
    HANDOVER_KEY_REPLY                    = 28, //!< Handover Key Reply                    [RFC5269]
    HANDOVER_ASSIST_INFORMATION           = 29, //!< Handover Assist Information           [RFC5271]
    MOBILE_NODE_IDENTIFIER                = 30, //!< Mobile Node Identifier                [RFC5271]
    DNS_SEARCH_LIST                       = 31, //!< DNS Search List                       [RFC6106]
    PROXY_SIGNATURE                       = 32, //!< Proxy Signature (PS)                  [RFC6496]
    ADDRESS_REGISTRATION                  = 33, //!< Address Registration                  [RFC6775]
    SIXLoWPAN_CONTEXT                     = 34, //!< 6LoWPAN Context                       [RFC6775]
    AUTHORITATIVE_BORDER_ROUTER           = 35, //!< Authoritative Border Router           [RFC6775]
    CARD_REQUEST                          = 138, //!< Candidate Access Router Discovery (CARD) Request [RFC4065]
    CARD_REPLY                            = 139  //!< Candidate Access Router Discovery (CARD) Reply   [RFC4065]
};


class NDPOptionField
{
    NetworkByteOrder<NDPOption>             m_Type;
    NetworkByteOrder<uint8>                 m_Length;
    NetworkByteOrder<uint16>                m_Reserved;
public:
    NDPOption getType() const { return m_Type; }
    uint8 getLength() const { return m_Length; }

    void setType(NDPOption val) { m_Type = val; }
    void setLength(uint8 len) { m_Length = len; }
};


class RDNSSOption: public NDPOptionField
{
    NetworkByteOrder<uint32>                m_Lifetime;
public:
    uint32 getLifetime() const { return m_Lifetime; }
    
    void setLifetime(uint32 lifetime) { m_Lifetime = lifetime; }
};

//! Specifies the fields in the UDP header.
class UDPHeader
{
    NetworkByteOrder<uint16>                m_SrcPort;      //!< The Source Port field of the UDP header.
    NetworkByteOrder<uint16>                m_DstPort;      //!< The Destination Port field of the UDP header.
    NetworkByteOrder<uint16>                m_Length;       //!< The Length field of the UDP header.
    NetworkByteOrder<uint16>                m_Checksum;     //!< The Checksum field of the UDP header.
public:
    //! Returns the value of the source port field of the UDP header.
    uint16 getSourcePort() const;

    //! Returns the value of the destination port field of the UDP header.
    uint16 getDestinationPort() const;

    //! Returns the value of the Length field of the UDP header.
    uint16 getLength() const;

    //! Returns the value of the Checksum field of the UDP header.
    uint16 getChecksum() const;

    //! Sets the value of the source port field of the UDP header.
    void setSourcePort(uint16 src_port);

    //! Sets the value of the destination port field of the UDP header.
    void setDestinationPort(uint16 dst_port);

    //! Sets the value of the Length field of the UDP header.
    void setLength(uint16 len);

    //! Sets the value of the Checksum field of the UDP header.
    void setChecksum(uint16 checksum);
};

//! List the ARP message types.
enum class ARPOpcode: uint16
{
    RCDCAP_ARP_RESERVED                 = 0x00, //!< Reserved (RFC 5494).
    RCDCAP_ARP_REQUEST                  = 0x01, //!< Request (RFC 826, RFC 5227).
    RCDCAP_ARP_REPLY                    = 0x02, //!< Reply (RFC 826, RFC 1868, RFC 5227).
    RCDCAP_ARP_REQUEST_RESERVE          = 0x03, //!< Request Reverse (RFC 903).
    RCDCAP_ARP_REPLY_RESERVE            = 0x04, //!< Reply Reverse (RFC 903) .
    RCDCAP_ARP_DRARP_REQUEST            = 0x05, //!< DRARP Request (RFC 1931).
    RCDCAP_ARP_DRARP_REPLY              = 0x06, //!< DRARP Reply (RFC 1931).
    RCDCAP_ARP_DRARP_ERROR              = 0x07, //!< DRARP Error (RFC 1931).
    RCDCAP_ARP_inARP_REQUEST            = 0x08, //!< InARP Request (RFC 1293).
    RCDCAP_ARP_inARP_REPLY              = 0x09, //!< InARP Reply (RFC 1293).
    RCDCAP_ARP_NAK                      = 0x0a, //!< ARP NAK (RFC 1577).
    RCDCAP_ARP_MARS_REQUEST             = 0x0b, //!< MARS Request.
    RCDCAP_ARP_MARS_MULTI               = 0x0c, //!< MARS Multi.
    RCDCAP_ARP_MARS_MSERV               = 0x0d, //!< MARS MServ.
    RCDCAP_ARP_MARS_JOIN                = 0x0e, //!< MARS Join.
    RCDCAP_ARP_MARS_LEAVE               = 0x0f, //!< MARS Leave.
    RCDCAP_ARP_MARS_NAK                 = 0x10, //!< MARS NAK.
    RCDCAP_ARP_MARS_UNSERV              = 0x11, //!< MARS Unserv.
    RCDCAP_ARP_MARS_SJOIN               = 0x12, //!< MARS SJoin.
    RCDCAP_ARP_MARS_SLEAVE              = 0x13, //!< MARS SLeave.
    RCDCAP_ARP_MARS_GROUPLIST_REQUEST   = 0x14, //!< MARS Grouplist Request.
    RCDCAP_ARP_MARS_GROUPLIST_REPLY     = 0x15, //!< MARS Grouplist Reply.
    RCDCAP_ARP_MARS_REDIRECT_MAP        = 0x16, //!< MARS Redirect Map.
    RCDCAP_MAPOS_UNARP                  = 0x17, //!< MAPOS UNARP (RFC 2176).
    RCDCAP_ARP_OP_EXP1                  = 0x18, //!< OP_EXP1 (RFC 5494).
    RCDCAP_ARP_OP_EXP2                  = 0x19  //!< OP_EXP2 (RFC 5494).
};

//! List of the Layer 2 protocols which can be specified in ARP's "Hardware Type" field.
enum class ARPHardwareType: uint16
{
    RCDCAP_ARP_HW_Reserved1    = 0x00, //!< Reserved.
    RCDCAP_ARP_HW_Ethernet     = 0x01, //!< Ethernet.
    RCDCAP_ARP_HW_EXP_Ethernet = 0x02, //!< Experimental Ethernet.
    RCDCAP_ARP_HW_AX25         = 0x03, //!< Amateur Radio AX.25.
    RCDCAP_ARP_HW_PRONET       = 0x04, //!< Proteon ProNET Token Ring.
    RCDCAP_ARP_HW_CHAOS        = 0x05, //!< Chaos.
    RCDCAP_ARP_HW_IEEE802      = 0x06, //!< IEEE 802.
    RCDCAP_ARP_HW_ARCNET       = 0x07, //!< ARCNET.
    RCDCAP_ARP_HW_Hyperchannel = 0x08, //!< Hyperchannel.
    RCDCAP_ARP_HW_Lanstar      = 0x09, //!< Lanstar.
    RCDCAP_ARP_HW_ASA          = 0x0a, //!< Autonet Short Address.
    RCDCAP_ARP_HW_LocalTalk    = 0x0b, //!< LocalTalk.
    RCDCAP_ARP_HW_LocalNet     = 0x0c, //!< LocalNet (IBM PCNet or SYTEK LocalNET).
    RCDCAP_ARP_HW_UltraLink    = 0x0d, //!< Ultra link.
    RCDCAP_ARP_HW_SMDS         = 0x0e, //!< SMDS.
    RCDCAP_ARP_HW_FrameRelay   = 0x0f, //!< Frame Relay.
    RCDCAP_ARP_HW_ATM1         = 0x10, //!< ATM, Asynchronous Transmission Mode.
    RCDCAP_ARP_HW_HDLC         = 0x11, //!< HDLC.
    RCDCAP_ARP_HW_FibreChannel = 0x12, //!< Fibre Channel (RFC 4338).
    RCDCAP_ARP_HW_ATM2         = 0x13, //!< ATM, Asynchronous Transmission Mode (RFC 2225).
    RCDCAP_ARP_HW_SerialLine   = 0x14, //!< Serial Line.
    RCDCAP_ARP_HW_ATM3         = 0x15, //!< ATM, Asynchronous Transmission Mode.
    RCDCAP_ARP_HW_MIL          = 0x16, //!< MIL-STD-188-220.
    RCDCAP_ARP_HW_Metricom     = 0x17, //!< Metricom.
    RCDCAP_ARP_HW_IEEE1394     = 0x18, //!< IEEE 1394.1995.
    RCDCAP_ARP_HW_MAPOS        = 0x19, //!< MAPOS.
    RCDCAP_ARP_HW_Twinaxial    = 0x1a, //!< Twinaxial.
    RCDCAP_ARP_HW_EUI64        = 0x1b, //!< EUI-64.
    RCDCAP_ARP_HW_HIPARP       = 0x1c, //!< HIPARP (RFC 2834, RFC 2835).
    RCDCAP_ARP_HW_IPARPoverISO = 0x1d, //!< IP and ARP over ISO 7816-3.
    RCDCAP_ARP_HW_ARPSec       = 0x1e, //!< ARPSec.
    RCDCAP_ARP_HW_IPsec        = 0x1f, //!< IPsec tunnel (RFC 3456).
    RCDCAP_ARP_HW_Infiniband   = 0x20, //!< Infiniband (RFC 4391).
    RCDCAP_ARP_HW_CAI          = 0x21, //!< CAI, TIA-102 Project 25 Common Air Interface.
    RCDCAP_ARP_HW_Wiegand      = 0x22, //!< Wiegand Interface.
    RCDCAP_ARP_HW_PureIP       = 0x23, //!< Pure IP.
    RCDCAP_ARP_HW_EXP1         = 0x24, //!< HW_EXP1 (RFC 5494).
    RCDCAP_ARP_HW_EXP2         = 0x100, //!< HW_EXP2 (RFC 5494).
    RCDCAP_ARP_HW_Reserved2    = 0xFFFF //!< Reserved.
};

//! Describes the fields inside the ARP header.
class ARPHeader
{
    NetworkByteOrder<ARPHardwareType> m_HardwareType;          //!< The Layer 2 protocol.
    NetworkByteOrder<EtherType>       m_ProtocolType;          //!< The Layer 3 protocol.
    NetworkByteOrder<uint8>           m_HardwareAddressLength; //!< The size of address used by the Layer 2 frame.
    NetworkByteOrder<uint8>           m_ProtocolAddressLength; //!< The size of address used by the Layer 3 packet.
    NetworkByteOrder<ARPOpcode>       m_Opcode;                //!< The type of the ARP message.
public:
    //! Returns the type of the Layer 2 protocol.
    ARPHardwareType getHardwareType() const;
    
    //! Returns the type of the Layer 3 protocol.
    EtherType getProtocolType() const;
    
    //! Returns the Layer 2 address length.
    uint8 getHardwareAddressLength() const;
    
    //! Returns the Layer 3 address length.
    uint8 getProtocolAddressLength() const;
    
    //! Returns the type of the ARP message.
    ARPOpcode getOpcode() const;

    //! Sets the type of the Layer 2 protocol.
    void setHardwareType(ARPHardwareType hw_type);

    //! Sets the type of the Layer 3 protocol.
    void setProtocolType(EtherType proto_type);

    //! Sets the Layer 2 address length.
    void setHardwareAddressLength(uint8 hw_addr);

    //! Sets the Layer 3 address length.
    void setProtocolAddressLength(uint8 proto_addr);

    //! Sets the type of the ARP message.
    void setOpcode(ARPOpcode opcode);
};

//! Describes the hardware and protocol address fields inside an IPv4 ARP Reply packet.
class ARPIPv4ReplyFields
{
    mac_t           m_SrcMAC; //!< Represents the source hardware address.
    ip_t            m_SrcIP;  //!< Represents the source protocol address.
    mac_t           m_DstMAC; //!< Represents the destination hardware address.
    ip_t            m_DstIP;  //!< Represents the source protocol address.
public:
    //! Returns the source hardware address.
    mac_t getSourceHardwareAddress() const;

    //! Returns the source protocol address.
    ip_t getSourceProtocolAddress() const;

    //! Returns the destination hardware address.
    mac_t getDestinationHardwareAddress() const;

    //! Returns the destination protocol address.
    ip_t getDestinationProtocolAddress() const;

    //! Sets the source hardware address.
    void setSourceHardwareAddress(const mac_t& src);

    //! Sets the source protocol address.
    void setSourceProtocolAddress(const ip_t& src);

    //! Sets the destination hardware address.
    void setDestinationHardwareAddress(const mac_t& dst);

    //! Sets the destination protocol address.
    void setDestinationProtocolAddress(const ip_t& dst);
};

//! Describes the hardware and protocol address fields inside an IPv4 ARP Request packet.
class ARPIPv4RequestFields
{
    mac_t           m_SrcMAC; //!< Represents the hardware source address.
    ip_t            m_SrcIP;  //!< Represents the protocol source address.
public:
    //! Returns the source hardware address.
    mac_t getSourceHardwareAddress() const;

    //! Returns the source protocol address.
    ip_t getSourceProtocolAddress() const;

    //! Sets the source hardware address.
    void setSourceHardwareAddress(const mac_t& src);

    //! Sets the source protocol address.
    void setSourceProtocolAddress(const ip_t& src);
};

class DHCPHeader
{
    NetworkByteOrder<uint8>     m_Op;
    NetworkByteOrder<uint8>     m_HType;
    NetworkByteOrder<uint8>     m_HLen;
    NetworkByteOrder<uint8>     m_Hops;
    NetworkByteOrder<uint32>    m_XID;
    NetworkByteOrder<uint16>    m_Secs;
    NetworkByteOrder<uint16>    m_Flags;
    ip_t                        m_CiAddr;
    ip_t                        m_YiAddr;
    ip_t                        m_SiAddr;
    ip_t                        m_GiAddr;
    std::array<uint8, 16>       m_ChAddr;
    std::array<int8, 64>        m_SName;
    std::array<int8, 128>       m_File;
public:
    uint8 getOpcode() const { return m_Op; }
    uint8 getHType() const { return m_HType; }
    uint8 getHLen() const { return m_HLen; }
    uint8 getHops() const { return m_Hops; }
    uint32 getXID() const { return m_XID; }
    uint16 getSecs() const { return m_Secs; }
    uint16 getFlags() const { return m_Flags; }
    ip_t getCiAddr() const { return m_CiAddr; }
    ip_t getYiAddr() const { return m_YiAddr; }
    ip_t getSiAddr() const { return m_SiAddr; }
    ip_t getGiAddr() const { return m_GiAddr; }
    const uint8* getChAddr() const { return &m_ChAddr.front(); }
    const int8* getSName() const { return &m_SName.front(); }
    const int8* getFile() const { return &m_File.front(); }
    
    void setOpcode(uint8 op) { m_Op = op; }
    void setHType(uint8 htype) { m_HType = htype; }
    void setHLen(uint8 hlen) { m_HLen = hlen; }
    void setHops(uint8 hops) { m_Hops = hops; }
    void setXID(uint32 xid) { m_XID = xid; }
    void setSecs(uint16 secs) { m_Secs = secs; }
    void setFlags(uint16 flags) { m_Flags = flags; }
    void setCiAddr(ip_t ciaddr) { m_CiAddr = ciaddr; }
    void setViAddr(ip_t yiaddr) { m_YiAddr = yiaddr; }
    void setSiAddr(ip_t siaddr) { m_SiAddr = siaddr; }
    void setGiAddr(ip_t giaddr) { m_GiAddr = giaddr; }
    void setChAddr(uint8* chaddr) { std::copy(chaddr, chaddr + m_ChAddr.size(), m_ChAddr.begin()); }
    void setSName(int8* sname) { std::copy(sname, sname + m_SName.size(), m_SName.begin()); }
    void setFile(int8* _file) { std::copy(_file, _file + m_File.size(), m_File.begin()); }
};

constexpr uint32 DHCPMagicCookie1 = (99 << 24) | (83 << 16) | (130 << 8) | (99);
constexpr uint32 DHCPMagicCookie2 = (63 << 24) | (53 << 16) | (82 << 8)  | (63);

enum class DHCPOptionTag : uint8
{
    PAD_OPTION                              = 0,
    SUBNET_MASK_OPTION                      = 1,
    TIME_OFFSET_OPTION                      = 2,
    ROUTER_OPTION                           = 3,
    TIME_SERVER_OPTION                      = 4,
    NAME_SERVER_OPTION                      = 5,
    DNS_OPTION                              = 6,
    LOG_SERVER_OPTION                       = 7,
    COOKIE_SERVER_OPTION                    = 8,
    LPR_SERVER_OPTION                       = 9,
    IMPRESS_SERVER_OPTION                   = 10,
    RESOURCE_LOCATION_SERVER_OPTION         = 11,
    HOST_NAME_OPTION                        = 12,
    BOOT_FILE_SIZE_OPTION                   = 13,
    MERIT_DUMP_FILE_OPTION                  = 14,
    DOMAIN_NAME_OPTION                      = 15,
    SWAP_SERVER_OPTION                      = 16,
    ROOT_PATH_OPTION                        = 17,
    EXTENSIONS_PATH_OPTION                  = 18,
    IP_FORWARDING_OPTION                    = 19,
    NON_LOCAL_SOURCE_ROUTING_OPTION         = 20,
    POLICY_FILTER_OPTION                    = 21,
    MAXIMUM_DATAGRAM_REASSEMBLY_SIZE        = 22,
    DEFAULT_IP_TIME_TO_LIVE                 = 23,
    PATH_MTU_AGING_TIMEOUT_OPTION           = 24,
    PATH_MTU_PLATEAU_TABLE_OPTION           = 25,
    INTERFACE_MTU_OPTION                    = 26,
    ALL_SUBNETS_ARE_LOCAL_OPTION            = 27,
    BROADCAST_ADDRESS_OPTION                = 28,
    PERFORMANCE_MASK_DISCOVERY_OPTION       = 29,
    MASK_SUPPLIER_OPTION                    = 30,
    PERFORM_ROUTER_DISCOVERY_OPTION         = 31,
    ROUTER_SOLICITATION_ADDRESS_OPTION      = 32,
    STATIC_ROUTE_OPTION                     = 33,
    LINK_LAYER_PARAMETERS_OPTION            = 34,
    ARP_CACHE_TIMEOUT_OPTION                = 35,
    ETHERNET_ENCAPSULATION_OPTION           = 36,
    TCP_DEFAULT_TTL_OPTION                  = 37,
    TCP_KEEPALIVE_INTERNAL_OPTION           = 38,
    TCP_KEEPALIVE_GARBAGE_OPTION            = 39,
    NIS_DOMAIN_OPTION                       = 40,
    NIS_OPTION                              = 41,
    NTP_SERVERS_OPTION                      = 42,
    VENDOR_SPECIFIC_INFORMATION_OPTION      = 43,
    NETBIOS_OVER_TCP_IP_NAME_SERVER_OPTION  = 44,
    NETBIOS_OVER_TCP_IP_DDS_OPTION          = 45,
    NETBIOS_OVER_TCP_IP_NODE_TYPE           = 46,
    NETBIOS_OVER_TCP_IP_SCOPE_OPTION        = 47,
    X_WINDOW_FONT_SERVER_OPTION             = 48,
    X_WINDOW_SYSTEM_DISPLAY_MANAGER_OPTION  = 49,
    REQUESTED_IP_ADDRESS_OPTION             = 50,
    IP_ADDRESS_LEASE_TIME_OPTION            = 51,
    OPTION_OVERLOAD                         = 52,
    DHCP_MESSAGE_TYPE_OPTION                = 53,
    SERVER_IDENTIFIER_OPTION                = 54,
    PARAMETER_REQUEST_LIST_OPTION           = 55,
    MESSAGE_OPTION                          = 56,
    MAXIMUM_DHCP_MESSAGE_SIZE_OPTION        = 57,
    REWEVAL_T1_VALUE_NAME_OPTION            = 58,
    REBINDING_T2_TIME_VALUE_OPTION          = 59,
    VENDOR_CLASS_IDENTIFIER_OPTION          = 60,
    CLIENT_IDENTIFIER_OPTION                = 61,
    NISP_DOMAIN_OPTION                      = 64,
    NISP_SERVERS_OPTION                     = 65,
    TFTP_SERVER_NAME_OPTION                 = 66,
    BOOTFILE_NAME_OPTION                    = 67,
    MOBILE_IP_HOME_AGENT_OPTION             = 68,
    SMTP_SERVER_OPTION                      = 69,
    POP3_SERVER_OPTION                      = 70,
    NNTP_SERVER_OPTION                      = 71,
    DEFAULT_WWW_SERVER_OPTION               = 72,
    DEFAULT_FINGER_SERVER_OPTION            = 73,
    DEFAULT_IRC_SERVER_OPTION               = 74,
    STREETTALK_SERVER_OPTION                = 75,
    STDA_SERVER_OPTION                      = 76,
    OPTION_PANA_AGENT                       = 136,
    END_OPTION                              = 255
};

enum class DHCPMessageType : uint8
{
    DHCPDISCOVER = 1,
    DHCPOFFER = 2,
    DHCPREQUEST = 3,
    DHCPDECLINE = 4,
    DHCPACK = 5,
    DHCPNAK = 6,
    DHCPRELEASE = 7,
    DHCPINFORM = 8
};

//! That's for options that are longer than a single octet
class DHCPOptionField
{
    NetworkByteOrder<DHCPOptionTag>   m_Tag;
    NetworkByteOrder<uint8>           m_Length;
public:
    DHCPOptionTag getTag() const { return m_Tag; }
    uint8 getLength() const { return m_Length; }
    
    void setTag(DHCPOptionTag _tag) { m_Tag = _tag; }
    void setLength(uint8 len) { m_Length = len; }
};

enum class DHCPv6MessageType : uint8
{
    SOLICIT             = 1,
    ADVERTISE           = 2,
    REQUEST             = 3,
    CONFIRM             = 4,
    RENEW               = 5,
    REBIND              = 6,
    REPLY               = 7,
    RELEASE             = 8,
    DECLINE             = 9,
    RECONFIGURE         = 10,
    INFORMATION_REQUEST = 11,
    RELAY_FORW          = 12,
    RELAY_REPL          = 13
};

class DHCPv6Header
{
	enum
	{
		BF_MESSAGE_TYPE,
		BF_TRANSACTION_ID
	};
	
	NetworkByteOrderBitfield<uint32, 8, 24> m_Type_Transaction;
public:
	DHCPv6MessageType getType() const { return static_cast<DHCPv6MessageType>(m_Type_Transaction.get<BF_MESSAGE_TYPE>()); }
	uint32 getTransactionId() const { return m_Type_Transaction.get<BF_TRANSACTION_ID>(); }
	
	void setType(DHCPv6MessageType _type) { m_Type_Transaction.set<BF_MESSAGE_TYPE>(static_cast<uint32>(_type)); }
	void setTransactionId(uint32 trans_id) { m_Type_Transaction.set<BF_TRANSACTION_ID>(trans_id); }
};

enum class DHCPv6OptionCode : uint16
{
    OPTION_CLIENTID         = 1,
    OPTION_SERVERID         = 2,
    OPTION_IA_NA            = 3,
    OPTION_IA_TA            = 4,
    OPTION_IAADDR           = 5,
    OPTION_ORO              = 6,
    OPTION_PREFERENCE       = 7,
    OPTION_ELAPSED_TIME     = 8,
    OPTION_RELAY_MSG        = 9,
    OPTION_AUTH             = 11,
    OPTION_UNICAST          = 12,
    OPTION_STATUS_CODE      = 13,
    OPTION_RAPID_COMMIT     = 14,
    OPTION_USER_CLASS       = 15,
    OPTION_VENDOR_CLASS     = 16,
    OPTION_VENDOR_OPTS      = 17,
    OPTION_INTERFACE_ID     = 18,
    OPTION_RECONF_MSG       = 19,
    OPTION_RECONF_ACCEPT    = 20,
    OPTION_SIP_SERVER_D     = 21,
    OPTION_SIP_SERVER_A     = 22,
    OPTION_DNS_SERVERS      = 23,
    OPTION_DOMAIN_LIST      = 24,
    OPTION_IA_PD            = 25,
    OPTION_IAPREFIX         = 26,
    OPTION_NIS_SERVERS      = 27,
    OPTION_NISP_SERVERS     = 28,
    OPTION_NIS_DOMAIN_NAME  = 29,
    OPTION_NISP_DOMAIN_NAME = 30,
    OPTION_SNTP_SERVERS     = 31,
    OPTION_INFORMATION_REFRESH_TIME = 32,
    OPTION_BCMCS_SERVER_D   = 33,
    OPTION_BCMCS_SERVER_A   = 34,
    OPTION_REMOTE_ID        = 37,
    OPTION_SUBSCRIBER_ID    = 38,
    OPTION_CLIENT_FQDN      = 39,
    OPTION_PANA_AGENT       = 40,
    OPTION_ERO              = 43,
    OPTION_LQ_QUERY         = 44,
    OPTION_CLIENT_DATA      = 45,
    OPTION_CLT_TIME         = 46,
    OPTION_LQ_RELAY_DATA    = 47,
    OPTION_LQ_CLIENT_LINK   = 48,
    OPT_BOOTFILE_URL        = 59,
    OPT_BOOTFILE_PARAM      = 60,
    OPTION_CLIENT_ARCH_TYPE = 61,
    OPTION_NII              = 62,
    OPTION_PD_EXCLUDE       = 67,
    OPTION_VSS              = 68,
    OPTION_CLIENT_LINKLAYER_ADDR = 79,
    OPTION_RADIUS           = 81
};

class DHCPv6OptionField
{
    NetworkByteOrder<DHCPv6OptionCode>  m_Option;
    NetworkByteOrder<uint16>            m_Length;
public:
    DHCPv6OptionCode getOptionCode() const { return m_Option; }
    uint16 getLength() const { return m_Length; }
    
    void setOptionCode(DHCPv6OptionCode option_code) { m_Option = option_code; }
    void setLength(uint16 len) { m_Length = len; }
};

#pragma pack(pop)
}

// HACK ! HACK ! HACK ! HACK ! HACK ! HACK ! HACK ! HACK !
namespace std
{
//! Prints the IPv4 address in text format to the output stream that is passed to this function.
DLL_EXPORT std::ostream& operator<<(std::ostream& out, const RCDCap::ip_t& ip);

//! Prints the IPv6 address in text format to the output stream that is passed to this function.
DLL_EXPORT std::ostream& operator<<(std::ostream& out, const RCDCap::ip6_t& ip);

//! Prints the physical address in text format to the output stream that is passed to this function.
DLL_EXPORT std::ostream& operator<<(std::ostream& out, const RCDCap::mac_t& mac);
    
DLL_EXPORT std::istream& operator>>(std::istream& in, RCDCap::ip_t& ip);

DLL_EXPORT std::istream& operator>>(std::istream& in, RCDCap::ip6_t& ip);

DLL_EXPORT std::istream& operator>>(std::istream& in, RCDCap::mac_t& ip);
}
// HACK ! HACK ! HACK ! HACK ! HACK ! HACK ! HACK ! HACK !

#endif /* _RCDCAP_PACKET_HEADERS_HH_ */