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

#ifndef _QN_DHCP_MONITOR_HH_
#define _QN_DHCP_MONITOR_HH_

#include "rcdcap/processor.hh"
#include "quiet-neighborhood.hh"
#include "network-cache.hh"

#include <unordered_map>

#include <boost/property_tree/ptree.hpp>

/*! \brief The traffic processor object of the extension Quiet Neighborhood.
 * 
 *  It splits the traffic and analyses the protocol headers for information
 *  which is being stored in the network cache. Also, it reports information
 *  about any suspicious activity performed after the learning phase.
 */
class QuietNeighborhoodMonitor: public RCDCap::Processor
{
    //! A reference to the Boost.ASIO I/O Service.
    boost::asio::io_service&    m_IOService;
    //! A reference to the data source inside RCDCap's pipeline.
    RCDCap::DataSource&         m_DataSource;
    
    //! The current state: learning or monitoring.
    MonitorState                m_State;
    
    int                         m_DHCPServerPort,   //!< The port which is being monitored for DHCP client requests.
                                m_DHCPClientPort,   //!< The port which is being monitored for DHCP server requests.
                                m_DHCPv6ServerPort, //!< The port which is being monitored for DHCPv6 client requests.
                                m_DHCPv6ClientPort; //!< The port which is being monitored for DHCPv6 server requests.
    
    boost::asio::deadline_timer m_StateSwitchTimer; /*!< Timer which determines when the pipeline is going to switch
                                                     *   from learning to monitoring phase.
                                                     */

    CacheFormat                 m_NetworkCacheFormat; //!< The format used when doing persistent storage of the network cache entries.
    std::string                 m_CacheFile;          //!< The cache file used for persistent storage of the network cache of the legitimate entries.
    std::string                 m_SuspiciousHostsCacheFile; //!< The cache file used for persistent storage of the network cache of the suspicious entries.
    NetworkCache                m_NetworkCache;       //!< The object used for storage of the network cache.
    
public:
    /*! \brief Constructor.
     *  \param io_service       a reference to the Boost.ASIO I/O Service.
     *  \param src              a reference to the data source inside RCDCap's
     *                          pipeline.
     *  \param opts             a reference to some options that determine the
     *                          pool size and the general behavior of the monitor
     *                          processor.
     */
    QuietNeighborhoodMonitor(boost::asio::io_service& io_service,
                             RCDCap::DataSource& src,
                             const QuietNeighborhoodOptions& opts);
    
    //! Destructor.
    virtual ~QuietNeighborhoodMonitor();
    
    /*! \brief Notifies the processor about new data.
     * 
     *  The actual processing is not done within this function because it is
     *  quite expensive. It is done in separate task which executes
     *  QuietNeighborhoodMonitor::process.
     * 
     *  \param packet_info  a pointer to the information about the first packet.
     *  \param packets      how many packets are part of this burst.
     */
    virtual void notify(RCDCap::PacketInfo* packet_info, size_t packets) override;
private:
    /*! \brief Processes a burst of packets.
     * 
     *  The actual processing function is QuietNeighborhoodMonitor::processImpl. This function does demultiplexing of packet bursts
     *  and handing the information to the next element of the pipeline.
     * 
     *  \param packet_info  a pointer to the information about the first packet.
     *  \param packets      how many packets are part of this burst.
     */
    void process(RCDCap::PacketInfo* packet_info, size_t packets);
    
    /*! \brief Performs per packet processing and traffic splitting.
     * 
     *  The actual traffic is split by type and then handed to correct function. The traffic is first split by protocol type:
     *  IPv4, IPv6 and ARP. The ARP traffic is directly handed to QuietNeighborhoodMonitor::processARP. The IPv4 traffic is
     *  handed to QuietNeighborhoodMonitor::processDHCP only if it is UDP traffic. The same principle is used for DHCPv6. The
     *  ICMPv6 traffic is directly handed to QuietNeighborhoodMonitor::processNDP.
     * 
     *  \param packet_info  a pointer to the information about the currently processed packet.
     */
    void processImpl(RCDCap::PacketInfo* packet_info);
    
    /*! \brief Switches from learning to monitoring phase.
     *  
     *  This function is called by asynchronous task which is waiting on the QuietNeighborhoodMonitor::m_StateSwitchTimer timer.
     *  During the transition this function saves the current state, so that it is preserved even if the application crashes
     *  or gets killed.
     */
    void transitionToAlertState();
    
    /*! \brief Processes DHCP option field related to a advertised network service.
     * 
     *  \param vlan             a pointer to the VLAN entry.
     *  \param dhcp_option      a pointer to the DHCP option field.
     *  \param service_flag     the flag that marks this type of service.
     *  \param payload_len      the payload size of the packet payload that follows the header of this field.
     *  \param offset           the current processing packet processing offset which might get modified by this function.
     */
    void processDHCPService(VLANEntry* vlan, const RCDCap::DHCPOptionField* dhcp_option, size_t service_flag, size_t payload_len, size_t& offset);
    
    /*! \brief Processes DHCPv6 option field related to a advertised network service.
     * 
     *  \param vlan             a pointer to the VLAN entry.
     *  \param dhcp_option      a pointer to the DHCPv6 option field.
     *  \param service_flag     the flag that marks this type of service.
     */
    void processDHCPv6Service(VLANEntry* vlan, const RCDCap::DHCPv6OptionField* dhcpv6_option, size_t service_flag);
    
    /*! \brief Processes and extracts IPv4 addresses out of ARP messages.
     * 
     *  It processe only ARP reply messages and extracts the actual IP addreses.
     * 
     *  \param vid          the identifier of the current VLAN.
     *  \param arp_header   the header of the ARP message.
     *  \param payload_len  the packet payload that follows the arp_header.
     */
    void processARP(size_t vid, const RCDCap::ARPHeader* arp_header, size_t payload_len);
    
    /*! \brief Processes and extracts data out of ICMPv6 NDP message.
     * 
     *  It processes traffic Router Advertisement and Neighbor Advertisement traffic. The data that gets scraped out of the
     *  header is information about DNS servers, routers, network pools and network hosts.
     */
    void processNDP(size_t vid, const RCDCap::IPv6Header* ipv6_header, const RCDCap::ICMPv6Header* icmp_header, size_t payload_len);
    
    /*! \brief Processes and extracts data out of DHCP packets.
     * 
     *  It processes DHCP traffic in the form of DHCP replies. The data that gets scraped out of the header is information
     *  about services, network pools and the address of the DHCP server.
     * 
     *  \param vid          the identifier of the current VLAN.
     *  \param ipv4_header  the IPv4 header used when extracting the IP address of the current DHCP server.
     *  \param udp_header   the contents of the UDP header, which are used for determining whether it is a DHCP reply message.
     *  \param payload_len  the packet payload that follows the udp_header.
     */
    void processDHCP(size_t vid, const RCDCap::IPv4Header* ipv4_header, const RCDCap::UDPHeader* udp_header, size_t payload_len);

    /*! \brief Processes and extracts data out of DHCP packets.
     * 
     *  It processes DHCPv6 traffic in the form of DHCPv6 replies. The data that gets scraped out of the header is information
     *  about services, network pools and the address of the DHCPv6 server.
     * 
     *  \param vid          the identifier of the current VLAN.
     *  \param ipv6_header  the IPv6 header used when extracting the IP address of the current DHCP server.
     *  \param udp_header   the contents of the UDP header, which are used for determining whether it is a DHCP reply message.
     *  \param payload_len  the packet payload that follows the udp_header.
     */
    void processDHCPv6(size_t vid, const RCDCap::IPv6Header* ipv6_header, const RCDCap::UDPHeader* header, size_t payload_len);
};

#endif // _QN_DHCP_MONITOR_HH_

