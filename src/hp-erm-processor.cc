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

#include "rcdcap/hp-erm-processor.hh"
#include "rcdcap/packet-headers.hh"
#include "rcdcap/exception.hh"

#include <boost/scope_exit.hpp>

namespace RCDCap
{
using std::placeholders::_1;
using std::placeholders::_2;

const uint8 HPERMHeader::m_PriorityLUT[] = { 1, 2, 0, 3, 4, 5, 6, 7 };

HPERMProcessor::HPERMProcessor(boost::asio::io_service& io_service,
                               CommonBuffer& buffer,
                               size_t udpport, bool vlan_enabled)
    :   DecapsulatingProcessor(io_service, buffer),
        m_VLANEnabled(vlan_enabled),
        m_UDPPort(udpport)
{
}

HPERMProcessor::~HPERMProcessor() {}

void HPERMProcessor::notify(PacketInfo* packet_info, size_t packets)
{
    m_IOService.post(std::bind(&HPERMProcessor::process, this, packet_info, packets));
}

void HPERMProcessor::process(PacketInfo* packet_info, size_t packets)
{
    PacketInfo* current_packet = packet_info;
    for(size_t i = 0; i < packets; ++i, current_packet = m_CommonBuffer.next(current_packet))
        this->processImpl(current_packet);
	if(m_Sink)
    	m_Sink->notify(packet_info, packets);
}

void HPERMProcessor::processImpl(PacketInfo* packet_info)
{
    auto&           pcap_header = packet_info->getPCAPHeader();
    auto*           packet = GetPacket(packet_info);
    auto            caplen = pcap_header.getCapturedLength();
    auto            origlen = pcap_header.getOriginalLength();
    size_t          offset;
    ProtocolType    proto;
    
    if(packet_info->getLinkType() != DLT_RAW)
    {
        if(!this->getProtocolOffset(packet_info, offset, proto))
            return;
        
        if(proto != ProtocolType::RCDCAP_PROTOCOL_TYPE_UDP ||
           caplen < sizeof(UDPHeader) + offset)
            return;
        auto& udp_header = reinterpret_cast<UDPHeader&>(packet[offset]);
        if(udp_header.getDestinationPort() != m_UDPPort && udp_header.getSourcePort() != m_UDPPort)
            return;
        offset += sizeof(UDPHeader);
        if(caplen < sizeof(HPERMHeader) + offset)
            return;
    }
    else
    {
        offset = 0;
        assert(caplen >= sizeof(HPERMHeader) + offset);
    }
    
    auto& hperm_header = reinterpret_cast<const HPERMHeader&>(packet[offset]);
    auto priority = hperm_header.getPriority();
    auto vlan_id = hperm_header.getVLAN();
    offset += sizeof(HPERMHeader);
    assert((int)offset >= 0);
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
    pcap_header.setCapturedLength(caplen - offset);
    pcap_header.setOriginalLength(origlen - offset);
    packet_info->setLinkType(DLT_EN10MB);
}

HPERMUDPDataSource::HPERMUDPDataSource(boost::asio::io_service& io_service,
                                       termination_handler hnd,
                                       size_t buffer_size, bool memory_locking,
                                       size_t burst_size, size_t timeout,
                                       size_t udpport)
    :   DataSource(io_service, hnd, buffer_size, memory_locking, burst_size, timeout),
        m_Active(true),
        m_Socket(io_service, boost::asio::ip::udp::endpoint(boost::asio::ip::udp::v4(), udpport)),
        m_UDPPort(udpport)
{
}
    
HPERMUDPDataSource::~HPERMUDPDataSource()
{
}

void HPERMUDPDataSource::startAsync()
{
    if(m_Sink)
        m_Socket.async_receive(boost::asio::buffer(m_RecvBuffer), std::bind(&HPERMUDPDataSource::receiveHandler, this, _1, _2));
    else
        m_Socket.async_receive(boost::asio::buffer(m_RecvBuffer), std::bind(&HPERMUDPDataSource::dummyReceiveHandler, this, _1, _2));
}

void HPERMUDPDataSource::start()
{
    size_t caplen;
    boost::system::error_code ec;
    while(m_Active)
    {
        caplen = m_Socket.receive(boost::asio::buffer(m_RecvBuffer), 0, ec);
        if(ec == boost::asio::error::interrupted)
            return;
        boost::asio::detail::throw_error(ec);
        if(m_Sink)
            pushData(caplen);
        else
            ++m_PacketsCaptured;
    }
    m_TermHandler();
}

void HPERMUDPDataSource::stop()
{
    m_Active = false;
    boost::system::error_code ec;
    
    m_Socket.close(ec);
    if(ec && ec != boost::asio::error::operation_aborted)
        boost::asio::detail::throw_error(ec);
}

void HPERMUDPDataSource::setFilterExpression(const std::string& expr)
{
    THROW_EXCEPTION("filtering is not supported in this mode");
}

std::string HPERMUDPDataSource::getName() const
{
    std::stringstream ss;
    ss << "port " << m_UDPPort << " (HP ERM)";
    return ss.str();
}

bool HPERMUDPDataSource::isFile() const
{
    return false;
}

int HPERMUDPDataSource::getLinkType() const
{
    return DLT_RAW; // WARNING: Hard-codeds
}

int HPERMUDPDataSource::getSnapshot() const
{
    return m_RecvBuffer.size();
}

std::string HPERMUDPDataSource::getLinkTypeName() const
{
    return "HP ERM RAW"; // WARNING: Hard-coded
}

size_t HPERMUDPDataSource::getPacketsCapturedKernel() const
{
    return 0;
}

size_t HPERMUDPDataSource::getPacketsDroppedKernel() const
{
    return 0;
}

size_t HPERMUDPDataSource::getPacketsDroppedDriver() const
{
    return 0;
}

size_t HPERMUDPDataSource::getPacketsCaptured() const
{
    return m_PacketsCaptured;
}

size_t HPERMUDPDataSource::getPacketsDroppedBuffer() const
{
    return m_PacketsLostBuff;
}

void HPERMUDPDataSource::receiveHandler(const boost::system::error_code& ec, std::size_t bytes_transferred)
{
    if(ec == boost::asio::error::operation_aborted)
        return;
    boost::asio::detail::throw_error(ec);
    pushData(bytes_transferred);
    m_Socket.async_receive(boost::asio::buffer(m_RecvBuffer), std::bind(&HPERMUDPDataSource::receiveHandler, this, _1, _2));
}

void HPERMUDPDataSource::dummyReceiveHandler(const boost::system::error_code& ec, std::size_t bytes_transferred)
{
    if(ec == boost::asio::error::operation_aborted)
        return;
    boost::asio::detail::throw_error(ec);
    ++m_PacketsCaptured;
    m_Socket.async_receive(boost::asio::buffer(m_RecvBuffer), std::bind(&HPERMUDPDataSource::dummyReceiveHandler, this, _1, _2));
}

void HPERMUDPDataSource::pushData(size_t caplen)
{
    assert(caplen);
    ++m_PacketsCaptured;
    auto count = sizeof(PacketInfo) + caplen;
    auto* packet_info = m_Buffer.push(count);
    if(!packet_info)
    {
        ++m_PacketsLostBuff;
        return;
    }
    auto* packet_buf = GetPacket(packet_info);
    assert((char*)packet_info + sizeof(PacketInfo) == (char*)packet_buf);
    assert((uintptr_t)packet_buf + caplen <= (uintptr_t)packet_info + count);
    std::copy(m_RecvBuffer.begin(), m_RecvBuffer.begin() + caplen, packet_buf);
    
    auto _now = std::chrono::high_resolution_clock::now();
    
    typedef std::chrono::microseconds duration_t;
    typedef duration_t::rep rep_t;
    rep_t d = std::chrono::duration_cast<duration_t>(_now.time_since_epoch()).count();
    rep_t sec = d/1000000;
    rep_t usec = d%1000000;
    packet_info->init(DLT_RAW, Time(sec, usec), caplen, caplen, count);
    assert(count);

    m_Sink->notify(packet_info, 1); // TODO: Optimize for bursts
}
}