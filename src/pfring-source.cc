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

#include "rcdcap/pfring-source.hh"
#include "rcdcap/exception.hh"

#include <pfring.h>

namespace RCDCap
{
PF_RINGDataSource::PF_RINGDataSource(boost::asio::io_service& io_service,
                                     termination_handler hnd,
                                     size_t buffer_size,
                                     bool memory_locking,
                                     size_t burst_size,
                                     size_t timeout)
    :   DataSource(io_service, hnd, buffer_size, memory_locking, burst_size, timeout),
        m_Handle(0),
        m_Active(true),
        m_Snaplen(4096),
        m_PacketsLostBuff(0),
        m_PacketsCaptured(0)
{
}

PF_RINGDataSource::~PF_RINGDataSource()
{
    if(m_Handle)
        pfring_close(m_Handle);
}
    
void PF_RINGDataSource::startAsync()
{
    pfring_enable_ring(m_Handle);
    if(m_Sink)
        m_IOService.post(std::bind(&PF_RINGDataSource::dispatch, this));
    else
        m_IOService.post(std::bind(&PF_RINGDataSource::dispatchDummy, this));
}

void PF_RINGDataSource::start()
{
    int                     ret;
    u_char                  *packet;
    struct pfring_pkthdr    header;
    pfring_enable_ring(m_Handle);
    while(m_Active)
    {
        size_t packets = 0;
        PacketInfo* current = nullptr;
        size_t burst_size = getBurstSize();
        while(packets < burst_size &&
              (ret = pfring_recv(m_Handle, &packet, 0, &header, 0)))
        {
            if(ret < 0)
                THROW_EXCEPTION(std::string("error: pfring_recv: ") + strerror(errno));
            else if(ret > 0)
            {
                ++m_PacketsCaptured;
                if(m_Sink)
                {
                    size_t count = sizeof(PacketInfo) + header.caplen;
                    auto* packet_info = m_Buffer.push(count);
                    auto* packet_buf = GetPacket(packet_info);
                    if(!packet_info)
                        ++m_PacketsLostBuff;
                    else
                    {
                        std::copy(packet, packet + header.caplen, packet_buf);
                        packet_info->init(DLT_EN10MB, Time(header.ts), header.caplen, header.len, count);
                        if(!current)
                            current = packet_info;
                        ++packets;
                    }
                }
            }
        }
        if(current)
            m_Sink->notify(current, packets);
    }
    m_TermHandler();
}

void PF_RINGDataSource::stop()
{
    m_Active = false;
}

void PF_RINGDataSource::openDevice(const std::string& devname, size_t snaplen)
{
    m_Name = devname;
    m_Snaplen = snaplen;
    m_Handle = pfring_open(const_cast<char*>(m_Name.c_str()), m_Snaplen, PF_RING_PROMISC);
    if(!m_Handle)
        THROW_EXCEPTION("could not open device " + m_Name + ": " + strerror(errno) + "\n"
                        "Make sure that you have enough permissions.");
}

void PF_RINGDataSource::openDefaultDevice(size_t snaplen)
{
    m_Name = "eth0"; // WARNING: Hard-coded
    m_Snaplen = snaplen;
    m_Handle = pfring_open(const_cast<char*>(m_Name.c_str()), m_Snaplen, PF_RING_PROMISC);
    if(!m_Handle)
        THROW_EXCEPTION("could not open device " + m_Name + ": " + strerror(errno) + "\n"
                        "Make sure that you have enough permissions.");
}

void PF_RINGDataSource::setFilterExpression(const std::string& expr)
{
    if(pfring_set_bpf_filter(m_Handle, const_cast<char*>(expr.c_str())) < 0)
        THROW_EXCEPTION("could not set the specified filter expression: " + expr);
}

std::string PF_RINGDataSource::getName() const
{
    return m_Name;
}

bool PF_RINGDataSource::isFile() const
{
    return false;
}

int PF_RINGDataSource::getLinkType() const
{
    return DLT_EN10MB; // WARNING: Hard-coded
}

int PF_RINGDataSource::getSnapshot() const
{
    return m_Snaplen;
}

std::string PF_RINGDataSource::getLinkTypeName() const
{
    return "EN10MB"; // WARNING: Hard-coded
}

size_t PF_RINGDataSource::getPacketsCapturedKernel() const
{
    pfring_stat stats;
    pfring_stats(m_Handle, &stats);
    return stats.recv + stats.drop;
}

size_t PF_RINGDataSource::getPacketsDroppedKernel() const
{
    pfring_stat stats;
    pfring_stats(m_Handle, &stats);
    return stats.drop;
}

size_t PF_RINGDataSource::getPacketsDroppedDriver() const
{
    return 0;
}

size_t PF_RINGDataSource::getPacketsCaptured() const
{
    return m_PacketsCaptured;
}

size_t PF_RINGDataSource::getPacketsDroppedBuffer() const
{
    return m_PacketsLostBuff;
}

void PF_RINGDataSource::dispatch()
{
    int                     ret;
    u_char                  *packet;
    struct pfring_pkthdr    header;
    do
    {
        if(!m_Active)
        {
            m_TermHandler();
            return;
        }
        size_t packets = 0;
        PacketInfo* current = nullptr;
        size_t burst_size = getBurstSize();
        while(packets < burst_size &&
              (ret = pfring_recv(m_Handle, &packet, 0, &header, 0)))
        {
            if(ret < 0)
                THROW_EXCEPTION(std::string("error: pfring_recv: ") + strerror(errno));
            else if(ret > 0)
            {
                ++m_PacketsCaptured;
                size_t count = sizeof(PacketInfo) + header.caplen;
                auto* packet_info = m_Buffer.push(count);
                auto* packet_buf = GetPacket(packet_info);
                if(!packet_info)
                {
                    ++m_PacketsLostBuff;
                    break;
                }
                else
                {
                    std::copy(packet, packet + header.caplen, packet_buf);
                    packet_info->init(DLT_EN10MB, Time(header.ts), header.caplen, header.len, count);
                    if(!current)
                        current = packet_info;
                    ++packets;
                }
            }
        }
        if(current)
            m_Sink->notify(current, packets);
    } while(ret);
    m_IOService.post(std::bind(&PF_RINGDataSource::dispatch, this));
}


void PF_RINGDataSource::dispatchDummy()
{
    int                     ret;
    u_char                  *packet;
    struct pfring_pkthdr    hdr;
    do
    {
        if(!m_Active)
        {
            m_TermHandler();
            return;
        }
        ret = pfring_recv(m_Handle, &packet, 0, &hdr, 0);
        if(ret < 0)
            THROW_EXCEPTION(std::string("error: pfring_recv: ") + strerror(errno));
        else if(ret > 0)
            ++m_PacketsCaptured;
    } while(ret);
    m_IOService.post(std::bind(&PF_RINGDataSource::dispatchDummy, this));
}
}
