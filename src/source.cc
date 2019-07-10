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

#include "rcdcap/source.hh"
#include "rcdcap/exception.hh"

#include <iostream>
#include <iomanip>
#include <cstring>
#include <functional>

#ifndef PCAP_NETMASK_UNKNOWN
#   define PCAP_NETMASK_UNKNOWN 0xffffffff
#endif

namespace RCDCap
{
using std::placeholders::_1;
using std::placeholders::_2;

Source::~Source()
{
}

void Source::attach(const SinkPtr& _sink)
{
    m_Sink = _sink;
}

SinkPtr Source::getMainSink()
{
    return m_Sink;
}

DataSource::DataSource(boost::asio::io_service& io_service,
                       termination_handler hnd,
                       size_t buffer_size,
                       bool memory_locking,
                       size_t burst_size,
                       size_t timeout)
    :   m_Buffer(buffer_size, memory_locking),
        m_IOService(io_service),
        m_TermHandler(hnd),
        m_BurstSize(burst_size),
        m_Timeout(timeout)
{
}

CommonBuffer& DataSource::getBuffer()
{
    return m_Buffer;
}

PCAPDataSource::PCAPDataSource(boost::asio::io_service& io_service,
                               termination_handler hnd,
                               size_t buffer_size,
                               bool memory_locking,
                               size_t burst_size,
                               size_t timeout)
    :   DataSource(io_service, hnd, buffer_size, memory_locking, burst_size, timeout),
        m_Handle(nullptr),
        m_Current(nullptr),
        m_PacketsLostBuff(0),
        m_PacketsCaptured(0)
{
    memset(&m_Filter, 0, sizeof(bpf_program));
}

PCAPDataSource::~PCAPDataSource()
{
    pcap_freecode(&m_Filter);
    if(m_Handle)
        pcap_close(m_Handle);
}

void PCAPDataSource::startAsync()
{
    //Source::start();
    char errbuf[PCAP_ERRBUF_SIZE];
    if(pcap_setnonblock(m_Handle, 1, errbuf) < 0)
        THROW_EXCEPTION("could not set the device " + m_Source + " in non-blocking mode");
    if(m_Sink)
        m_IOService.post(std::bind(&PCAPDataSource::dispatch, this));
    else
        m_IOService.post(std::bind(&PCAPDataSource::dispatchDummy, this));
}

void PCAPDataSource::start()
{
    pcap_handler hnd = m_Sink ? &PCAPDataSource::handler : &PCAPDataSource::dummyHandler;
    for(;;)
    {
        auto packets_lost = m_PacketsLostBuff;
        auto status = pcap_dispatch(m_Handle, m_BurstSize, hnd, reinterpret_cast<u_char*>(this));
        status -= m_PacketsLostBuff - packets_lost;
        if(status == -1)
            THROW_EXCEPTION(std::string("error: ") + pcap_geterr(m_Handle));
        else if(status == -2 || (status == 0 && isFile()))
            break;
        else if(status != 0 && m_Sink && m_Current)
        {
            m_Sink->notify(m_Current, status);
            m_Current = nullptr;
        }
    }
    m_TermHandler();
}
    
void PCAPDataSource::stop()
{
    pcap_breakloop(m_Handle);
}

void PCAPDataSource::openDefaultDevice(size_t snaplen)
{
    char errbuf[PCAP_ERRBUF_SIZE];
    const char* dev_name;
    dev_name = pcap_lookupdev(errbuf);
    errno = 0; // ^^^^^ BUG: That's buggy
    if(!dev_name)
        THROW_EXCEPTION(std::string("could not find default device: ") + errbuf +
                        ".\nMake sure that you have enough permissions.");
    m_Source = dev_name;
    openDevice(snaplen, errbuf);
}

void PCAPDataSource::openDevice(const std::string& dev, size_t snaplen)
{
    char errbuf[PCAP_ERRBUF_SIZE];
    m_Source = dev;
    openDevice(snaplen, errbuf);
}

void PCAPDataSource::openStdin()
{
    openFile("-");
}

void PCAPDataSource::openFile(const std::string& filename)
{
    char errbuf[PCAP_ERRBUF_SIZE];
    m_Source = filename;
    m_Handle = pcap_open_offline(filename.c_str(), errbuf);
    if(!m_Handle)
        THROW_EXCEPTION("could not open the specified file: " + filename + ": " + errbuf);
}

void PCAPDataSource::openDevice(size_t snaplen, char* errbuf)
{
    m_Handle = pcap_open_live(m_Source.c_str(), snaplen, 1, m_Timeout, errbuf);
    if(!m_Handle)
        THROW_EXCEPTION("could not open device " + m_Source + ": " + errbuf +
                        "\nMake sure that you have enough permissions.");
}

void PCAPDataSource::setFilterExpression(const std::string& expr)
{
    char errbuf[PCAP_ERRBUF_SIZE];
    bpf_u_int32 net, mask = 0;
    if(isFile())
        net = PCAP_NETMASK_UNKNOWN;
    else if (pcap_lookupnet(m_Source.c_str(), &net, &mask, errbuf) < 0)
        THROW_EXCEPTION("could not get netmask for device " + m_Source + ": " + errbuf);
    if (pcap_compile(m_Handle, &m_Filter, expr.c_str(), 0, mask) < 0)
        THROW_EXCEPTION("could not parse filter \"" + expr + "\": " + pcap_geterr(m_Handle));
    if (pcap_setfilter(m_Handle, &m_Filter) < 0)
        THROW_EXCEPTION("could not install filter \"" + expr + "\": " + pcap_geterr(m_Handle));
}

std::string PCAPDataSource::getName() const
{
    return m_Source;
}

pcap_t* PCAPDataSource::_getHandle()
{
    return m_Handle;
} 

bool PCAPDataSource::isFile() const
{
    return pcap_file(m_Handle) != NULL;
}

int PCAPDataSource::getLinkType() const
{
    return pcap_datalink(m_Handle);
}

int PCAPDataSource::getSnapshot() const
{
    return pcap_snapshot(m_Handle);
}

std::string PCAPDataSource::getLinkTypeName() const
{
    return pcap_datalink_val_to_name(pcap_datalink(m_Handle));
}

size_t PCAPDataSource::getPacketsCapturedKernel() const
{
    pcap_stat stats;
    pcap_stats(m_Handle, &stats);
    return stats.ps_recv;
}

size_t PCAPDataSource::getPacketsDroppedKernel() const
{
    pcap_stat stats;
    pcap_stats(m_Handle, &stats);
    return stats.ps_drop;
}
    
size_t PCAPDataSource::getPacketsDroppedDriver() const
{
    pcap_stat stats;
    pcap_stats(m_Handle, &stats);
    return stats.ps_ifdrop;
}

size_t PCAPDataSource::getPacketsCaptured() const
{
    return m_PacketsCaptured;
}

size_t PCAPDataSource::getPacketsDroppedBuffer() const
{
    return m_PacketsLostBuff;
}

void PCAPDataSource::dispatch()
{
    auto packets_lost = m_PacketsLostBuff;
    auto r = pcap_dispatch(m_Handle, -1, &PCAPDataSource::handler,
                           reinterpret_cast<u_char*>(this));
    r -= m_PacketsLostBuff - packets_lost;
    if(r == -1)
        THROW_EXCEPTION(std::string("error: ") + pcap_geterr(m_Handle));
    else if(r != -2 && (r != 0 || !isFile()))
    {
        if(m_Sink && m_Current)
        {
            m_Sink->notify(m_Current, r);
            m_Current = nullptr;
        }
        m_IOService.post(std::bind(&PCAPDataSource::dispatch, this));
    }
    else 
        m_TermHandler();
}


void PCAPDataSource::dispatchDummy()
{
    auto r = pcap_dispatch(m_Handle, -1, &PCAPDataSource::dummyHandler,
                           reinterpret_cast<u_char*>(this));
    if(r == -1)
        THROW_EXCEPTION(std::string("error: ") + pcap_geterr(m_Handle));
    else if(r != -2 && (r != 0 || !isFile()))
        m_IOService.post(std::bind(&PCAPDataSource::dispatchDummy, this));
    else 
        m_TermHandler();
}

void PCAPDataSource::handler(u_char* args, const pcap_pkthdr* header, const u_char* packet)
{
    
    auto& src = *reinterpret_cast<PCAPDataSource*>(args);
    auto& buffer = src.getBuffer();
    ++src.m_PacketsCaptured;
    
    size_t count = sizeof(PacketInfo) + header->caplen;
    auto* packet_info = buffer.push(count);
    if(!packet_info)
    {
        ++src.m_PacketsLostBuff;
        return;
    }
    auto* packet_buf = GetPacket(packet_info);
    assert((char*)packet_info + sizeof(PacketInfo) == (char*)packet_buf);
    assert((uintptr_t)packet_buf + header->caplen <= (uintptr_t)packet_info + count);
    std::copy(packet, packet + header->caplen, packet_buf);
    
    if(src.m_Current == nullptr)
        src.m_Current = packet_info;
    
    packet_info->init(pcap_datalink(src.m_Handle), Time(header->ts), header->caplen, header->len, count);
    assert(count);
}

void PCAPDataSource::dummyHandler(u_char* args, const pcap_pkthdr* header, const u_char* packet)
{
    auto& src = *reinterpret_cast<PCAPDataSource*>(args);
    ++src.m_PacketsCaptured;
}
}
