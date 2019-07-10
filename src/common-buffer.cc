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

#include "rcdcap/common-buffer.hh"
#include "rcdcap/exception.hh"
#include "rcdcap/memory.hh"

#ifndef _WIN32
#include <sys/mman.h>
#endif

#include <limits>
#include <cassert>

namespace RCDCap
{
void PacketInfo::init(int link_type, const Time& t, size_t caplen, size_t origlen, size_t alloclen)
{
    m_AllocLen = alloclen;
    m_LinkType = link_type;
    m_PacketHeader.setTimestamp(t);
    m_PacketHeader.setCapturedLength(caplen);
    m_PacketHeader.setOriginalLength(origlen);
}

size_t PacketInfo::getAllocatedSize() const
{
    return m_AllocLen;
}

void PacketInfo::setLinkType(int link_type)
{
    m_LinkType = link_type;
}

int PacketInfo::getLinkType() const
{
    return m_LinkType;
}

CommonBuffer::CommonBuffer(size_t _size, bool memory_locking)
    :   m_Capacity(_size),
        m_Begin(0),
        m_Count(0),
        m_Padding(0),
        m_MemoryLocking(memory_locking)
{
    void* ptr;
    RCDCAP_ALIGNED_ALLOC(ptr, m_Capacity, 8);
    m_Data = reinterpret_cast<char*>(ptr);
#ifndef _WIN32
    if(m_MemoryLocking && mlock(m_Data, m_Capacity))
        THROW_EXCEPTION("could not lock the buffer in memory");
#endif
}

CommonBuffer::~CommonBuffer()
{
#ifndef _WIN32
    if(m_MemoryLocking)
        munlock(m_Data, m_Capacity);
#endif
    RCDCAP_ALIGNED_DEALLOC(m_Data);
}

PacketInfo* CommonBuffer::push(size_t bytes)
{
    std::lock_guard<std::mutex> lock(m_Mutex);
    auto uend = m_Begin + m_Count + m_Padding;
    if(uend < m_Capacity)
    {
        if(uend + bytes > m_Capacity)
        {
            auto padding = m_Capacity - uend;
            if(m_Count + padding + bytes > m_Capacity)
                return 0;
            m_Padding = padding;
            m_Count += bytes;
            assert(bytes > sizeof(PacketInfo));
            auto* packet_info = reinterpret_cast<PacketInfo*>(m_Data);
            packet_info->m_Processed = 0;
        #ifndef NDEBUG
            packet_info->m_DebugMagic = 0x1337;
        #endif
            return packet_info;
        }
    }
    else
    {
        uend %= m_Capacity;
        if(uend + bytes > m_Begin)
            return 0;
    }
    m_Count += bytes;
    assert(bytes > sizeof(PacketInfo));
    auto* packet_info = reinterpret_cast<PacketInfo*>(m_Data + uend);
#ifndef NDEBUG    
    packet_info->m_DebugMagic = 0x1337;
#endif
    packet_info->m_Processed = 0;
    return packet_info;
}

void CommonBuffer::pop(size_t bytes)
{
    std::lock_guard<std::mutex> lock(m_Mutex);
    assert(bytes <= m_Count);
    m_Begin += bytes;
    assert(m_Begin <= m_Capacity);
    if(m_Begin + m_Padding == m_Capacity)
    {
        m_Begin = 0;
        m_Padding = 0;
    }
    m_Count -= bytes;
    if(!m_Count)
        m_Begin = 0;
}

void CommonBuffer::popSequence(size_t bytes)
{
    std::lock_guard<std::mutex> lock(m_Mutex);
#ifndef NDEBUG
    auto packet_info = begin();
    size_t total_bytes = 0;
    for(total_bytes = 0; total_bytes < bytes; packet_info = next(packet_info))
    {
        assert(packet_info->m_DebugMagic == 0x1337 && packet_info->m_Processed == 0);
        total_bytes += packet_info->getAllocatedSize();
    }
    assert(total_bytes == bytes);
#endif    

    assert(bytes <= m_Count);
    m_Begin += bytes;
    //assert(m_Begin <= m_Capacity);
    if(m_Begin + m_Padding >= m_Capacity)
    {
        m_Begin = (m_Begin + m_Padding) % m_Capacity;
        m_Padding = 0;
    }
    m_Count -= bytes;
    if(!m_Count)
        m_Begin = 0;
}

bool CommonBuffer::acquireSequence(PacketInfo* packet_info, size_t* inout_packet_count)
{
    std::lock_guard<std::mutex> lock(m_Mutex);
    auto packet_count = *inout_packet_count;
    if(reinterpret_cast<PacketInfo*>(m_Data + m_Begin) == packet_info)
    {
        size_t total_bytes = 0;
        for(size_t packet_idx = 0; packet_idx < packet_count; ++packet_idx,
                                                            packet_info = next(packet_info))
        {
            assert(packet_info->m_Processed == 0);
            total_bytes += packet_info->getAllocatedSize();
        }
        
        for(; packet_info->m_Processed && total_bytes < m_Count; ++packet_count,
                                                                 packet_info = next(packet_info))
        {
            assert(packet_info->m_Processed);
            packet_info->m_Processed = 0;
            total_bytes += packet_info->getAllocatedSize();
        }
        
        *inout_packet_count = packet_count;
        
        return true;
    }
  

    for(size_t packet_idx = 0; packet_idx < packet_count; ++packet_idx,
                                                            packet_info = next(packet_info))
    {
        assert(packet_info->m_Processed == 0);
        packet_info->m_Processed = 1;
    }
   
    return false;
}

PacketInfo* CommonBuffer::acquireSequence(size_t* packet_count)
{
    std::lock_guard<std::mutex> lock(m_Mutex);
    if(!m_Count)
        return nullptr;
    auto packet_info = reinterpret_cast<PacketInfo*>(m_Data + m_Begin);
    if(!packet_info->m_Processed)
        return nullptr;
    size_t total_bytes = 0;
    auto begin_packet_info = packet_info;
    for(; packet_info->m_Processed && total_bytes < m_Count; ++*packet_count,
                                                             packet_info = next(packet_info))
    {
        assert(packet_info->m_Processed);
        packet_info->m_Processed = 0;
        total_bytes += packet_info->getAllocatedSize();
    }
    
    return begin_packet_info;
}

PacketInfo* CommonBuffer::next(PacketInfo* packet_info) const
{
    assert(packet_info->m_DebugMagic == 0x1337);
    assert(m_Data <= reinterpret_cast<char*>(packet_info));
    assert(reinterpret_cast<char*>(packet_info) + packet_info->getAllocatedSize() <= m_Data + m_Capacity);
    auto offset = (reinterpret_cast<char*>(packet_info) - m_Data) + packet_info->getAllocatedSize();
    assert(offset + m_Padding <= m_Capacity);
    return reinterpret_cast<PacketInfo*>(&m_Data[(offset + m_Padding == m_Capacity) ? 0 : offset]);
}
}
