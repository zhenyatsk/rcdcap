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

#ifndef _RCDCAP_COMMON_BUFFER_HH_
#define _RCDCAP_COMMON_BUFFER_HH_

#include "rcdcap/global.hh"
#include "rcdcap/pcap.hh"

#include <thread>
#include <atomic>
#include <mutex>

namespace RCDCap
{
#ifdef _WIN32
#   define PACKET_ALIGN8 __declspec(align(8))
#else
#   define PACKET_ALIGN8 __attribute__((aligned(8)))
#endif

class CommonBuffer;

/*! \brief The data structure which contains information about the packets that
 *         are being processed.
 */
class PacketInfo
{
    friend class CommonBuffer;
    
    /*! \brief The total space that was allocated for the particular packet in
     *         the DataSource's buffer.
     */
    size_t                  m_AllocLen;

    //! Indicates if the packet was processed.
    uint32_t                m_Processed;
    
    //! Contains the current link type associated with this packet.
    int                     m_LinkType;
    
#ifndef NDEBUG
    int                     m_DebugMagic;
#endif
    
    //! The PCAP packet header.
    PACKET_ALIGN8 PCAPPacketHeader m_PacketHeader;
public:
    //! Sets a new current link type for the packet associated with this object.
    void setLinkType(int link_type);
    
    //! Returns the current link type.
    int getLinkType() const;
    
    //! Returns the PCAP packet header.
    PCAPPacketHeader& getPCAPHeader() { return m_PacketHeader; }
    
    /*! Initialization.
     *  \param link_type    the current link type associated with this packet.
     *  \param ts           a reference to the timestamp.
     *  \param caplen       the total amount of bytes from the packet that were
     *                      captured.
     *  \param origlen      the original length of the packet.
     *  \param alloclen     the total space that was allocated for the particular
     *                      packet.
     */
    void init(int link_type, const Time& ts, size_t caplen, size_t origlen, size_t alloclen);
    
    //! Returns the total space that was allocated for the packet.
    size_t getAllocatedSize() const;
};

/*! \brief A convenience function for getting the packet that has been written
 *         after the PacketInfo header.
 */
inline unsigned char* GetPacket(PacketInfo* packet_info)
{
    return reinterpret_cast<unsigned char*>(packet_info) + sizeof(PacketInfo);
}

/*! \brief The data structure, representing the internal ring buffer, which is
 *         used by all of the data sources to store temporary the data which is
 *         going to be processed.
 */
class DLL_EXPORT CommonBuffer
{
    //! The total capacity of the circular buffer.
    const size_t            m_Capacity;
    //! The index of the first element.
    size_t                  m_Begin,
    //! The total amount of data in the circular buffer.
                            m_Count,
    //! The padding at end of the list.
                            m_Padding;
    //! A pointer to the array which holds the data.
    char*                   m_Data;
    //! A mutex that is used to prevent any race condition.
    mutable std::mutex      m_Mutex;
    //! Indicates whether memory locking is enabled.
    bool                    m_MemoryLocking;
public:
    /*! \brief Constructor.
     *  \param _size          the total capacity of the circular buffer.
     *  \param memory_locking specifies whether memory locking must be enabled.
     */
    CommonBuffer(size_t _size, bool memory_locking);
    
    //! Destructor.
     ~CommonBuffer();
    
    //! \warning Copying is forbidden by design.
    CommonBuffer(const CommonBuffer&)=delete;
    
    //! \warning Assignment is forbidden by design.
    CommonBuffer& operator=(const CommonBuffer&)=delete;
    
    /*! \brief Allocates the specified amount of bytes, if there is still enough
     *         space left in the buffer.
     *  \param bytes    the amount bytes that are requested.
     *  \return on success returns a pointer to the PacketInfo section of the
     *          allocated space or null pointer.
     */
    PacketInfo* push(size_t bytes);
    
    /*! \brief Deallocates the specified amount of bytes.
     *  \param bytes    the amount bytes that must be freed.
     */
    void pop(size_t bytes);
    
    /*! \brief Deallocates the specified amount of bytes which contain more than
     *         one packet.
     *  \param bytes    the amount bytes that must be freed.
     */
    void popSequence(size_t bytes);
    
    /*! \brief Returns a pointer to the PacketInfo section of the first packet
     *         that is in the buffer.
     */
    PacketInfo* begin() const
    {
        return reinterpret_cast<PacketInfo*>(m_Data + m_Begin);
    }
    
    /*! \brief Returns the offset of the packet from the first element of the
     *         ring buffer.
     */
    size_t offset(PacketInfo* packet_info) const
    {
        size_t offset = (reinterpret_cast<char*>(packet_info) - m_Data);
        return m_Begin <= offset ?
                    offset - m_Begin :
                    m_Capacity - (m_Begin - offset) - m_Padding;
    }
    
    //! Returns the next packet in the buffer.
    PacketInfo* next(PacketInfo* packet_info) const;
    
    bool acquireSequence(PacketInfo* packet_info, size_t* packet_count);
    
    PacketInfo* acquireSequence(size_t* packet_count);
    
    //! Returns the maximum amount of bytes that could be allocated.
    size_t capacity() const { return m_Capacity; }
    
    /*! \brief Returns the current amount of bytes that are currently allocated
     *         in the buffer.
     */
    size_t size() const { return m_Count; }
};
}

#endif /* _RCDCAP_COMMON_BUFFER_HH_ */
