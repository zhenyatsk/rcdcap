/* ZECap
* Copyright (C) 2012 Zdravko Velinov
*
* This program is free software: you can redistribute it and/or modify
* it under the terms of the GNU General Public License as published by
* the Free Software Foundation, either version 3 of the License, or
* (at your option) any later version.
*
* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
* GNU General Public License for more details.
*
* You should have received a copy of the GNU General Public License
* along with this program. If not, see <http://www.gnu.org/licenses/>.
*/
#ifndef _ZECAP_PCAP_HH_
#define _ZECAP_PCAP_HH_
#include <pcap.h>
#include "rcdcap/byte-swap.hh"
#include "rcdcap/types.hh"
#include <iostream>

#include <boost/asio.hpp>

namespace RCDCap
{
//! The magic number which is used for identifying a PCAP file.
const uint32 PCAPMagicNumber = 0xa1b2c3d4;

//! The magic number when a different endianess is used.
const uint32 PCAPReversedMagicNumber = 0xd4c3b2a1;

//! The supported PCAP major version.
const uint16 PCAPVersionMajor = 2;

//! The supported PCAP minor version.
const uint16 PCAPVersionMinor = 4;

#pragma pack(push, 1)
//! Specifies the fields in the PCAP file header.
class PCAPFileHeader
{
    uint32  m_MagicNumber;  /*!< \brief The magic number which is used for identifying a PCAP file.
                             *   \see RCDCap::PCAPMagicNumber and RCDCap::PCAPReversedMagicNumber.
                             */
    uint16  m_VersionMajor; /*!< \brief The current PCAP major version of the file.
                             *   \see RCDCap::PCAPVersionMajor.
                             */
    uint16  m_VersionMinor; /*!< \brief The current PCAP minor version of the file.
                             *   \see RCDCap::PCAPVersionMinor.
                             */
    int32   m_ThisZone;     //!< The time zone correction.
    uint32  m_SigFigs;      //!< The accuracy of the timestamps.
    uint32  m_SnapLen;      //!< The maximum amount of bytes that was captured per packet.
    uint32  m_Network;      //!< The data link type.
public:
    //! Default constructor.
    PCAPFileHeader();
    
    /*! \brief Constructor.
     *  \param snaplen      the maximum amount of bytes that was captured per packet.
     *  \param net          the data link type.
     */
    PCAPFileHeader(uint32 snaplen, uint32 net);
    
    //! Checks whether the values of the header are valid.
    bool isValid() const;
    
    //! Returns whether the byte swapping is enabled for the file which has this header.
    bool isSwappingEnabled() const;
    
    //! Returns the PCAP major version currently employed by this header and the associated file.
    uint16 getVersionMajor() const;
    
    //! Returns the PCAP minor version currently employed by this header and the associated file.
    uint16 getVersionMinor() const;
    
    //! Returns the time zone correction relative to GMT.
    int32 getTimezone() const;
    
    //! Returns the maximum amount of bytes that captured per packet.
    uint32 getSnapLength() const;
    
    //! Returns the data link type.
    uint32 getNetwork() const;
};

//! Represents time in seconds and microseconds.
class Time
{
    uint32  m_Sec;      //!< The variable that is holding the total amount of seconds.
    uint32  m_uSec;     //!< The variable that is holding the total amount of microseconds.
public:
    //! Default constructor.
    Time();
    
    /*! \brief Constructor.
     *  Converts timeval to the internal representation.
     *  \param tv   the variable, which represents a time value.
     */
    Time(timeval tv);
    
    /*! \brief Constructor.
     *  \param s    the amount of seconds.
     *  \param us   the amount of microseconds.
     */
    Time(uint32 s, uint32 us);
    
    //! Returns the amount of seconds stored in that object.
    uint32 getSeconds() const;
    
    //! Returns the amount of microseconds stored in that object.
    uint32 getMicroseconds() const;

    //! Sets the amount of seconds stored in that object.
    void setSeconds(uint32 sec);

    //! Sets the amount of microseconds stored in that object.
    void setMicroseconds(uint32 usec);
    
    //! Performs byte swapping on the internal representation.
    void swapBytes();
    
    //! Comparison operator.
    bool operator==(const Time& t) const;
    
    //! Subtraction operator.
    Time operator-(const Time& t) const;
    
    //! Greater-than operator.
    bool operator>(const Time& t) const;
    
    //! Lesser-than operator.
    bool operator<(const Time& t) const;
};

//! Specifies the fields in the PCAP per-packet header.
class PCAPPacketHeader
{
    Time    m_Time;     //!< The timestamp.
    uint32  m_InclLen;  //!< The captured length.
    uint32  m_OrigLen;  //!< The original length.
public:
    //! Returns the timestamp.
    Time getTimestamp() const;
    
    //! Returns the original length of the packet.
    uint32 getOriginalLength() const;
    
    //! Returns the captured length of the packet.
    uint32 getCapturedLength() const;
    
    //! Sets the timestamp to the specified value.
    void setTimestamp(const Time& _time);
    
    //! Sets the captured length to the specified value.
    void setCapturedLength(uint32 incl_len);
    
    //! Sets the original length to the specified value.
    void setOriginalLength(uint32 orig_len);
};
#pragma pack(pop)
}
#endif /* _ZECAP_PCAP_HH_ */ 