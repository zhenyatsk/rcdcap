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

#include "rcdcap/pcap.hh"

namespace RCDCap
{
PCAPFileHeader::PCAPFileHeader()
{
}

PCAPFileHeader::PCAPFileHeader(uint32 snaplen, uint32 net)
    :   m_MagicNumber(PCAPMagicNumber),
        m_VersionMajor(PCAPVersionMajor),
        m_VersionMinor(PCAPVersionMinor),
        m_ThisZone(0),
        m_SigFigs(0),
        m_SnapLen(snaplen),
        m_Network(net)
{
}

bool PCAPFileHeader::isValid() const
{
    return m_MagicNumber == PCAPMagicNumber || m_MagicNumber == PCAPReversedMagicNumber;
}

bool PCAPFileHeader::isSwappingEnabled() const
{
    return m_MagicNumber == PCAPReversedMagicNumber;
}

uint16 PCAPFileHeader::getVersionMajor() const
{
    return m_VersionMajor;
}

uint16 PCAPFileHeader::getVersionMinor() const
{
    return m_VersionMinor;
}

int32 PCAPFileHeader::getTimezone() const
{
    return m_ThisZone;
}

uint32 PCAPFileHeader::getSnapLength() const
{
    return m_SnapLen;
}

uint32 PCAPFileHeader::getNetwork() const
{
    return m_Network;
}

Time::Time()
{
}

Time::Time(timeval tv)
    :   m_Sec(tv.tv_sec),
        m_uSec(tv.tv_usec)
{
}

Time::Time(uint32 s, uint32 us)
    :   m_Sec(s),
        m_uSec(us)
{
}

void Time::swapBytes()
{
    ByteSwap(m_Sec);
    ByteSwap(m_uSec);
}

uint32 Time::getSeconds() const
{
    return m_Sec;
}

uint32 Time::getMicroseconds() const
{
    return m_uSec;
}

void Time::setSeconds(uint32 sec)
{
    m_Sec = sec;
}

void Time::setMicroseconds(uint32 usec)
{
    m_Sec = usec/1000000;
    m_uSec = usec%1000000;
}

bool Time::operator==(const Time& t) const
{
    return t.m_Sec == m_Sec && m_uSec == t.m_uSec;
}

Time Time::operator-(const Time& t) const
{
    if(t.m_Sec > m_Sec)
        return Time(0, 0);
    else if(t.m_Sec == m_Sec)
    {
        if(t.m_uSec > m_uSec)
            return Time(0, 0);
        else
            return Time(0, m_uSec - t.m_uSec);
    }
    else if(t.m_uSec > m_uSec)
        return Time(m_Sec - t.m_Sec - 1, 1000000 - (t.m_uSec - m_uSec));
    return Time(m_Sec - t.m_Sec, m_uSec - t.m_uSec);
}

bool Time::operator>(const Time& t) const
{
    if(m_Sec > t.m_Sec)
        return true;
    else if(m_Sec == t.m_Sec && m_uSec > t.m_uSec)
        return true;
    return false;
}

bool Time::operator<(const Time& t) const
{
    if(m_Sec < t.m_Sec)
        return true;
    else if(m_Sec == t.m_Sec && m_uSec < t.m_uSec)
        return true;
    return false;
}

Time PCAPPacketHeader::getTimestamp() const
{
    return m_Time;
}

uint32 PCAPPacketHeader::getOriginalLength() const
{
    return m_OrigLen;
}

uint32 PCAPPacketHeader::getCapturedLength() const
{
    return m_InclLen;
}

void PCAPPacketHeader::setTimestamp(const Time& _time)
{
    m_Time = _time;
}

void PCAPPacketHeader::setCapturedLength(uint32 incl_len)
{
    m_InclLen = incl_len;
}

void PCAPPacketHeader::setOriginalLength(uint32 orig_len)
{
    m_OrigLen = orig_len;
}
}