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

#ifndef _RCDCAP_DECAPSULATION_PROCESSOR_HH_
#define _RCDCAP_DECAPSULATION_PROCESSOR_HH_

#include "rcdcap/global.hh"
#include "rcdcap/processor.hh"
#include "rcdcap/packet-headers.hh"

namespace RCDCap
{
/*! \brief Implements some common functions between all of the decapsulating
 *         processors.
 *
 *  The most significant function provided by this class is a algorithm for
 *  extracting the header and the protocol type of an IP packet. The actual
 *  algorithm is shown below.
 *
 *  \image html gen-decap-algorithm.png General algorithm for finding the first header after the IP header and what is its protocol type.
 *
 *  That is a simplified version of the algorithm executed inside the
 *  DecapsulatingProcessor::getProtocolOffset member function. It does not
 *  contain any sanity checks related to the captured packet length -- just
 *  to make it more clean and easy to understand. First, it checks whether it is
 *  working with an Ethernet source. If not, it returns with failure because
 *  other Layer 2 protocols are currently unsupported. Otherwise, it determines
 *  the type of Ethernet header (Ethernet II or IEEE 802.1Q) and appends the correct
 *  offset. Afterwards, it determines whether the frame is carrying an IPv4 or IPv6
 *  packet. If it is one of them, the correct offset gets appended and the protocol
 *  type gets set to the value provided in the IP header. Every other branch that
 *  does not result into extracting the IP header and the protocol type returns
 *  a failure.
 */
class DLL_EXPORT DecapsulatingProcessor: public Processor
{
protected:
    //! The Boost.ASIO I/O Service.
    boost::asio::io_service&        m_IOService;
    //! Reference to the common buffer.
    CommonBuffer&                   m_CommonBuffer;
public:
    /*! \brief Constructor.
     *  \param io_service   a reference to the Boost.ASIO I/O Service.
     *  \param buffer       a reference to the pipeline common buffer.
     */
    DecapsulatingProcessor(boost::asio::io_service& io_service, CommonBuffer& buffer);
protected:
    /*! \brief Computes the offset of the header that is after the IP header and
     *         outputs the protocol which is used.
     *  \param packet_info  a pointer to the information about the packet.
     *  \param offset       the offset that was computed after the execution of
     *                      this function.
     *  \param proto        the protocol that is used in the processed data.
     *  \return on success the function returns true.
     */
    bool getProtocolOffset(PacketInfo* packet_info, size_t& offset,
                           ProtocolType& proto);
};
}

#endif /* _RCDCAP_DECAPSULATION_PROCESSOR_HH_ */
