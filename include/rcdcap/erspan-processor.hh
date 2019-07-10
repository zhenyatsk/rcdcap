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

#ifndef _RCDCAP_ERSPAN_PROCESSOR_HH_
#define _RCDCAP_ERSPAN_PROCESSOR_HH_

#include "rcdcap/global.hh"
#include "rcdcap/decapsulating-processor.hh"
#include "rcdcap/byte-order.hh"

namespace RCDCap
{
#pragma pack(push, 1)
/*! \brief Specifies the fields in the CISCO ERSPAN header and provides a convenient way to access them
 *
 *  ERSPAN -- as it is called in CISCO's terminology -- is the protocol
 *  supported by some of the network equipment manufactored by CISCO. It is a
 *  proprietary protocol and it can be deployed to enable encapsulated remote port
 *  mirroring.
 */
class ERSPANHeader
{
    enum
    {
        BF_VERSION,     //!< The index of the version bit field.
        BF_VLAN_ID      //!< The index of the VLAN identifier bit field.
    };
    enum
    {
        BF_PRIORITY,    //!< The index of the priority bit field.
        BF_UNKNOWN2,    //!< The index of a bit that contains unknown data.
        BF_DIRECTION,   //!< The index of the direction bit.
        BF_TRUNCATED,   //!< The index of the truncated bit.
        BF_SPAN_ID      //!< The index of the span identifier bit field.
    };
    NetworkByteOrderBitfield<uint16, 4, 12>             m_Ver_VID;  //!< The variable that is holding the version and the VLAN ID bit fields.
    NetworkByteOrderBitfield<uint16, 3, 1, 1, 1, 10>    m_AttrPack; //!< The variable that is holding the rest of the bit fields.
    NetworkByteOrder<uint32>                            m_Unknown7; //!< A variable that contains unspecified data.
public:
    //! Constructor.
    ERSPANHeader() { static_assert(sizeof(ERSPANHeader) == 8, "invalid header size"); }
    
    //! Returns the version of the ERSPAN protocol.
    uint16 getVersion() const { return m_Ver_VID.get<BF_VERSION>(); }
    
    //! Returns the VLAN identifier.
    uint16 getVLAN() const { return m_Ver_VID.get<BF_VLAN_ID>(); }
    
    //! Returns the priority.
    uint16 getPriority() const { return m_AttrPack.get<BF_PRIORITY>(); }
    
    //! Returns the direction.
    bool getDirection() const { return static_cast<bool>(m_AttrPack.get<BF_DIRECTION>()); }
    
    //! Returns true if the packet is truncated.
    bool isTruncated() const { return static_cast<bool>(m_AttrPack.get<BF_TRUNCATED>()); }
    
    //! Returns the SPAN identifier.
    uint16 getSpanID() const { return m_AttrPack.get<BF_SPAN_ID>(); }
};
#pragma pack(pop)

/*! \brief The processor that is used for decapsulating the proprietary CISCO ERSPAN protocol.
 *
 *  Algorithm for decapsulating the protocol and applying the 802.1Q VLAN tag is shown below.
 *
 *  \image html erspan-decapsulation.png Simplified algorithm for decapsulating CISCO ERSPAN.
 *
 *  In general, the algorithm first gets information about the offset and the protocol type
 *  by following the algorithm explained in the figure above. If in fact
 *  this algorithm returns with failure, the procedure does not proceed and the packet
 *  gets handed to the next element in the pipeline. Otherwise, it must determine whether
 *  the protocol used for transporting data is GRE and whether there are
 *  some optional GRE fields. According to the data that was provided from one of the
 *  core routers of University of Twente's network, CISCO ERSPAN uses the old GRE
 *  specification from RFC 1701. More specifically, it uses the optional Checksum and
 *  the Sequence number GRE fields. The Checksum is the only field present in the
 *  newer version RFC 2784. So the Sequence Number check is purely for backward compatibility.
 *  If it gets proven that some other optional fields from the older GRE version are used, it
 *  would be trivial to update the algorithm with some additional checks and offset modifications.
 *
 *  There is an important branching at the end of the algorithm, which enables decapsulation
 *  without 802.1Q tagging. It is in the form of the "Is VLAN tagging enabled?" check.
 *  It is included for any application that does not have proper VLAN support.
 *
 *  After everything is done, the captured length and the original length of the packet must
 *  be updated and the packet gets passed to the next element in the pipeline. It is important
 *  to note that any packet must pass, even if some of the checks at the beginning fail.
 *  There could be another processor in the pipeline that can process the packet.
 *  Even if the packet does not get processed by any processor, it still may contain
 *  vital information, so it should reach the data sink.
 */
class DLL_EXPORT ERSPANProcessor: public DecapsulatingProcessor
{
    bool m_VLANEnabled;  //!< Indicates whether 802.1Q tagging is enabled.
public:
    /*! \brief Constructor.
     *  \param io_service   a reference to the Boost.ASIO I/O Service.
     *  \param buffer       a reference to the pipeline common buffer.
     *  \param vlan_enabled enables 802.1Q tagging by the processor.
     */
    ERSPANProcessor(boost::asio::io_service& io_service, CommonBuffer& buffer, bool vlan_enabled);
    
    //! Destructor.
    virtual ~ERSPANProcessor() {}
    
    /*! \brief Notifies the processor about new data.
     *  \param packet_info  a pointer to the information about the first packet in the burst.
     *  \param packets      the number of packets in the burst.
     */
    virtual void notify(PacketInfo* packet_info, size_t packets) override;
private:
    /*! \brief Dispatches packets for processing and then hands the data to the next element in the pipeline.
     * 
     *  \param packet_info  a pointer to the information about the first packet in the burst.
     *  \param packets      the number of packets in the burst.
     */
    void process(PacketInfo* packet_info, size_t packets);
    
    /*! \brief Processes the data that is delivered from a particular DataSource.
     * 
     *  The processor strips all of the headers that are associated with the encapsulation and
     *  keeps only the data that is after them. The only data that is kept is the VLAN identifier
     *  and the priority which are inserted in the Ethernet header of the mirrored packet.
     *  \warning Do not assume that the resulting header is the original one; the device that is
     *           sending the data could have overridden some of the fields with its own values.
     *  \param packet_info  a pointer to the information about the packet.
     */
    void processImpl(PacketInfo* packet_info);
};
}

#endif /* _RCDCAP_ERSPAN_PROCESSOR_HH_ */