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

#ifndef _RCDCAP_GRE_PROCESSOR_HH_
#define _RCDCAP_GRE_PROCESSOR_HH_

#include "rcdcap/global.hh"
#include "rcdcap/decapsulating-processor.hh"
#include "rcdcap/byte-order.hh"

namespace RCDCap
{
#pragma pack(push, 1)
/*! \brief Contains a list of all of the available protocols that could be
 *         transfered through GRE.
 */
enum GREProtocolType
{
    RCDCAP_GRE_ERSPAN = 0x88be, // Cisco
    RCDCAP_GRE_ERSPAN_VMWARE = 0x6558      //!< CISCO ERSPAN protocol number.

};

/*! \brief Specifies the fields in the GRE header and provides a convenient way
 *         to access them.
 */
class GREHeader
{
    enum
    {
        BF_CHECKSUM_BIT,            //!< The index of the checksum bit.
        BF_ROUTING_BIT,             //!< The index of the routing bit.
        BF_KEY_BIT,                 //!< The index of the key bit.
        BF_SEQUENCE_NUMBER_BIT,     //!< The index of the sequence number bit.
        BF_STRICT_SOURCE_ROUTE_BIT, //!< The index of the strict source route bit.
        BF_RECURSION_CONTROL,       //!< The index of the recursion control bit field.
        BF_FLAGS,                   //!< The index of the flags bit field.
        BF_VERSION                  //!< The index of the version bit field.
    };
    NetworkByteOrderBitfield<uint16, 1, 1, 1, 1, 1, 3, 5, 3> m_Flags;           //!< The variable that is holding some of the bit fields.
    NetworkByteOrder<uint16>                                 m_ProtocolType;    //!< The protocol that is carried through GRE.
public:
    //! Constructor.
    GREHeader() { static_assert(sizeof(GREHeader) == 4, "invalid header size"); }
    
    //! Returns true if the checksum bit is set and the checksum optional field is present, respectively.
    bool isCheksumPresent() const { return static_cast<bool>(m_Flags.get<BF_CHECKSUM_BIT>()); }
    
    //! Returns true if the sequence number bit is set and the sequence number optional field is present, respectively.
    bool isSeqNumPresent() const { return static_cast<bool>(m_Flags.get<BF_SEQUENCE_NUMBER_BIT>()); }
    
    //! Returns the version of the GRE protocol that is currently employed.
    uint8 getVersion() const { return static_cast<uint8_t>(m_Flags.get<BF_VERSION>()); }
    
    //! Returns the protocol that is carried through GRE.
    uint16 getProtocolType() const { return m_ProtocolType; }
};

/*! \brief Specifies the fields in the checksum optional part of the GRE header and
 *         provides a convenient way to access them.
 */
class GREChecksumField
{
    NetworkByteOrder<uint16>                        m_Checksum;     //!< GRE checksum field.
    NetworkByteOrder<uint16>                        m_Offset;       //!< GRE reserved field.
public:
    //! Constructor.
    GREChecksumField() { static_assert(sizeof(GREChecksumField) == 4, "invalid header size"); }
    
    //! Returns the checksum.
    uint16 getChecksum() const { return m_Checksum; }
};

/*! \brief Specifies the fields in the sequence number optional part of the GRE header and
 *         provides a convenient way to access them.
 */
class GRESeqNumField
{
    NetworkByteOrder<uint32>                        m_SeqNum;       //!< GRE sequence number field.
public:
    //! Constructor.
    GRESeqNumField() { static_assert(sizeof(GRESeqNumField) == 4, "invalid header size"); }
    
    //! Returns the sequence number.
    uint32 getSequenceNumber() const { return m_SeqNum; }
};

#pragma pack(pop)

class DLL_EXPORT GREProcessor: public DecapsulatingProcessor
{
public:
    /*! \brief Constructor.
     *  \param io_service   a reference to the Boost.ASIO I/O Service.
     *  \param buffer       a reference to the pipeline common buffer.
     */
    GREProcessor(boost::asio::io_service& io_service, CommonBuffer& buffer);
    
    //! Destructor.
    virtual ~GREProcessor() {}
    
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