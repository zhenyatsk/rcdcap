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

#ifndef _RCDCAP_HP_ERM_PROCESSOR_HH_
#define _RCDCAP_HP_ERM_PROCESSOR_HH_

#include "rcdcap/global.hh"
#include "rcdcap/decapsulating-processor.hh"
#include "rcdcap/source.hh"
#include "rcdcap/packet-headers.hh"

namespace RCDCap
{
#pragma pack(push, 1)
//! Specifies the fields in the HP ERM header and provides a convenient way to access them.
class HPERMHeader
{
    enum
    {
        BF_UNKNOWN3,        //!< The index of a field of unspecified data.
        BF_PRIORITY,        //!< The index of the priority bit field in HP ERM format.
        BF_CANONICAL,       //!< The index of the canonical format bit, supposedly, if they follow the 802.1Q format to some extend.
        BF_VLAN_ID          //!< The index of VLAN identifier bit field.
    };
    
    static const uint8 m_PriorityLUT[]; //!< Provides mapping of the HP ERM priorities to the ones specified in IEEE 802.1Q

    NetworkByteOrder<uint32>                            m_Unknown1; //!< Unspecified data.
    NetworkByteOrder<uint32>                            m_Unknown2; //!< Unspecified data.
    NetworkByteOrderBitfield<uint32, 8, 3, 1, 12, 8>    m_AttrPack; //!< The variable that is holding most of the bit fields.
public:
    //! Constructor.
    HPERMHeader() { static_assert(sizeof(HPERMHeader) == 12, "invalid header size"); }
    
    //! Returns the priority in IEEE 802.1Q format.
    uint8 getPriority() const { return m_PriorityLUT[m_AttrPack.get<BF_PRIORITY>()]; }
    
    //! Returns true if the canonical format bit is set.
    bool isCanonical() const { return static_cast<bool>(m_AttrPack.get<BF_CANONICAL>()); }
    
    //! Returns the VLAN identifier.
    uint16 getVLAN() const { return static_cast<uint16>(m_AttrPack.get<BF_VLAN_ID>()); }
};
#pragma pack(pop)

/*! \brief The processor that is used for decapsulating the proprietary HP ERM protocol.
 *
 *  Algorithm for decapsulating the protocol and applying the 802.1Q VLAN tag is shown below.
 *
 *  \image html erm-decapsulation.png General algorithm for decapsulating HP ERM.
 *
 *  Overall, the algorithm follows the same decapsulation principles that are
 *  explained for RCDCap::ERSPANProcessor. The only difference is that it
 *  includes an additional branch which is just for the socket-based approach
 *  (RCDCap::HPERMUDPDataSource) because the network stack has already stripped
 *  the Ethernet and the UDP header. It goes straight to decapsulating the protocol.
 *  Also, the algorithm shown above does not include any sanity checks related
 *  to the captured packet length, which are actually included in the real implementation.
 */
class DLL_EXPORT HPERMProcessor: public DecapsulatingProcessor
{
    bool            m_VLANEnabled;  //!< Indicates whether 802.1Q tagging is enabled.
    size_t          m_UDPPort;      //!< The UDP port on which the HP ERM packets are being sent.
public:
    /*! \brief Constructor.
     *  \param io_service   a reference to the Boost.ASIO I/O Service.
     *  \param buffer       a reference to the pipeline common buffer.
     *  \param udpport      the UDP port on which the HP ERM packets are being sent.
     *  \param vlan_enabled enables 802.1Q tagging by the processor.
     */
    HPERMProcessor(boost::asio::io_service& io_service, CommonBuffer& buffer, size_t udpport, bool vlan_enabled);
    
    //! Destructor.
    virtual ~HPERMProcessor();
    
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
     *  \return             on success the function returns true.
     */
    void processImpl(PacketInfo* packet_info);
};

//! A UDP socket-based data source which is specifically built for HP ERM.
class DLL_EXPORT HPERMUDPDataSource: public DataSource
{
    bool                            m_Active;       //!< A flag that is used for stopping the capturing loop.
    std::array<char, 8192>          m_RecvBuffer;   //!< The buffer which is used for receiving data from the network stack.
    boost::asio::ip::udp::socket    m_Socket;       //!< The UDP socket.
    size_t                          m_UDPPort;      //!< The UDP port on which the data source is listening.

    size_t                          m_PacketsLostBuff;  //!< The total amount of packets lost due to buffer overflow.
    size_t                          m_PacketsCaptured;  //!< The total amount of packets captured by the application.
public:
    /*! \brief Constructor
     *  \param io_service     a reference to the ASIO I/O service.
     *  \param hnd            a termination handler that must be executed when the capturing loop exits prematurely.
     *  \param buffer_size    the size of the internal buffer.
     *  \param memory_locking indicates whether buffer memory locking is enabled.
     *  \param burst_size     the cap of packets in a burst.
     *  \param timeout        the time spent waiting before handing the packet burst to the next element in the pipeline.
     *  \param udpport        the UDP port on which the data source is going to listen for encapsulated data.
     */ 
    explicit HPERMUDPDataSource(boost::asio::io_service& io_service,
                                termination_handler hnd,
                                size_t buffer_size, bool memory_locking,
                                size_t burst_size, size_t timeout,
                                size_t udpport);
    
    //! Destructor.
    virtual ~HPERMUDPDataSource();
    
    //! Starts the capturing process in asynchronous mode.
    virtual void startAsync();
    
    //! Starts the capturing process in the current thread.
    virtual void start();
    
    //! Stops the capturing process.
    virtual void stop();
    
    /*! \brief Sets the BPF filter expression
     *  \param expr     the expression that is going to be used for filtering.
     */
    virtual void setFilterExpression(const std::string& expr);
    
    //! Returns the name of the source that is currently being used.
    virtual std::string getName() const;
    
    //! Returns true if the source, which is currently opened, is a file.
    virtual bool isFile() const;
    
    //! Returns the link type as specified in the libpcap documentation.
    virtual int getLinkType() const;
    
    //! Returns the snapshot length.
    virtual int getSnapshot() const;
    
    //! Returns the link type as a string.
    virtual std::string getLinkTypeName() const;

    //! Returns the total amount of packets that have been captured by this object.
    virtual size_t getPacketsCaptured() const;
    
    //! Returns the total amount of packets that have been captured by the kernel.
    virtual size_t getPacketsCapturedKernel() const;
    
    //! Returns the total amount of packets dropped by the kernel.
    virtual size_t getPacketsDroppedKernel() const;
    
    //! Returns the total amount of packets dropped by the driver.
    virtual size_t getPacketsDroppedDriver() const;

    //! Returns the total amount of packets dropped due to buffer overflow.
    virtual size_t getPacketsDroppedBuffer() const;
private:
    /*! \brief The handler which is called when new data is received.
     *  \param error                the error code which indicates whether some error has occurred during the receive operation.
     *  \param bytes_transferred    how many bytes have been received.
     */ 
    void receiveHandler(const boost::system::error_code& error, std::size_t bytes_transferred);
    
    /*! \brief The handler which is called when new data is received and dummy mode had been enabled.
     *  \param error                the error code which indicates whether some error has occurred during the receive operation.
     *  \param bytes_transferred    how many bytes have been received.
     */
    void dummyReceiveHandler(const boost::system::error_code& error, std::size_t bytes_transferred);
    
    /*! \brief Copies the data from the buffer for receiving data to the common buffer.
     *  \param len      how many bytes have been received in the buffer for receiving data.
     */
    void pushData(size_t len);
};
}

#endif /* _RCDCAP_HP_ERM_PROCESSOR_HH_ */