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

#ifndef _RCDCAP_SINK_HH_
#define _RCDCAP_SINK_HH_

#include "rcdcap/global.hh"
#include "rcdcap/source.hh"
#include "rcdcap/types.hh"
#include "rcdcap/common-buffer.hh"
#include "rcdcap/packet-headers.hh"

#include <boost/asio.hpp>
#include <pcap.h>

#include <fstream>
#include <vector>
#include <thread>

namespace RCDCap
{
class Source;
class DataSource;

//! Sink base class.
class DLL_EXPORT Sink
{
public:
    //! Constructor.
    explicit Sink() {}
    
    //! Destructor.
    virtual ~Sink() {}
    
    /*! \brief Abstract function which is called when a burst of packets is processed from
     *         the previous element inside RCDCap's pipeline.
     *  \param packet_info  a pointer to the information about the first packet in the burst.
     *  \param packets      the number of packets in the burst.
     */
    virtual void notify(PacketInfo* packet_info, size_t packets)=0;
};

//! A shorthand for a shared_ptr to a Sink object.
typedef boost::shared_ptr<Sink> SinkPtr;

/*! \brief Provides some of the common facilities for a Sink object that outputs the data to a particular entity,
 *         such as hard drive, network device, etc.
 */
class DLL_EXPORT DataSink: public Sink
{
protected:
    DataSource&                 m_DataSource;   //!< A reference to the data source.
    size_t                      m_Processed;    //!< The variable that is holding the number of packets that have been processed.
    boost::asio::io_service&    m_IOService;    //!< The Boost.ASIO I/O Service.
public:
    /*! \brief Constructor.
     *  \param io_service   a reference to the Boost.ASIO I/O Service.
     *  \param src          a reference to the data source.
     */ 
    explicit DataSink(boost::asio::io_service& io_service, DataSource& src);
    
    //! Destructor.
    virtual ~DataSink() {}
    
    //! Returns the number of packets that have been processed.
    size_t getProcessed() const;
};

/*! \brief Outputs the data to a text stream.
 *
 * It follows the same synchronization principles that are described in
 * RCDCap::BinarySink's documentation. Instead of outputting packets in PCAP
 * format, it outputs basic information about the packet. It is just the
 * source and the destination MAC address in the Ethernet frame. The application
 * is not intended to be used for outputting human readable traffic breakdown, so
 * this data sink is provided just for debugging purposes. The information could be
 * easily piped through the binary sink and the standard output to some application
 * like tcpdump. Therefore, it is not crucial to include any protocol dissectors.
 */
class DLL_EXPORT TextSink: public DataSink
{
public:
    /*! \brief Constructor.
     *  \param io_service   a reference to the Boost.ASIO I/O Service.
     *  \param src          a reference to the data source.
     */
    explicit TextSink(boost::asio::io_service& io_service, DataSource& src);
    
    //! Destructor.
    virtual ~TextSink() {}
protected:
    /*! \brief An intermediate function that enqueues the write requests.
     *  \param os               a reference to the stream on which the data is going to be dumped in text format.
     *  \param packet_info      a pointer to the information about the first packet in the burst.
     *  \param packets          the number of packets in the burst.
     */
    void writeInfo(std::ostream& os, PacketInfo* packet_info, size_t packets);
private:
    /*! \brief The actual implementation of the function that writes the data to the standard output.
     *  \param os               a reference to the stream on which the data is going to be dumped in text format.
     *  \param packet_info      a pointer to the information about the first packet in the burst.
     *  \param packets          the number of packets in the burst.
     */
    void writeInfoImpl(std::ostream& os, PacketInfo* packet_info, size_t packets);
};

/*! \brief Outputs the data to the standard output in text format.
 *
 *  For more information about the actual implementation, refer to RCDCap::TextSink.
 */
class DLL_EXPORT ConsoleSink: public TextSink
{
public:
    /*! \brief Constructor.
     *  \param io_service   a reference to the Boost.ASIO I/O Service.
     *  \param src          a reference to the data source.
     */
    explicit ConsoleSink(boost::asio::io_service& io_service, DataSource& src);
    
    //! Destructor.
    virtual ~ConsoleSink();
    
    /*! \brief Writes the data to the standard output in text format.
     *  \param packet_info      a pointer to the information about the first packet in the burst.
     *  \param packets          the number of the packets in the burst.
     */
    virtual void notify(PacketInfo* packet_info, size_t packets) override;
};

/*! \brief Outputs the data to a text file.
 *
 *  For more information about the actual implementation, refer to RCDCap::TextSink.
 */
class DLL_EXPORT TextFileSink: public TextSink
{
    std::fstream    m_File; //!< The C++ file stream which represents the file in which the data is being dumped.
public:
    /*! \brief Constructor.
     *  \param io_service   a reference to the Boost.ASIO I/O Service.
     *  \param src          a reference to the data source.
     *  \param filename     the name of the text file which is going to be used for dumping the data.
     */
    explicit TextFileSink(boost::asio::io_service& io_service, DataSource& src, const std::string& filename);
    
    //! Destructor.
    virtual ~TextFileSink();
    
    /*! \brief Writes the data to the text file.
     *  \param packet_info      a pointer to the information about the first packet in the burst.
     *  \param packets          the number of packets in the burst.
     */
    virtual void notify(PacketInfo* packet_info, size_t packets) override;
};

/*! \brief Outputs the data to a binary stream.
 *
 *  There are two subclasses of the main RCDCap::BinarySink class,
 *  which are called RCDCap::BinaryConsoleSink and RCDCap::BinaryFileSink.
 *  The former is used for outputting packets in PCAP format to the standard
 *  output. While the latter is used for outputting them to a PCAP file.
 *  In C++ a file stream and the standard output are represented by different types of
 *  objects, so it is required to have separate classes for both cases. However,
 *  most of the work is actually done inside the RCDCap::BinarySink superclass
 *  which receives a reference to the output stream from both classes and outputs
 *  data in the same fashion (PCAP format).
 *
 *  \image html binary-sink.png An overview of the internal algorithms used in RCDCap::BinarySink for outputting packets.
 *
 *  RCDCap::BinarySink has two mechanism for enqueuing new write operations (see the figure above).
 *  The first option is to enqueue a write operation when a notification about a
 *  new packet arrives at the data sink. To guarantee
 *  sequential order, before actually enqueuing the packet, there is a check whether
 *  it is the first packet in the buffer. If this requirement is not met, the function
 *  for notifying about new packets returns. Otherwise, a new write operation task is
 *  enqueued inside the thread pool's task queue to be executed in separate thread.
 *  The write operation task handler usually contains a
 *  synchronous blocking write operation. After the write operation is completed,
 *  it removes the packet from the common buffer. Then, it checks whether there are
 *  other packets inside the buffer. If there is another packet, it tries to
 *  enqueue a write operation task. Both the notification handler and the write
 *  operation task handler may try to enqueue the same packet at the same time.
 *  To ensure that there is only one resulting write operation task, the ``Processed
 *  Flag'' inside the additional header associated with the packet is used. In
 *  RCDCap's implementation, the "Processed Flag" is defined as an atomic flag.
 *  C++11 provides a function that guarantees that the resetting of the flag
 *  will be atomic, i.e. the operation gets executed completely before another
 *  gets started. This means that if both operations try to reset the flag at the same time,
 *  only one will succeed. Also, the packet notification handler
 *  always sets first the "Processed Flag", which ensures that there will be always
 *  one function that manages to enqueue a new operation. The packet notification
 *  handler could then do the check that ensures sequential order.
 *  If it fails, there is going to be another write operation task that can
 *  enqueue the packet after it completes. So the constant flow of data to the
 *  storage device does not get broken. On the other hand, by setting the flag
 *  before the check, it ensures that if another write operation task tries to
 *  enqueue a task for this packet at the same time, it will succeed. Otherwise, it
 *  is possible that both the sequential order check and the enqueing-related check fail at the same
 *  time and the pipeline gets stuck because these are the only functions in which
 *  the packet can be enqueued for writing.
 *
 *  It is important to note that the synchronous write operation results in one of
 *  the threads inside the application getting scheduled every time when
 *  there is a write operation to a storage device. Currently, Linux does not provide
 *  a viable alternative. Another possible solution is to use synchronous operation
 *  in non-blocking mode. It does not work with Boost ASIO with its default settings.
 *  The main reason is the implementation provided by Linux for the epoll
 *  event notification facility which does not provide this behavior due
 *  to some performance concerns. Boost ASIO also provides an implementation
 *  based on the select facility that supports this behavior, but it
 *  indeed had some performance issues in some of the preliminary tests of the application. Other viable option is
 *  to use the asynchronous operations provided in the <a href="http://pubs.opengroup.org/onlinepubs/9699919799/">POSIX</a> standard.
 *  It turns out that they are actually implemented in userland by using threads,
 *  which is not different from using synchronous operations in separate threads. The last option was
 *  to use the kernel asynchronous write operation syscalls. They lack a proper
 *  currently supported API. At the same time, they usually fall back to synchronous operations if
 *  the file is not opened in direct mode. Implementing the last solution with direct
 *  mode would greatly increase the complexity of the buffering solution, reduce the
 *  portability and does not guarantee any performance gain. There is currently an
 *  experimental branch in RCDCap's Mercurial repository, which implements the discussed
 *  solution. It is in non-direct mode, which does not result in any performance gain.
 *  So any eventual implementation in direct mode is postponed indefinitely.
 */
class DLL_EXPORT BinarySink: public DataSink
{
public:
    /*! \brief Constructor.
     *  \param io_service   a reference to the Boost.ASIO I/O Service.
     *  \param src          a reference to the data source.
     */
    explicit BinarySink(boost::asio::io_service& io_service, DataSource& src);
    
    //! Destructor.
    virtual ~BinarySink();
    
    /*! \brief Writes the PCAP file header; it is used by the subclasses of that class.
     *  \param fs   a reference to the output stream.
     */
    void writeHeader(std::ostream& fs);
protected:
    /*! \brief An intermediate function that enqueues the write requests.
     *  \param os               a reference to the stream on which the data is going to be dumped in text format.
     *  \param packet_info      a pointer to the information about the first packet in the burst.
     *  \param packets          the number of packets in the burst.
     */
    void writePacket(std::ostream& os, PacketInfo* packet_info, size_t packets);
private:
        /*! \brief The actual implementation of the function that writes the data to the standard output.
     *  \param os               a reference to the stream on which the data is going to be dumped in text format.
     *  \param packet_info      a pointer to the information about the first packet in the burst.
     *  \param packets          the number of packets in the burst.
     */
    void writePacketImpl(std::ostream& os, PacketInfo* packet_info, size_t packets);
};

/*! \brief Outputs the data to the standard output in binary format.
 *
 *  For more information about the actual implementation, refer to RCDCap::BinarySink.
 * 
 *  \note This class is provided for the sake of consistency. It does not provide anything more substantial over the
 *        RCDCap::BinarySink base class.
 */
class DLL_EXPORT BinaryConsoleSink: public BinarySink
{
public:
    /*! \brief Constructor.
     *  \param io_service   a reference to the Boost.ASIO I/O Service.
     *  \param src          a reference to the data source.
     */
    explicit BinaryConsoleSink(boost::asio::io_service& io_service, DataSource& src);
    
    //! Destructor.
    virtual ~BinaryConsoleSink();
    
    /*! \brief Writes the data to a binary stream.
     *  \param packet_info      a pointer to the information about the first packet in the burst.
     *  \param packets          the number of packets in the burst.
     */
    virtual void notify(PacketInfo* packet_info, size_t packets) override;
};

/*! \brief Outputs the data to a binary file.
 *
 *  For more information about the actual implementation, refer to RCDCap::BinarySink.
 * 
 *  \note This class is provided for the sake of consistency. It does not provide anything more substantial over the
 *        RCDCap::BinarySink base class.
 */
class DLL_EXPORT BinaryFileSink: public BinarySink
{
    std::fstream    m_File; //!< The C++ file stream which represents the file in which the data is being dumped.
public:
    /*! \brief Constructor.
     *  \param io_service   a reference to the Boost.ASIO I/O Service.
     *  \param src          a reference to the data source.
     *  \param filename     the name of the file to which the data is going to be written.
     */
    explicit BinaryFileSink(boost::asio::io_service& io_service, DataSource& src, const std::string& filename);
    
    //! Destructor.
    virtual ~BinaryFileSink();

    /*! \brief Writes the data to a binary stream.
     *  \param packet_info      a pointer to the information about the first packet in the burst.
     *  \param packets          the number of packets in the burst.
     */
    virtual void notify(PacketInfo* packet_info, size_t packets) override;
};

enum Flags
{
    RCDCAP_SINK_OPTION_PERSIST = 1 << 0,
    RCDCAP_SINK_OPTION_IGNORE = 1 << 1,
    RCDCAP_SINK_OPTION_FORCE = 1 << 2
};

#ifndef _WIN32

/*! \brief Outputs the data to a virtual Ethernet device (TAP device).
 *
 *  It is used for outputting raw packets to a virtual Ethernet device -- TAP device in
 *  this case. The main reason for including it is that some applications do not support
 *  piping through the standard output, but on the other hand, they support capturing directly
 *  from an Ethernet device.
 *
 *  There are some other kinds of virtual devices available on Linux, but the important
 *  advantage of TAP is that it is portable. There is a Windows implementation
 *  which is part of the OpenVPN project. That could enable a future port to
 *  other operating systems. Also, on Linux the TAP device could be bridged with
 *  other network devices for the purpose of injecting traffic.
 *
 *  The basic synchronization principles (see RCDCap::BinarySink) are still
 *  followed for this data sink, but the synchronous operation is replaced by a non-blocking
 *  one. It is supported by Boost ASIO for this kind of devices. Instead of having
 *  a write operation task handler which contains a synchronous blocking write operation,
 *  an asynchronous operation is used. Basically, it does the same thing, but does not
 *  execute any write operations inside the write operation task handler. The write operation
 *  task handler in this case is just a completion handler executed when the asynchronous
 *  operation completes.
 */
class DLL_EXPORT TAPDeviceSink: public DataSink
{
    boost::asio::posix::stream_descriptor   m_SD;       //!< The stream descriptor that is representing the TAP device.
    uint32                                  m_Flags;    //!< Option flags.
public:
    /*! \brief Constructor.
     *  \param io_service       a reference to the Boost.ASIO I/O Service.
     *  \param src              a reference to the data source.
     *  \param ip               the IP that is going to be assigned to this TAP device.
     *  \param devname          the preferred name of the TAP device.
     *  \param flags            bitfield flags field.
     */
    explicit TAPDeviceSink(boost::asio::io_service& io_service, DataSource& src, uint32 ip,
                           const std::string& devname = "", uint32 flags = 0);
    
    //! Destructor.
    virtual ~TAPDeviceSink();
    
    /*! \brief Writes the data to the TAP device.
     *  \param packet_info      a pointer to the information about the first packet in the burst.
     *  \param packets          the number of packets in the burst.
     */
    virtual void notify(PacketInfo* packet_info, size_t packets) override;
private:
    /*! \brief The handler that is executed after the write operation is completed.
     *  \param packet_info          a pointer to the information about the first packet in the burst.
     *  \param packets              the number of packets left to be transferred.
     *  \param transferred_chunk    the size of the currently sucessfully transferred chunk of data.
     *  \param ec                   the error code which indicates whether some error has occurred during the write operation.
     *  \param bytes_transferred    the amount of successfully transferred bytes.
     */
    void writeCompleted(PacketInfo* packet_info, size_t packets, size_t transferred_chunk, const boost::system::error_code& ec, std::size_t bytes_transferred);
    
    /*! \brief Creates the TAP device without setting any substantial options.
     *  \param ifr                  a reference to the ifreq structure that is used when setting some options to the TAP device.
     *  \param devname              the preferred name of the TAP device.
     *  \param persistent           indicates is it required to keep the TAP device after the sink is destroyed.
     */
    void createTapDevice(struct ifreq& ifr, const std::string& devname, bool persistent);
    
    /*! \brief Sets the IP address of the TAP device.
     *  \param ifr                  a reference to the ifreq structure that is used when setting some options to the TAP device.
     *  \param sock                 a reference to the socket which is going to be opened, so that some IP related options could be set.
     *  \param ip                   the ip that is going to be assigned to this TAP device.
     */
    void setIP(struct ifreq& ifr, int& sock, uint32 ip);
    
    /*! \brief Starts the TAP device, so that it is accessible by the rest of the system.
     *  \param ifr                  a reference to the ifreq structure that is used when setting some options to the TAP device.
     *  \param sock                 the socket which is also used when starting the TAP device.
     */
    void start(struct ifreq& ifr, int sock);
private:
    /*! \brief Executes an asynchronous task to write a packet to TAP device.
     *  \param packet_info  a pointer to the first packet in the burst.
     *  \param packets      the number of packets in the burst.
     */
    void writeSequence(PacketInfo* packet_info, size_t packets);
    
    bool cleanupCargo();
};

/*! \brief Injects packets into existing Ethernet device.
 * 
 *  It generally could be used to redirect processed traffic without going through virtual network devices. Please, have in mind
 *  that injecting packets in someone else's network is considered as bad practice or straight up attack on the network. This
 *  software does not take any responsibility for any misusage. Use it with caution in networks that you have explicit permission
 *  to perform tests.
 */
class DLL_EXPORT InjectionSink: public DataSink
{
    int         m_SD;           //!< The identifier of the raw socket associated with this sink.
    mac_t       m_InterfaceMAC; //!< The MAC address of the Ethernet device.
    ip_t        m_InterfaceIP;  //!< The IP address of the Ethernet device.
public:
    /*! \brief Constructor.
     *  \param io_service   a reference to the Boost.ASIO I/O Service.
     *  \param src          a reference to the data source.
     *  \param _interface   the interface that is going to receive all packets produced by the pipeline.
     */
    explicit InjectionSink(boost::asio::io_service& io_service, DataSource& src, const std::string& _interface);
    
    //! Destructor.
    virtual ~InjectionSink();

    /*! \brief Writes the data to a Ethernet interface.
     * 
     *  The whole process tries to preserve sequential order, so that's why all functions
     *  used out here are not actually writing, but checking whether they can. Also, the whole
     *  thing serves the purpose of synchronizing the thread access which removes data races.
     * 
     *  \param packet_info  a pointer to the information about the first packet in the burst.
     *  \param packets      the number of packets in the burst.     
     */
    virtual void notify(PacketInfo* packet_info, size_t packets) override;
private:
    /*! \brief Writes a sequence/burst of packets to an Ethernet device.
     * 
     *  It injects the traffic to an Ethernet device only if the received packets are complete.
     *  Otherwise, it just discards packets.
     * 
     *  \param packet_info  a pointer to the first packet in the burst.
     *  \param packets      the number of packets in the burst.
     */
    void writeSequence(PacketInfo* packet_info, size_t packets);
};
#endif

/*! \brief Pure packet discarding sink that cleans up the pipeline.
 */
class DLL_EXPORT DiscardSink: public DataSink
{
public:
    /*! \brief Constructor.
     * 
     *  \param io_service   a reference to the Boost I/O Service.
     *  \param src          a reference to the data source.
     */
    explicit DiscardSink(boost::asio::io_service& io_service, DataSource& src);
    
    //! Destructor.
    virtual ~DiscardSink() = default;
    
    /*! \brief Notifies the sink about a new burst of packets.
     * 
     *  It just discards packets and removes them out of the common buffer.
     * 
     *  \param packet_info  a pointer to the first packet in the burst.
     *  \param packets      the number of packets in the burst.
     */
    virtual void notify(PacketInfo* packet_info, size_t packets);
};
}

#endif /* _RCDCAP_SINK_HH_ */
