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

#ifndef _RCDCAP_CAPTURE_HH_
#define _RCDCAP_CAPTURE_HH_

#include "rcdcap/global.hh"
#include "rcdcap/sink.hh"
#include "rcdcap/memory.hh"
#include "rcdcap/common-buffer.hh"

#include <boost/thread.hpp>
#include <boost/asio.hpp>
#include <boost/date_time/posix_time/posix_time_types.hpp>

#include <thread>
#include <tuple>
#include <string>
#include <fstream>
#include <functional>

#include <pcap.h>

namespace RCDCap
{
class Source;

class Sink;
typedef boost::shared_ptr<Sink> SinkPtr;

//! A base class of every Source object, which defines the common interface.
class DLL_EXPORT Source
{
protected:
    SinkPtr     m_Sink;         //!< A pointer to the Sink object which is going to receive the data.
public:
    //! Constructor.
    explicit Source() {}
    
    //! Destructor.
    virtual ~Source()=0;
    
    /*! \brief Sets the Sink object to which the data from the Source object is going to flow.
     *  \param _sink    a pointer to the Sink object.
     */
    virtual void attach(const SinkPtr& _sink);

    //! Returns the main sink attached to this Source object.
    SinkPtr getMainSink();
};

//! A base class of every Source object, which is used for capturing data from a physical entity, such as a file, network device, etc.
class DLL_EXPORT DataSource: public Source
{
public:
    //! The handler type which is used when a premature termination is commenced.
    typedef std::function<void ()> termination_handler;
protected:
    CommonBuffer                    m_Buffer;           //!< An internal buffer, which is used for keeping the packets during processing and consequent write to the Sink object.
    boost::asio::io_service&        m_IOService;        //!< ASIO I/O service; it provides the facilities for executing asynchronous operations.
    termination_handler             m_TermHandler;      //!< The termination handler is executed when the capture exits prematurely the capturing loop.
    size_t                          m_BurstSize,        //!< Maximum packets sent to the next element in the pipeline.
                                    m_Timeout;          //!< Time to wait in milliseconds before sending the packet to the next element in the pipeline.
public:
    /*! \brief Constructor
    * \param io_service     a reference to the ASIO I/O service.
    * \param hnd            a termination handler that must be executed when the capturing loop exits prematurely.
    * \param buffer_size    the size of the internal buffer.
    * \param memory_locking indicates whether buffer memory locking is enabled.
    * \param burst_size     how many packets should be sent to the next element in the pipeline at higher load.
    * \param timeout        how much time to wait in milliseconds before sending the packet to the next element in the pipeline.
    */ 
    explicit DataSource(boost::asio::io_service& io_service,
                        termination_handler hnd,
                        size_t buffer_size,
                        bool memory_locking,
                        size_t burst_size,
                        size_t timeout);
    
    //! Destructor.
    virtual ~DataSource() {}
    
    //! \warning Copying is forbidden by design.
    DataSource(const DataSource&)=delete;
    
    //! \warning Assignment is forbidden by design.
    DataSource& operator=(const DataSource&)=delete;
    
    //! Returns a reference to the internal buffer.
    CommonBuffer& getBuffer();
    
    //! Starts the capturing process in asynchronous mode.
    virtual void startAsync()=0;
    
    //! Starts the capturing process in the current thread.
    virtual void start()=0;
    
    //! Stops the capturing process.
    virtual void stop()=0;
    
    /*! \brief Sets the BPF filter expression
     *  \param expr     the expression that is going to be used for filtering.
     */
    virtual void setFilterExpression(const std::string& expr)=0;
    
    //! Returns the name of the source that is currently being used.
    virtual std::string getName() const=0;
    
    //! Returns true if the source, which is currently opened, is a file.
    virtual bool isFile() const=0;
    
    //! Returns the link type as specified in the libpcap documentation.
    virtual int getLinkType() const=0;
    
    //! Returns the snapshot length.
    virtual int getSnapshot() const=0;
    
    //! Returns the link type as a string.
    virtual std::string getLinkTypeName() const=0;
    
    //! Returns the total amount of packets that have been captured by this object.
    virtual size_t getPacketsCaptured() const=0;
    
    //! Returns the total amount of packets that have been captured by the kernel.
    virtual size_t getPacketsCapturedKernel() const=0;
    
    //! Returns the total amount of packets dropped by the kernel.
    virtual size_t getPacketsDroppedKernel() const=0;
    
    //! Returns the total amount of packets dropped by the driver.
    virtual size_t getPacketsDroppedDriver() const=0;
    
    //! Returns the total amount of packets dropped due to buffer overflow.
    virtual size_t getPacketsDroppedBuffer() const=0;
    
    //! Returns the current burst size.
    size_t getBurstSize() const { return m_BurstSize; }
};

/*! \brief The data source
 *
 *  This class is mostly a wrapper around the libpcap functions for capturing data from a data source.
 */
class DLL_EXPORT PCAPDataSource: public DataSource
{
    std::string                         m_Source;           //!< The name of the source.
    bpf_program                         m_Filter;           //!< The libpcap filter.
    pcap_t*                             m_Handle;           //!< The libpcap handle.
    PacketInfo*                         m_Current;          //!< Pointer to the beginning of a packet burst.
    
    size_t                              m_PacketsLostBuff;  //!< The total amount of packets lost due to buffer overflow.
    size_t                              m_PacketsCaptured;  //!< The total amount of packets captured by the application.
public:
    /*! \brief Constructor
     * \param io_service    a reference to the ASIO I/O service.
     * \param hnd           a termination handler that must be executed when the capturing loop exits prematurely.
     * \param buffer_size   the size of the internal buffer.
     * \param memory_locking indicates whether buffer memory locking is enabled.
     * \param burst_size     how many packets should be sent to the next element in the pipeline at higher load.
     * \param timeout        how much time to wait in milliseconds before sending the packet to the next element in the pipeline.
     */ 
    explicit PCAPDataSource(boost::asio::io_service& io_service,
                            termination_handler hnd,
                            size_t buffer_size,
                            bool memory_locking,
                            size_t burst_size,
                            size_t timeout);

    //! Destructor.
     ~PCAPDataSource();

    //! \warning Copying is forbidden by design.
    PCAPDataSource(const PCAPDataSource&)=delete;
    
    //! \warning Assignment is forbidden by design.
    PCAPDataSource& operator=(const PCAPDataSource&)=delete;

    //! Starts the capturing process in asynchronous mode.
    virtual void startAsync();
    
    //! Starts the capturing process in the current thread.
    virtual void start();
    
    //! Stops the capturing process.
    virtual void stop();
    
    /*! Opens the default device as a source; usually, this is one of Ethernet controllers.
     *  \param snaplen  the maximum snapshot length.
     */
    void openDefaultDevice(size_t snaplen);
    
    /*! \brief Opens the specified device as a source
     *  \param dev      the name of the device.
     *  \param snaplen  the maximum snapshot length.
     */
    void openDevice(const std::string& dev, size_t snaplen);
    
    //! Opens the standard input as a source.
    void openStdin();
    
    /*! \brief Opens the specified file as a source
     *  \param filename the name of the file that is going to be opened.
     */
    void openFile(const std::string& filename);
    
    /*! \brief Sets the BPF filter expression
     *  \param expr     the expression that is going to be used for filtering.
     */
    virtual void setFilterExpression(const std::string& expr);
    
    //! Returns the name of the source that is currently being used.
    virtual std::string getName() const;
    
    //! Returns true if the source, which is currently opened, is a file.
    virtual bool isFile() const;
    
    //! Internal function for wrapping purposes. It returns the libpcap handle.
    pcap_t* _getHandle(); 
    
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
    //! Common function for opening devices through libpcap.
    void openDevice(size_t snaplen, char* errbuf);
    
    //! Wrapper around the libpcap_dispatch function.
    void dispatch();
    
    //! Wrapper around the libpcap_dispatch function when the dummy mode is activated
    void dispatchDummy();

    //! Intermediate handler which adapts the handler that was passed to PCAPDataSource::start.
    static void handler(u_char* args, const pcap_pkthdr* header, const u_char* packet);
    
    //! Just counts the packets.
    static void dummyHandler(u_char* args, const pcap_pkthdr* header, const u_char* packet);
};
}

#endif /* _RCDCAP_CAPTURE_HH_ */
