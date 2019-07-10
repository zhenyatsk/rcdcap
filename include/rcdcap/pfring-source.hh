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

#ifndef _PFRING_SOURCE_HH_
#define _PFRING_SOURCE_HH_

#include "rcdcap/global.hh"
#include "rcdcap/source.hh"

#include <pfring.h>

namespace RCDCap
{
/*! \brief The data source
 *
 *  This class is mostly a wrapper around the libpfring functions for capturing data from a data source.
 */
class PF_RINGDataSource: public DataSource
{
    pfring*             m_Handle;           //!< The libpfring handle.
    bool                m_Active;           //!< A flag that is used for stopping the capturing loop
    u_int32_t           m_Snaplen;          //!< The maximum snapshot length.
    std::string         m_Name;             //!< The name of the source.

    size_t              m_PacketsLostBuff;  //!< The total amount of packets lost due to buffer overflow.
    size_t              m_PacketsCaptured;  //!< The total amount of packets captured by the application.
public:
    /*! \brief Constructor
     *  \param io_service     a reference to the ASIO I/O service.
     *  \param hnd            a termination handler that must be executed when the capturing loop exits prematurely.
     *  \param buffer_size    the size of the internal buffer.
     *  \param memory_locking indicates whether buffer memory locking is enabled.
     */ 
    explicit PF_RINGDataSource(boost::asio::io_service& io_service,
                               termination_handler hnd,
                               size_t buffer_size,
                               bool memory_locking,
                               size_t burst_size,
                               size_t timeout);
    
    //! Destructor.
    virtual ~PF_RINGDataSource();
    
    //! \warning Copying is forbidden by design.
    PF_RINGDataSource(const PF_RINGDataSource&)=delete;
    
    //! \warning Assignment is forbidden by design.
    PF_RINGDataSource& operator=(const PF_RINGDataSource&)=delete;
    
    //! Starts the capturing process in asynchronous mode.
    virtual void startAsync();
    
    //! Starts the capturing process in the current thread.
    virtual void start();
        
    //! Stops the capturing process.
    virtual void stop();
    
    /*! \brief Sets the BPF filter expression
     *  \param expr     the expression that is going to be used for filtering.
     */
    virtual void setFilterExpression(const std::string&);
    
    /*! \brief Opens the specified device as a source
     *  \param dev      the name of the device.
     *  \param snaplen  the maximum snapshot length.
     */
    void openDevice(const std::string& dev, size_t snaplen);
    
    /*! \brief Opens the default device as a source; usually, this is one of Ethernet controllers.
     *  \param snaplen  the maximum snapshot length.
     */
    void openDefaultDevice(size_t snaplen);
    
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
    //! Wrapper around the pfring_recv function.
    void dispatch();
    
    //! Wrapper around the pfring_recv function when the dummy mode is activated
    void dispatchDummy();
};
}

#endif /* _PFRING_SOURCE_HH_ */
