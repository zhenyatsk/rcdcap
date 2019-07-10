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

#ifndef _VLAN_MONITOR_PLUGIN_HH_
#define _VLAN_MONITOR_PLUGIN_HH_
#include "rcdcap/plugin.hh"
#include "rcdcap/processor.hh"
#include "rcdcap/packet-headers.hh"

#include <vector>
#include <map>

// You should not make your plug-in as part of namespace RCDCap because it is
// reserved for classes that are part of RCDCap and its core library. On the
// other hand, nothing stops you from directly using everything from namespace
// RCDCap.
using namespace RCDCap;

//! An example plug-in which monitors for unknown VLANs and untagged packets.
class VLANMonitorPlugin: public Plugin
{
    //! A reference to the Boost.ASIO I/O Service.
    boost::asio::io_service*    m_IOService;
    //! A list of the permitted VLAN identifier values.
    std::vector<unsigned>       m_PermittedVLANs;
public:
    //! Constructor.
    VLANMonitorPlugin();
    
    //! Destructor.
     ~VLANMonitorPlugin();
    
    /*! \brief Initializes the plugin.
     * 
     *  This function inserts all additional command line options supported
     *  by the plug-in. Also, it initializes some basic values associated with
     *  the plug-in.
     *  
     *  \param io_service   a reference to the Boost.ASIO I/O Service.
     *  \param opts         a reference to the command line options description.
     */
    virtual void init(boost::asio::io_service& io_service,
                      popt::options_description& opts) final;
    
    /*! \brief Returns a pointer to a new processor, if the command line options
     *         match the criteria placed by the plug-in.
     *  \param src  a reference to the data source inside RCDCap's pipeline.
     *  \param vm   a reference to the parser command line options.
     */
    virtual ProcessorPtr hasProcessor(DataSource& src,
                                      const popt::variables_map& vm) final;
};

//! A processor which monitors for unknown VLANs and untagged packets.
class VLANMonitor: public Processor
{
    std::map<mac_t, ip_t>       m_ARPTable;
    //! A reference to the Boost.ASIO I/O Service.
    boost::asio::io_service&    m_IOService;
    //! A reference to the data source inside RCDCap's pipeline.
    DataSource&                 m_DataSource;
    //! A list of the permitted VLAN identifier values.
    std::vector<unsigned>       m_PermittedVLANs;
    //! Specifies whether untagged packets must be reported.
    bool                        m_UntaggedEnabled;
public:
    /*! \brief Constructor.
     *  \param io_service       a reference to the Boost.ASIO I/O Service.
     *  \param src              a reference to the data source inside RCDCap's
     *                          pipeline.
     *  \param vlans            a list of the permitted VLAN identifier values.
     *  \param enable_untagged  specifies whether untagged packets must be
     *                          reported.
     */
    VLANMonitor(boost::asio::io_service& io_service,
                DataSource& src,
                std::vector<unsigned> vlans,
                bool enable_untagged);
    
    //! Destructor.
    virtual ~VLANMonitor();

    /*! \brief Notifies the processor about new data.
     *  \param packet_info  a pointer to the information about the packet.
     */
    virtual void notify(PacketInfo* packet_info, size_t packet_size) override;
private:
    /*! \brief Analyzes the contents of the packet.
     *  \param packet_info  a pointer to the information about the packet.
     */
    void analyze(PacketInfo* packet_info, size_t packet_size);
    
    void analyzeImpl(PacketInfo* packet_info);
};

#endif /* _VLAN_MONITOR_PLUGIN_HH_ */