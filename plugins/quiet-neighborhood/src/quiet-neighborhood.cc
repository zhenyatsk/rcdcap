/*   RCDCap
 *   Copyright (C) 2013  Zdravko Velinov
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

#include "rcdcap/plugin.hh"
#include "rcdcap/processor.hh"

#include "quiet-neighborhood-monitor.hh"

#include <boost/make_shared.hpp>

#include <wordexp.h>

using namespace RCDCap;

/*! \brief Monitors any neighbor or IP discovery activities and reports any
 *         abnormal activities.
 * 
 *  The idea of this plug-in is to simplify the day to day job of system
 *  operators of networks that employ DHCP for automatic IP configuration.
 *  Also, it makes sure that the proper IPs get assigned in the respective
 *  VLANs and there are not packets for unassigned VLANs. Essentially, this
 *  plug-in brings the basic functionality of the already existing VLAN
 *  monitor and makes it completely automatic. The main idea behind the
 *  plug-in is that there are two phases:
 *  1. Learning phase   - when the software assumes that the network is
 *                        configured properly and just makes reports about
 *                        the current situation, so that the network
 *                        administrator could confirm that everything is
 *                        alright.
 *  2. Monitoring phase - it considers any new VLAN or service as harmful
 *                        and reports them. The suspicious hosts are
 *                        collected in their own table, so that it is
 *                        possible to merge the two tables can be merged
 *                        if everything is fine.
 */
class QuietNeighborhoodPlugin: public Plugin
{
    //! A reference to the Boost.ASIO I/O Service.
    boost::asio::io_service*    m_IOService;
public:
    //! Constructor.
    QuietNeighborhoodPlugin();
    
    //! Destructor.
     ~QuietNeighborhoodPlugin();
    
    /*! \brief Initializes the plug-in.
     * 
     *  This function inserts all additional command line options supported
     *  by the plug-in. Also, it initializes some basic values associated
     *  with the plug-in.
     *  
     *  \param io_service   a reference to the Boost.ASIO I/O Service.
     *  \param opts         a reference to the command line options
     *                      description.
     */
    virtual void init(boost::asio::io_service& io_service,
                      popt::options_description& opts) final;
    
    /*! \brief Returns a pointer to a new processor, if the command line
     *         options match the criteria placed by the plug-in.
     *  \param src  a reference to the data source inside RCDCap's
     *              pipeline.
     *  \param vm   a reference to the parser command line options.
     */
    virtual ProcessorPtr hasProcessor(DataSource& src,
                                      const popt::variables_map& vm) final;
};

// Defines all functions required for interfacing with RCDCap.
RCDCAP_PLUGIN(QuietNeighborhoodPlugin)

QuietNeighborhoodPlugin::QuietNeighborhoodPlugin() {}
QuietNeighborhoodPlugin::~QuietNeighborhoodPlugin() {}

void QuietNeighborhoodPlugin::init(boost::asio::io_service& io_service,
                                   popt::options_description& opts)
{
    // Saves a reference to the Boost ASIO I/O Service, which it later passes
    // to the plug-in processor.
    m_IOService = &io_service;
    // Adds new command line options to RCDCap.
    opts.add_options()
    ("quiet-neighborhood",
         "Active the Quiet neighborhood plug-in")
        // If you need more than 8. Think about whether your network probe could even handle that much traffic.
    ("vlan-pool-size",
         popt::value<size_t>()->default_value(8),
         "How many VLANs could appear in this network")
    ("address-pool-size",
         popt::value<size_t>()->default_value(256),
         "How many addresses could be assigned to the hosts which are part"
         "of a single VLAN")
    // Leave a couple for suspicious traffic
    ("subnet-pool-size",
         popt::value<size_t>()->default_value(2),
         "How many subnets might be present in any given VLAN")
    ("learning-phase-duration",
         popt::value<size_t>()->default_value(3600),
         "How long the learning phase lasts in seconds before switching to"
         "monitoring for any unexpected changes")
    ("network-cache",
         popt::value<std::string>()->
            default_value("~/.quiet-neighborhood.cfg"),
         "Where does the application keeps the information about the"
         "network that has been built during the learning phase")
    ("suspicious-hosts-cache",
         popt::value<std::string>()
            ->default_value("~/.quiet-neighborhood-suspicious-hosts.cfg"),
         "Where does the application keeps the information about all"
         "suspicious hosts collected during the monitoring phase")
    ("network-cache-format",
         popt::value<std::string>()->default_value("JSON"),
         "The internal format used for saving the network cache"
         "(XML, JSON, INFO)")
    ("merge-suspicious",
         "Merge the previously detected as suspicious"
         "host to the list of the legitimate hosts")
    ("ignore-network-cache",
         "Do not consider the information from any previous running of the"
         "application")
    ("force-learning-phase",
         "Force learning phase even if there is"
         "network cache built already")
    ("dhcp-server-port",
         popt::value<size_t>()->default_value(67),
         "The UDP port used by the DHCP servers for receiving requests")
    ("dhcp-client-port",
         popt::value<size_t>()->default_value(68),
         "The UDP port used by the DHCP clients for receiving replies")
    ("dhcpv6-server-port",
         popt::value<size_t>()->default_value(547),
         "The UDP port used by the DHCPv6 servers for receiving requests")
    ("dhcpv6-client-port",
         popt::value<size_t>()->default_value(546),
         "The UDP port used by the DHCPv6 clients for receiving replies")
    ("min-ipv4-subnet-mask",
         popt::value<size_t>()->default_value(24),
         "The starting subnet mask that is used when aggregating IPv4"
         "hosts into subnets")
    ("max-ipv4-subnet-mask",
         popt::value<size_t>()->default_value(24),
         "The maximum subnet mask that is allowed when aggregating IPv4"
         "hosts into subnets")
    ("min-ipv6-subnet-mask",
         popt::value<size_t>()->default_value(64),
         "The starting subnet mask that is used when aggregating IPv6"
         "hosts into subnets")
    ("max-ipv6-subnet-mask",
         popt::value<size_t>()->default_value(64),
         "The maximum subnet mask that is allowed when aggregating IPv6"
         "hosts into subnets")
    ;
    
}

static std::string ExpandPath(const std::string& _path)
{
    wordexp_t exp_result;
    ::wordexp(_path.c_str(), &exp_result, 0);
    std::string result(exp_result.we_wordv[0]);
    ::wordfree(&exp_result);
    return result;
}

ProcessorPtr QuietNeighborhoodPlugin::hasProcessor(DataSource& src,
                                                   const popt::variables_map& vm)
{
    // Initializes a new plug-in processor only if --quiet-neighborhood is specified.
    // All options are kept in a common structure which is passed to the new elements
    // of the pipeline.
    assert(m_IOService);
    QuietNeighborhoodOptions opts;
    auto qnc = vm.count("quiet-neighborhood");
    if(!qnc)
        return ProcessorPtr();

    opts.IPv4MinMask = vm["min-ipv4-subnet-mask"].as<std::size_t>();
    opts.IPv4MaxMask = vm["max-ipv4-subnet-mask"].as<std::size_t>();
    opts.IPv6MinMask = vm["min-ipv6-subnet-mask"].as<std::size_t>();
    opts.IPv6MaxMask = vm["max-ipv6-subnet-mask"].as<std::size_t>();    
    opts.subnetPoolSize = vm["subnet-pool-size"].as<std::size_t>();
    opts.hostPoolSize = vm["address-pool-size"].as<std::size_t>();
    opts.VLANPoolSize = vm["vlan-pool-size"].as<std::size_t>();
    opts.DHCPServerPort = vm["dhcp-server-port"].as<std::size_t>();
    opts.DHCPClientPort = vm["dhcp-client-port"].as<std::size_t>();
    opts.DHCPv6ServerPort = vm["dhcpv6-server-port"].as<std::size_t>();
    opts.DHCPv6ClientPort = vm["dhcpv6-client-port"].as<std::size_t>();
    opts.networkCache = ExpandPath(vm["network-cache"].as<std::string>());
    opts.networkViolationCache = ExpandPath(vm["suspicious-hosts-cache"].as<std::string>());

    if(opts.subnetPoolSize == 0)
        THROW_EXCEPTION("More than a single host per VLAN should be enabled");
    
    if(opts.hostPoolSize == 0)
        THROW_EXCEPTION("More than a single subnet per VLAN should be enabled");
    
    if(opts.VLANPoolSize == 0)
        THROW_EXCEPTION("More than a single VLAN should be enabled");
    
    std::string cache_format = vm["network-cache-format"].as<std::string>();
    if(cache_format == "JSON")
        opts.networkCacheFormat = CacheFormat::JSON;
    else if(cache_format == "XML")
        opts.networkCacheFormat = CacheFormat::XML;
    else if(cache_format == "INFO")
        opts.networkCacheFormat = CacheFormat::INFO;
    else
        THROW_EXCEPTION("Unknown cache format");
    
    opts.learningPhase = vm["learning-phase-duration"].as<std::size_t>();
    if(vm.count("ignore-network-cache"))
        opts.flags |= OptionFlags::IGNORE_CACHE;
    if(vm.count("force-learning-phase"))
        opts.flags |= OptionFlags::FORCE_LEARNING_PHASE;
    if(vm.count("merge-suspicious"))
        opts.flags |= OptionFlags::MERGE_VIOLATING;
    
    return boost::make_shared<QuietNeighborhoodMonitor>(*m_IOService, src, opts);
}

