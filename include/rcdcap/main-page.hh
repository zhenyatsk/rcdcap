#include "rcdcap/plugin-doc.hh"

/*! \mainpage Information about RCDCap
 *
 *  RCDCap is a remote capture preprocessor. It could be used for capturing
 *  traffic remotely by using CISCO ERSPAN and HP ERM. The remotely captured
 *  traffic then could be decapsulated and outputted to the standard output
 *  or virtual Ethernet device (TAP). Thereby enabling applications that do
 *  not support this kind of encapsulation to process the traffic. Also, it 
 *  preserves the priority and the VLAN identifier from the HP ERM and CISCO
 *  ERSPAN header by applying IEEE 802.1Q VLAN tag. This option could be
 *  optionally switched off for applications that do not have VLAN support.
 *
 *  The application could be extended by applying plug-ins. Therefore, new
 *  protocols could be added with minimum modification. For more information about
 *  extending RCDCap, refer to \ref rcdcap_plugins It also provides
 *  advanced performance tuning, which includes: support for different packet
 *  capturing mechanisms, thread pinning strategies, work separation, etc.
 *
 *  \page rcdcap_plugins Extending RCDCap
 *
 *  RCDCap includes a simple plug-in system which enables insertion of new
 *  data sources, processors and data sinks inside its pipeline. This article
 *  describes the core elements of a plug-in processor and how they are implemented.
 *  The plug-in on its own also demonstrates how the pipeline
 *  could be extended with functionalities that are unrelated to decapsulating
 *  packets. Its main purpose is to report untagged Ethernet frames (optionally
 *  enabled) and report VLAN identifiers that were not specified as valid by
 *  the user. It could be used for detecting attackers that are trying to inject
 *  corrupted traffic inside a network. There is already a more elaborate version
 *  of this plug-in included with RCDCap, which could be used for further studying
 *  how to implement plug-ins.
 *
 *  The rest of this article is split into three sections. First, the header
 *  file is described in detail. Then, the actual implementation of the plug-in
 *  is discussed. Finally, it is described how the plug-in could be compiled
 *  against RCDCap's core library and how the plug-in could be loaded inside
 *  RCDCap.
 *
 *  \section sec1 Plug-in header file
 *
 *  First and foremost, a header file must be made that includes all declarations.
 *  Every C++ header file includes a header guard and includes some headers which
 *  contain the declarations of the functions used inside the rest of the code.
 *  These first declarations are shown in Listing 1.
 *  rcdcap/plugin.hh contains the declaration of the RCDCap::Plugin class
 *  which every plug-in must inherit. Also, this plug-in provides its own
 *  data processor, so it must include rcdcap/processor.hh.
 *
\codesnippet
#ifndef _VLAN_MONITOR_PLUGIN_HH_
#define _VLAN_MONITOR_PLUGIN_HH_
#include "rcdcap/plugin.hh"
#include "rcdcap/processor.hh"

#include <vector>

// You should not make your plug-in as part of namespace RCDCap because it
// is reserved for classes that are part of RCDCap and its core library.
// On the other hand, nothing stops you from directly using everything
// from namespace RCDCap.
using namespace RCDCap;
\endcodesnippet{Listing 1: Header beginning.}
 *
 *  Every plug-in must contain a class which initializes all of its contents and
 *  interfaces with RCDCap::RCDCapApplication to provide new data sources, processors and/or
 *  data sinks. In the case of the plug-in discussed within this article, this
 *  class is called <I>VLANMonitorPlugin</I>. It is shown in Listing 2.
 *
\codesnippet
//! \brief An example plug-in which monitors for unknown VLANs and
//!        untagged packets.

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

    //! \brief Initializes the plugin.
    //!
    //! This function inserts all additional command line options supported
    //! by the plug-in. Also, it initializes some basic values associated
    //! with the plug-in.
    //!
    //! \param io_service   a reference to the Boost.ASIO I/O Service.
    //! \param opts         a reference to the command line options
    //!                     description.
    virtual void init(boost::asio::io_service& io_service,
                    popt::options_description& opts);

    //! \brief Returns a pointer to a new processor, if the command line
    //!         options match the criteria placed by the plug-in.
    //! \param src          a reference to the data source inside the
    //!                     RCDCap's pipeline.
    //! \param vm           a reference to the parser command line options.
    virtual ProcessorPtr hasProcessor(DataSource& src,
                                    const popt::variables_map& vm);
};
\endcodesnippet{Listing 2: VLAN Monitor plug-in main class.}
 *
 *  <I>VLANMonitorPlugin</I> overrides the abstract <I>init</I> function which
 *  is used for initializing the plug-in. To enable optional reporting of untagged
 *  Ethernet frames and reporting Ethernet frames with unknown VLAN identifier
 *  inside their 802.1Q VID field, it adds two additional command line
 *  options. They are called <I>--alert-untagged</I> and <I>--permitted-vlans</I>.
 *  The former is used for alerting about untagged Ethernet frames. While the latter
 *  is used for specifying the permitted VLAN identifier values within the monitored
 *  network. The actual initialization of the extension processor is done within
 *  <I>hasProcessor</I>. This function is used for creating a new processor
 *  which will be inserted inside RCDCap's pipeline. The new processor is usually
 *  inserted after the built-in processors supported by RCDCap and currently it
 *  is not possible to specify its place within the pipeline. However, that is
 *  the expected behavior in this case because the processor is interested in the
 *  remote traffic. Therefore, it must be at the end of the pipeline. The values
 *  attached to the encapsulation headers are just used for transferring the traffic,
 *  so they are not of any particular concern in this case. Also, the initialization
 *  function saves up a pointer to the Boost ASIO I/O Service which is later passed
 *  to the extension processor.
 *
 *  The actual extension processor is directly inherited from RCDCap's
 *  Processor class which specifies the basic interface of a data processor.
 *  It does not need any functions associated with decapsulation, so it does not
 *  need to inherit RCDCap::DecapsulatingProcessor. However, if a processor
 *  for a new encapsulation is being implemented, it is necessary to inherit
 *  RCDCap::DecapsulatingProcessor. The actual declaration of the extension
 *  processor is called <I>VLANMonitor</I> and it is shown in Listing 3.
 *
\codesnippet
//! A processor which monitors for unknown VLANs and untagged packets.
class VLANMonitor: public Processor
{
    //! A reference to the Boost.ASIO I/O Service.
    boost::asio::io_service&    m_IOService;
    //! A reference to the data source inside RCDCap's pipeline.
    DataSource&                 m_DataSource;
    //! A list of the permitted VLAN identifier values.
    std::vector<unsigned>       m_PermittedVLANs;
    //! Specifies whether untagged packets must be reported.
    bool                        m_UntaggedEnabled;
public:
    //! \brief Constructor.
    //! \param io_service       a reference to the Boost.ASIO I/O Service.
    //! \param src              a reference to the data source inside
    //!                         RCDCap's pipeline.
    //! \param vlans            a list of the permitted VLAN identifier
    //!                         values
    //! \param enable_untagged  specifies whether untagged packets must be
    //!                         reported.
    VLANMonitor(boost::asio::io_service& io_service,
                DataSource& src,
                std::vector<unsigned> vlans,
                bool enable_untagged);

    //! Destructor.
    virtual ~VLANMonitor();

    //! \brief Notifies the processor about new data.
    //! \param packet_info  a pointer to the information about the packet.
    virtual void notify(PacketInfo* packet_info);
private:
    //! \brief Analyzes the contents of the packet.
    //! \param packet_info  a pointer to the information about the packet.
    void analyze(PacketInfo* packet_info);
};
 *
#endif // _VLAN_MONITOR_PLUGIN_HH_
\endcodesnippet{Listing 3: VLAN Monitor plug-in processor.}
 *
 *  VLANMonitor has four private member variables called:
 *  <I>m_IOService</I>, <I>m_DataSource</I>, <I>m_PermittedVLANs</I>, and
 *  <I>m_UntaggedEnabled</I>. The actual implementation is done in
 *  asynchronous fashion. When a notification (<I>notify</I>) about new packet
 *  arrives, a new task for analyzing it (<I>analyze</I>) gets enqueued in the
 *  thread pool's task queue (<I>m_IOService</I>). On the other hand, it needs
 *  some information about the data source during analysis in order to decide
 *  whether the source is passing an Ethernet frame or not. That is why it includes
 *  an reference to the data source (<I>m_DataSource</I>). <I>m_PermittedVLANs</I>
 *  is a list of the permitted VLAN. If during the analysis the VID (included
 *  inside the Ethernet frame) is not part of this list, it gets always reported.
 *  <I>m_UntaggedEnabled</I> indicates whether untagged Ethernet must be reported.
 *  All of these variables are set through <I>VLANMonitor</I>'s
 *  constructor which contains a separate argument for every one of them.
 *
 *  \section sec2 Plug-in source code file
 *
 *  The source code file must start with the usual inclusion of header files. It
 *  is most important to include the header file which was discussed in \ref sec1
 *  (<I>vlan-monitor-processor.hh</I>). The implementation
 *  relies on <I>rcdcap/packet-headers.hh</I> to provide the necessary structures
 *  representing the actual packet headers. They are required in order to analyze
 *  the contents of the packets. Also, the reporting of the suspected
 *  attacker's traffic is done through syslog. Another important declaration
 *  which must be included by every plug-in is the <I>RCDCAP_PLUGIN</I> declaration. It
 *  provides all functions which are required to interface with RCDCap. Everything
 *  described in this paragraph is shown in Listing 4.
 *
\codesnippet
#include "vlan-monitor-processor.hh"

#include "rcdcap/packet-headers.hh"

#include <syslog.h>

RCDCAP_PLUGIN(VLANMonitorPlugin)
\endcodesnippet{Listing 4: Source code file beginning.}

<I>VLANMonitorPlugin</I> overrides just the <I>init</I> and <I>hasProcessor</I>
from the RCDCap::Plugin base class. <I>init</I> saves a pointer to the Boost
ASIO I/O Service which is later passed to the plug-in processor. Also, it adds
the <I>--alert-untagged</I> and <I>--permitted-vlans</I> command
line options to RCDCap. To actually plug the new processor into RCDCap, <I>hasProcessor</I>
is overridden. It checks whether one of the options associated with the plug-in is
defined and if that is the case, it returns a new instance of the <I>VLANMonitor</I>
processor. The actual code is presented in Listing 5.

\codesnippet
VLANMonitorPlugin::VLANMonitorPlugin()
    :   m_IOService(0)
{
}

VLANMonitorPlugin::~VLANMonitorPlugin()
{
}

void VLANMonitorPlugin::init(boost::asio::io_service& io_service,
                            popt::options_description& opts)
{
    m_IOService = &io_service;
    opts.add_options()
        ("alert-untagged", "alert about untagged Ethernet frames")
        ("permitted-vlans",
        popt::value<std::vector<unsigned>>(&m_PermittedVLANs)
            ->multitoken(),
        "set the VLAN identifiers which are permitted to be received by "
        "the monitored network node")
    ;
}

ProcessorPtr VLANMonitorPlugin::hasProcessor(DataSource& src,
                                            const popt::variables_map& vm)
{
    assert(m_IOService);
    auto auc = vm.count("alert-untagged");
    bool enable_untagged = !auc;
    auto pvlanc = vm.count("permitted-vlans");
    if(auc || pvlanc)
        return std::make_shared<VLANMonitor>(*m_IOService,
                                            src, m_PermittedVLANs,
                                            enable_untagged);
    return ProcessorPtr();
}
\endcodesnippet{Listing 5: VLAN Monitor plug-in main class implementation}
 *
 *  The actual implementation of the plug-in processor opens a new syslog connection
 *  through its constructor and closes it in its destructor. It does not process
 *  the packets when a notification gets handled by <I>notify</I>, but enqueues
 *  a new task through <I>m_IOService</I>. The analysis of the packet is done
 *  in <I>analyze</I>. First, it checks whether it is working with an Ethernet
 *  data source. If that is the case, it further analyzes the packet; otherwise,
 *  it returns because there is not support for other types of data sources.
 *  The actual extended analysis consists of determining whether the Ethernet frame
 *  contains an IEEE 802.1Q VLAN tag. If it is an 802.1Q frame, the VID
 *  gets compared with the permitted values inside <I>m_PermittedVLANs</I>. Every
 *  packet that contains a VID which is not specified in the list gets reported
 *  via syslog. The actual report consists of a warning message, the source MAC
 *  address and the destination MAC address. On the other hand, if a regular
 *  Ethernet frame arrives, it gets reported if untagged Ethernet frames are not
 *  enabled through <I>m_UntaggedEnabled</I>. Regardless of the outcome of the
 *  analysis, the packet always gets passed to the next element in the pipeline.
 *  A complete implementation is shown in Listing 6.
 *
\codesnippet
VLANMonitor::VLANMonitor(boost::asio::io_service& io_service,
                        DataSource& src, std::vector<unsigned> vlans,
                        bool enable_untagged)
    :   m_IOService(io_service),
        m_DataSource(src),
        m_PermittedVLANs(std::move(vlans)),
        m_UntaggedEnabled(enable_untagged)
{
    openlog("rcdcap", LOG_PID, LOG_LOCAL0);
}
 *
VLANMonitor::~VLANMonitor()
{
    closelog();
}

void VLANMonitor::notify(PacketInfo* packet_info)
{
    m_IOService.post(std::bind(&VLANMonitor::analyze, this, packet_info));
}

void VLANMonitor::analyze(PacketInfo* packet_info)
{
    switch(m_DataSource.getLinkType())
    {
    case DLT_EN10MB:
    {
        auto& eth_header
            = reinterpret_cast<MACHeader&>(*GetPacket(packet_info));
        auto dmac = eth_header.getDMacAddress(),
            smac = eth_header.getSMacAddress();
        if(eth_header.getEtherType() ==
            RCDCap::EtherType::RCDCAP_ETHER_TYPE_802_1Q)
        {
            auto& vlan_header
                = reinterpret_cast<MACHeader802_1Q&>(eth_header);
            auto vid = static_cast<size_t>(vlan_header.getVLANIdentifier());
            auto i = std::find(m_PermittedVLANs.begin(),
                            m_PermittedVLANs.end(), vid);
            if(i == m_PermittedVLANs.end())
                syslog(LOG_WARNING,
                    "vlan-monitor: "
                    "a packet has been received from unknown VLAN %u\n"
                    "\tsource MAC address:      "
                        "%02x:%02x:%02x:%02x:%02x:%02x\n"
                    "\tdestination MAC address: "
                        "%02x:%02x:%02x:%02x:%02x:%02x",
                    (unsigned)vid,
                    (unsigned)smac[0], (unsigned)smac[1],
                    (unsigned)smac[2], (unsigned)smac[3],
                    (unsigned)smac[4], (unsigned)smac[5],
                    (unsigned)dmac[0], (unsigned)dmac[1],
                    (unsigned)dmac[2], (unsigned)dmac[3],
                    (unsigned)dmac[4], (unsigned)dmac[5]);
        }
        else if(!m_UntaggedEnabled)
        {
            syslog(LOG_WARNING,
                "vlan-monitor: "
                "untagged Ethernet frame detected:\n"
                "\tsource MAC address:      "
                    "%02x:%02x:%02x:%02x:%02x:%02x\n"
                "\tdestination MAC address: "
                    "%02x:%02x:%02x:%02x:%02x:%02x",
                (unsigned)smac[0], (unsigned)smac[1], (unsigned)smac[2],
                (unsigned)smac[3], (unsigned)smac[4], (unsigned)smac[5],
                (unsigned)dmac[0], (unsigned)dmac[1], (unsigned)dmac[2],
                (unsigned)dmac[3], (unsigned)dmac[4], (unsigned)dmac[5]);
        }
    } break;
    }
    if(m_Sink)
        m_Sink->notify(packet_info);
}
\endcodesnippet{Listing 6: VLAN Monitor plug-in processor implementation.}
 *
 *  \section sec3 Building and loading the plug-in
 *
 *  The plug-in must be compiled against librcdcap_core and RCDCap's header
 *  files must be included. It is important to compile the plug-in against the new
 *  C++11 standard because the internal implementation of RCDCap uses it extensively.
 *  It is called "c++0x" in some earlier versions of GCC and "c++11" in
 *  the current 4.7 version, but the other name is provided for backward compatibility. An example
 *  of how the plug-in could be compiled against librcdcap_core by using CMake
 *  is shown in Listing 7. The actual files of the plug-in are
 *  called <I>vlan-monitor-processor.cc</I> and <I>vlan-monitor-processor.hh</I>.
 *  They are used for creating the plug-in module.
 *
\codesnippet
CMAKE_MINIMUM_REQUIRED(VERSION 2.8)
PROJECT(VLANMonitor)

FIND_LIBRARY(LIBRCDCAP_CORE "rcdcap_core" PATH_SUFFIXES "lib" "local/lib")
FIND_PATH(LIBRCDCAP_INC "plugin.hh"
        PATH_SUFFIXES "include/rcdcap" "local/include/rcdcap")
IF(NOT LIBRCDCAP_CORE AND NOT LIBRCDCAP_INC)
    MESSAGE(FATAL_ERROR "librcdcap_core was not found")
ENDIF()

ADD_DEFINITIONS("-std=c++0x")

INCLUDE_DIRECTORIES(${LIBRCDCAP_INC})

ADD_LIBRARY(vlan-monitor MODULE vlan-monitor-processor.cc
                                vlan-monitor-processor.hh)

TARGET_LINK_LIBRARIES(vlan-monitor ${LIBRCDCAP_CORE})
\endcodesnippet{Listing 7: VLAN Monitor build script.}
 *
 *  To actually compile the plug-in, CMake must be first executed to generate a
 *  Makefile and then it could be built in the regular fashion. An example of the
 *  required steps to compile the plug-in are shown in Listing 8.
 *
\codesnippet
cd /path/to/plugin-build-dir
cmake /path/to/plugin-source-dir
make
\endcodesnippet{Listing 8: Building the plug-in.}
 *
 *  The resulting plug-in file could be loaded by using RCDCap's <I>--load-plugins</I>
 *  command line option. Otherwise, it could be copied to <I>/path/to/rcdcap/share/rcdcap/plugins</I>
 *  where it is going to be loaded every time when RCDCap is launched.
 */