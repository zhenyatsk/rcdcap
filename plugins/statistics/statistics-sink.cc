/*   RCDCap
 *   Copyright (C) 2014  Zdravko Velinov
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
#include "rcdcap/sink.hh"

#include <boost/make_shared.hpp>

namespace popt=boost::program_options;

/*! \brief Plug-in that offers basic pipeline statistics.
 * 
 *  This plug-in generates time series related to the processed packets by the
 *  pipeline.
 */
class StatisticsPlugin: public RCDCap::Plugin
{
    boost::asio::io_service*    m_IOService;    //!< Pointer to the Boost I/O Service.
public:
    //! Default constructor.
    StatisticsPlugin()
        :   m_IOService(nullptr) {}
    
    //! Destructor.
     ~StatisticsPlugin() = default;
    
    /*! \brief Initializes some basic options related to this plug-in.
     *  \param io_servicee  a reference to the Boost I/O Service.
     *  \param opts         a reference to the command line options list.
     */
    virtual void init(boost::asio::io_service& io_service,
                      popt::options_description& opts) final;

    /*! \brief Returns a pointer to a new data sink, if the command line options
     *         match the criteria placed by the plug-in.
     * 
     *  \param src  a reference to the data source inside RCDCap's pipeline.
     *  \param vm   a reference to the parser command line options.
     */
    virtual RCDCap::DataSinkPtr hasSink(RCDCap::DataSource& src, const popt::variables_map& vm) final;
};

RCDCAP_PLUGIN(StatisticsPlugin)

//! Contains a record about the performance of the pipeline.
class PipelineStatistics
{
    RCDCap::uint64                                m_ProcessedTraffic;   //!< The number of processed packets.
    std::chrono::high_resolution_clock::duration  m_Time;               //!< The time elapsed since the beginning of the monitoring.
public:
    /*! \brief Constructor.
     * 
     *  \param processed_traffic the number of packets processed by the pipeline.
     */
    explicit PipelineStatistics(size_t processed_traffic)
        :   m_ProcessedTraffic(processed_traffic) {}

    //! Updates the current time based on the starting time.
    void updateTime(const std::chrono::high_resolution_clock::time_point& start) { m_Time = std::chrono::high_resolution_clock::now() - start; }

    //! Returns the elapsed time in milliseconds.
    RCDCap::uint64 getTimeInMilliseconds() const { return std::chrono::duration_cast<std::chrono::milliseconds>(m_Time).count(); }
    
    //! Returns the number of processed packets.
    RCDCap::uint64 getProcessedData() const { return m_ProcessedTraffic; }
};

/*! \brief Records time series related to the performance of the pipeline.
 * 
 *  It does a really simplistic data acquisition that involves pushing a record after the specified
 *  number of packets get processed.
 */
class StatisticsSink: public RCDCap::DataSink
{
    std::vector<PipelineStatistics>                m_Stats;             //!< The stats acquired during the traffic processing.
    RCDCap::uint64                                 m_ProcessedData;     //!< The number of processed packets.
    RCDCap::uint64                                 m_LastProcessedData; //!< The last number of packets processed by the pipeline.
    size_t                                         m_Step;              //!< The number of packets that must be processed before a new record gets inserted.
    std::chrono::high_resolution_clock::time_point m_Start;             //!< The starting time.
public:
    /*! \brief Constructor.
     *  \param io_service   a reference to the Boost I/O Service.
     *  \param src          a reference to the source.
     *  \param step         the step between every record.
     */
    explicit StatisticsSink(boost::asio::io_service& io_service, RCDCap::DataSource& src, size_t step);
    
    //! Destructor.
    virtual ~StatisticsSink();
    
    /*! \brief Notifies the processor about new packet.
     * 
     *  This function directly does the processing because it is quite light-weight most of the time.
     * 
     *  \param packet_info  a pointer to the first packet that has been processed.
     *  \param packets      the number of packets in this burst.
     */
    virtual void notify(RCDCap::PacketInfo* packet_info, size_t packets) override;
};

StatisticsSink::StatisticsSink(boost::asio::io_service& io_service, RCDCap::DataSource& src, size_t step)
    :   DataSink(io_service, src),
        m_ProcessedData(0),
        m_LastProcessedData(0),
        m_Step(step),
        m_Start(std::chrono::high_resolution_clock::now()) {}

StatisticsSink::~StatisticsSink()
{
    std::cout << "##########################################\n"
                 "#          Execution statistics          #\n"
                 "##########################################\n"
                 "    N       T      dT       P       V     \n";
    RCDCap::uint64 _last = 0;
    for(size_t i = 0; i < m_Stats.size(); ++i)
    {
        auto millisec = m_Stats[i].getTimeInMilliseconds();
        auto dur = millisec - _last;
        auto data = m_Stats[i].getProcessedData();
        std::cout << std::setw(8) << (i+1)*m_Step << " "
                  << std::setw(8) << millisec << " "
                  << std::setw(8) << dur <<  " "
                  << std::setw(8) << data << " "
                  << std::setw(8) << data*1000/dur << "\n";
        _last = millisec;
    }
    auto dur = std::chrono::high_resolution_clock::now() - m_Start;
    std::cout << "Total processed data, bytes: " << m_ProcessedData << "\n"
              << "Total time, ms: "              << std::chrono::duration_cast<std::chrono::milliseconds>(dur).count() << std::endl;
}
        
void StatisticsSink::notify(RCDCap::PacketInfo* packet_info, size_t packets)
{
    auto& buffer = m_DataSource.getBuffer();
    auto* next_packet_info = packet_info;
    // So we try one by one to catch our own sequence
    for(;; --packets, packet_info = next_packet_info)
    {
        if(packets == 0)
            return;
        next_packet_info = buffer.next(packet_info);
        packet_info->setProcessed();
        if(packet_info == buffer.begin() && packet_info->tryProcessed())
            break;
    }
   
    // Then we write a burst
    size_t chunk_size = 0;
    for(; packets; --packets, packet_info = buffer.next(packet_info))
    {
        ++m_Processed;
        chunk_size += packet_info->getAllocatedSize();
        m_ProcessedData += packet_info->getPCAPHeader().getCapturedLength();
        if((m_Processed % m_Step) == 0)
        {
            m_Stats.push_back(PipelineStatistics{ m_ProcessedData - m_LastProcessedData });
            m_LastProcessedData = m_ProcessedData;
            auto& cur = m_Stats.back();
            cur.updateTime(m_Start);
        }
    }
    buffer.popSequence(chunk_size);
    // But it is possible that the beginning is somewhere else, so we get a new one
    packet_info = buffer.begin();
    
    // And then we try to count the rest of the packets one by one in a slower fashion
    // TODO: Optimize slow path
    while(buffer.size() && packet_info->tryProcessed())
    {
        ++m_Processed;
        m_ProcessedData += packet_info->getPCAPHeader().getCapturedLength();
        if((m_Processed % m_Step) == 0)
        {
            m_Stats.push_back(PipelineStatistics{ m_ProcessedData - m_LastProcessedData });
            m_LastProcessedData = m_ProcessedData;
            auto& cur = m_Stats.back();
            assert(buffer.begin() == packet_info);
            auto* next_packet_info = buffer.next(packet_info);
            buffer.pop(packet_info->getAllocatedSize());
            packet_info = next_packet_info;
            cur.updateTime(m_Start);
        }
        else
        {
            assert(buffer.begin() == packet_info);
            auto* next_packet_info = buffer.next(packet_info);
            buffer.pop(packet_info->getAllocatedSize());
            packet_info = next_packet_info;
        }
    }
}

void StatisticsPlugin::init(boost::asio::io_service& io_service,
                            popt::options_description& opts) 
{
    m_IOService = &io_service;
    opts.add_options()
        ("statistics-sink",
         "Activates a statistics sink which discards all packets; however, it takes statistics at regular steps about the packet processing performance.")
        ("statistics-sink-step",
         popt::value<size_t>()->default_value(1000),
         "Specifies how many packets must be received before collecting statistical data.");
}

RCDCap::DataSinkPtr StatisticsPlugin::hasSink(RCDCap::DataSource& src, const popt::variables_map& vm)
{
    if(vm.count("statistics-sink") == 0)
        return RCDCap::DataSinkPtr();
    auto steps = vm["statistics-sink-step"].as<std::size_t>();
    return boost::make_shared<StatisticsSink>(*m_IOService, src, steps);
}