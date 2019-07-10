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

#ifndef __RCDCAP_HH__
#define __RCDCAP_HH__

#include "rcdcap/source.hh"
#include "rcdcap/processor.hh"
#include "rcdcap/plugin.hh"

#include <boost/program_options.hpp>

#include <boost/asio.hpp>

#include <memory>

namespace popt = boost::program_options;

namespace RCDCap
{
class Source;
typedef boost::shared_ptr<Source> SourcePtr;

//! A data type for storing size in different storage units, such KB, MB, GB, etc.
class Bytes
{
    size_t m_Size;          //!< The variable which is holding the value.
public:
    //! Default constructor.
    Bytes()=default;
    
    /*! \brief Constructor.
     *  \param _size    a string, representing the size in particular unit.
     */
    Bytes(const std::string& _size);
    
    /*! Assignment operator.
     *  \param _size    the size in bytes.
     */
    Bytes& operator=(size_t _size);
    
    //! Cast operator.
    operator size_t() const { return m_Size; }
};

/*! Outputs the size in the most suitable unit to the output stream.
 *  \param os   a reference to the output stream.
 *  \param b    a reference to the variable which represents the size.
 */
DLL_EXPORT std::ostream& operator<<(std::ostream& os, const Bytes& b);

/*! Parses the size from the input stream.
 *  \param is   a reference to the input stream.
 *  \param b    a reference to the variable which is going to receive the parsed value.
 */
DLL_EXPORT std::istream& operator>>(std::istream& is, Bytes& b);

#ifndef RCDCAP_STATIC
typedef std::vector<std::thread>                    ThreadGroup;
#else
typedef std::vector<std::unique_ptr<std::thread>>   ThreadGroup;
#endif

typedef boost::shared_ptr<Library>                LibraryPtr;

//! Implements all of the basic functions of the RCDCap application, such as initializing the pipeline.
class RCDCapApplication
{
    std::vector<LibraryPtr>                     m_PluginLibs;   //!< Contains all dynamic libraries which contain RCDCap plug-ins.
    std::vector<PluginPtr>                      m_Plugins;      //!< Contains all RCDCap plug-ins.

    popt::options_description                   m_Description;  //!< The description of the command line arguments that this application accepts
    boost::asio::io_service                     m_IOService;    //!< The Boost.ASIO I/O Service.
    boost::shared_ptr<DataSource>               m_Source;       //!< The object that represents the objects from which the data is being received.
    boost::shared_ptr<Sink>                     m_Sink;         //!< The object to which the data is going to be written.
    std::unique_ptr<boost::asio::signal_set>    m_Signals;      //!< The object that holds the information about the signals that could be received by this application from operating system.
    std::string                                 m_Expression;

    //! Just a helper object which sets the SMP IRQ affinity and cleans it up after the application exits.
    struct SMPAffinityRAII
    {
        std::string                             m_Path;         //!< The path to the smp_affinity file which is associated with the device that the user has chosen.
        size_t                                  m_OldValue;     //!< Holds the old value until the application exits and sets it up again.
    public:
        /*! \brief Constructor.
         *  \param dev          the device that the user has specified.
         *  \param cpu_mask     the desired value for the SMP IRQ affinity.
         */
        SMPAffinityRAII(const std::string& dev, size_t cpu_mask);
        
        //! Destructor.
         ~SMPAffinityRAII();
    };
    std::unique_ptr<SMPAffinityRAII>            m_SMPAffinityRAII; //!< SMP IRQ affinity RAII.
public:
    //! Constructor.
    RCDCapApplication();
    
    //! Destructor.
     ~RCDCapApplication();
    
    //! \warning Copying is forbidden by design.
    RCDCapApplication(const RCDCapApplication&)=delete;
    
    //! \warning Assignment is forbidden by design.
    RCDCapApplication& operator=(const RCDCapApplication&)=delete;
    
    //! Starts the RCDCap application.
    void run(int argc, char* argv[]);
    
    //! Shows help information about the application on the standard output.
    void showHelp();
    
    //! Shows information about the version of the application that is currently available.
    void showVersion();
    
    //! Terminates the application prematurely.
    void terminate();
private:
    /*! \brief Initializes the source from which the data is going to be received for processing.
     *  \param vm       a map that contains all of the parsed variables that were passed when executing the application.
     */
    void initSource(popt::variables_map& vm);
    
    /*! \brief Initializes the sink to which the data is going to be written after processing.
     *  \param vm       a map that contains all of the parsed variables that were passed when executing the application.
     *  \param _last    a reference to the last object in the pipeline.
     */
    void initSink(popt::variables_map& vm, const SourcePtr& _last);
    
    /*! \brief Initializes the pipeline and all of the processors which are requested.
     *  \param vm       a map that contains all of the parsed variables that were passed when executing the application.
     *  \param _last    a reference to which the last object in the pipeline is going to be written.
     */
    void initPipeline(popt::variables_map& vm, SourcePtr& _last);
    
    /*! \brief Spawns a given amount of threads, depending on the options that the user has entered.
     *  \param vm       a map that contains all of the parsed variables that were passed when executing the application.
     *  \param threads  a container, which is going to hold the threads.
     */
    void spawnWorkerThreads(popt::variables_map& vm, ThreadGroup& threads);
    
    /*! \brief Loads all plugins.
     *  
     *  By default, it searches for plug-ins inside /usr/share/rcdcap/plugins or
     *  whether RCDCap is installed for plug-ins. Also, it is possible to
     *  specify some plug-ins to be loaded by using a command line options.
     * 
     *  \param vm        a map that contains all of the parsed variables that were passed when executing the application.
     */
    void initPlugins(popt::variables_map& vm);
    
    //! \brief Detaches the process from the current terminal and convert it to background process.
    void daemonize();
};
}

#endif /* __RCDCAP_HH__ */