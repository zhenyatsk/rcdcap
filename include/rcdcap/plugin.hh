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

#ifndef _RCDCAP_PLUGIN_HH_
#define _RCDCAP_PLUGIN_HH_

#include "rcdcap/memory.hh"
#include "rcdcap/library.hh"
#include "rcdcap/exception.hh"

#include <boost/program_options.hpp>
#include <boost/asio.hpp>

namespace RCDCap
{
class DataSource;
typedef boost::shared_ptr<DataSource> DataSourcePtr;
class Processor;
typedef boost::shared_ptr<Processor> ProcessorPtr;
class DataSink;
typedef boost::shared_ptr<DataSink> DataSinkPtr;

namespace popt=boost::program_options;

//! The base class from which every RCDCap plug-in must inherit.
class Plugin
{
public:
    //! Constructor.
    explicit Plugin() {}
    
    //! Destructor.
    virtual ~Plugin() {}
    
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
                      popt::options_description& opts)=0;

    /*! \brief Returns a pointer to a new data source, if the command line options
     *         match the criteria placed by the plug-in.
     *  \param vm   a reference to the parser command line options.
     */
    virtual DataSourcePtr hasSource(const popt::variables_map& vm)
        { return DataSourcePtr(); }
    
    /*! \brief Returns a pointer to a new processor, if the command line options
     *         match the criteria placed by the plug-in.
     *  \param src  a reference to the data source inside RCDCap's pipeline.
     *  \param vm   a reference to the parser command line options.
     */
    virtual ProcessorPtr hasProcessor(DataSource& src,
                                      const popt::variables_map& vm)
        { return ProcessorPtr(); }
    
    /*! \brief Returns a pointer to a new data sink, if the command line options
     *         match the criteria placed by the plug-in.
     *  \param src  a reference to the data source inside RCDCap's pipeline.
     *  \param vm   a reference to the parser command line options.
     */
    virtual DataSinkPtr hasSink(DataSource& src, const popt::variables_map& vm)
        { return DataSinkPtr(); }
};

//! The pointer type used for storing the plug-in in a list.
typedef boost::shared_ptr<Plugin> PluginPtr;

/*! \brief Defines functions required for initializing the plug-in with the specified
 *         plugin_name.
 *  \param plugin_name      the name of the plug-in.
 */
#define RCDCAP_PLUGIN(plugin_name) \
extern "C" { \
    RCDCap::PluginPtr RCDCapCreatePlugin() \
        { return boost::make_shared<plugin_name>(); } \
}

//! The function pointer type of the functions used for initializing plug-ins.
typedef PluginPtr (*RCDCapCreatePluginFunc)();

/*! \brief Loads a plug-in included in the specified library file.
 *  \param lib  a reference to the library file which contains the plug-in.
 *  \return on success returns a pointer to the requested plug-in object.
 */
PluginPtr LoadRCDCapPlugin(Library& lib)
{
    ProcType proc = lib.getProcAddress("RCDCapCreatePlugin");
    if(!proc)
#ifdef _WIN32
        THROW_EXCEPTION("RCDCapCreatePlugin is not found:"
                        "\nMake sure that the plug-in includes a RCDCAP_PLUGIN "
                        "declaration.");
#else
        THROW_EXCEPTION(std::string("RCDCapCreatePlugin is not found:")
                        + std::string(dlerror()) +
                        "\nMake sure that the plug-in includes a RCDCAP_PLUGIN "
                        "declaration.");
#endif
    return reinterpret_cast<RCDCapCreatePluginFunc>(proc)();
}
}

#endif /* _RCDCAP_PLUGIN_HH_ */