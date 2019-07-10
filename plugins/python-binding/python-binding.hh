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

#ifndef _RCDCAP_PYTHON_BINDING_HH_
#define _RCDCAP_PYTHON_BINDING_HH_

#include "rcdcap/plugin.hh"
#include "rcdcap/processor.hh"

#include <boost/python.hpp>

using namespace RCDCap;

#define THROW_PYTHON_EXCEPTION(excstr) \
    ThrowPythonException(__FILE__ ":" TO_STRING(__LINE__) ": " + std::string(excstr))
void ThrowPythonException(const std::string& excstr);

//! Provides the mechanism for loading plug-ins that use the Python binding.
class PythonBindingPlugin: public Plugin
{
    //! A list of all loaded Python plug-ins.
    std::vector<boost::python::object>    m_Plugins;

    //! A reference to the Boost.ASIO I/O Service.
    boost::asio::io_service*              m_IOService;
public:
    //! Constructor.
    PythonBindingPlugin();

    //! Destructor.
     ~PythonBindingPlugin();

    /*! \brief Initializes the plug-in.
     * 
     *  This function inserts all additional command line options supported
     *  by the plug-in and initializes some basic values associated with
     *  the plug-in. It loads all Python plug-ins that are found in the default
     *  path.
     *  
     *  \param io_service   a reference to the Boost.ASIO I/O Service.
     *  \param opts         a reference to the command line options description.
     */
    virtual void init(boost::asio::io_service& io_service,
                      popt::options_description& opts);

    /*! \brief Returns a pointer to a new data source, if the command line options
     *         match the criteria placed by any Python plug-in.
     *  \warning The actual number of data sources is constrained to just one.
     *  \param vm   a reference to the parser command line options.
     */
    virtual DataSourcePtr hasSource(const popt::variables_map& vm);

    /*! \brief Returns a pointer to a new processor, if the command line options
     *         match the criteria placed by any Python plug-in.
     *  \param src  a reference to the data source inside RCDCap's pipeline.
     *  \param vm   a reference to the parser command line options.
     */
    virtual ProcessorPtr hasProcessor(DataSource& src,
                                      const popt::variables_map& vm);

    /*! \brief Returns a pointer to a new data sink, if the command line options
     *         match the criteria placed by any Python plug-in.
     *  \warning The actual number of data sinks is constrained to just one.
     *  \param src  a reference to the data source inside RCDCap's pipeline.
     *  \param vm   a reference to the parser command line options.
     */
    virtual DataSinkPtr hasSink(DataSource& src, const popt::variables_map& vm);
};

#endif /* _RCDCAP_PYTHON_BINDING_HH_ */