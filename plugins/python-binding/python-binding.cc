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

#include "python-wrapping.hh"
#include "python-binding.hh"
#include "rcdcap/source.hh"

#include <boost/filesystem.hpp>
#include <boost/make_shared.hpp>

RCDCAP_PLUGIN(PythonBindingPlugin)

//! Serves as a dispatcher class between C++ and all Python plug-in processors.
class ProcessorWrapper: public Processor
{
    //! Contains all currently loaded Python plug-in processors.
    std::vector<boost::python::object>       m_PythonProcessors;
public:
    //! Constructor.
    ProcessorWrapper() {}

    //! Notifies the first Python plug-in processor about a packet.
    virtual void notify(PacketInfo* packet_info, size_t packets) override
    {
        try
        {
            std::lock_guard<std::mutex> _lock(GlobalPythonPluginLock);
            if(!m_PythonProcessors.empty())
                m_PythonProcessors.front().attr("notify")(ptr(packet_info), packets);
        }
        catch(error_already_set&)
        {
            THROW_PYTHON_EXCEPTION("python-binding: ");
        }
    }

    //! Attaches a Python plug-in processor to this dispatcher object.
    void attachPluginProcessor(const boost::python::object& proc)
    {
        try
        {
            m_PythonProcessors.push_back(proc);
            if(m_PythonProcessors.size() > 1)
            {
                ProcessorPtr new_last = extract<ProcessorPtr>(proc),
                             old_last = extract<ProcessorPtr>(m_PythonProcessors[m_PythonProcessors.size() - 2]);
                SinkPtr      _sink = old_last->getMainSink();
                new_last->attach(_sink);
                old_last->attach(new_last);
            }
        }
        catch(error_already_set&)
        {
            THROW_PYTHON_EXCEPTION("python-binding: ");
        }
    }

    //! Attaches a data sink to the last Python plug-in processor.
    virtual void attach(const SinkPtr& _sink)
    {
        try
        {
            if(!m_PythonProcessors.empty())
                m_PythonProcessors.back().attr("attach")(_sink);
        }
        catch(error_already_set&)
        {
            THROW_PYTHON_EXCEPTION("python-binding: ");
        }
    }
};

class DataSinkWrapper: public DataSink
{
    boost::python::object               m_PyDataSink;
public:
    /*! Constructor.
     */
    DataSinkWrapper(boost::asio::io_service& io_service,
                    DataSource& src, const boost::python::object& py_data_sink)
        :   DataSink(io_service, src),
            m_PyDataSink(py_data_sink)
    {
    }

    //! Notifies the Python plug-in data source about a packet.
    virtual void notify(PacketInfo* packet_info, size_t packets) override
    {
        try
        {
            std::lock_guard<std::mutex> _lock(GlobalPythonPluginLock);
            m_PyDataSink.attr("notify")(ptr(packet_info), packets);
        }
        catch(error_already_set&)
        {
            THROW_PYTHON_EXCEPTION("python-binding: ");
        }
    }
};

class DataSourceWrapper: public DataSource
{
    boost::python::object               m_PyDataSource;
public:
    DataSourceWrapper(boost::asio::io_service& io_service,
                      termination_handler hnd, size_t buffer_size,
                      size_t burst_size, size_t timeout,
                      bool memory_locking, const boost::python::object& py_data_src)
        :   DataSource(io_service, hnd, buffer_size, memory_locking, burst_size, timeout),
            m_PyDataSource(py_data_src)
    {
    }

    //! Returns a reference to the internal buffer.
    CommonBuffer& getBuffer()
    {
        return extract<CommonBuffer&>(m_PyDataSource.attr("getBuffer")());
    }

    //! Starts the capturing process in asynchronous mode.
    virtual void startAsync()
    {
        std::lock_guard<std::mutex> _lock(GlobalPythonPluginLock);
        m_PyDataSource.attr("startAsync")();
    }

    //! Starts the capturing process in the current thread.
    virtual void start()
    {
        THROW_EXCEPTION("python-binding: synchronous mode is not supported");
    }

    //! Stops the capturing process.
    virtual void stop()
    {
        std::lock_guard<std::mutex> _lock(GlobalPythonPluginLock);
        m_PyDataSource.attr("stop")();
    }

    /*! \brief Sets the BPF filter expression
     *  \param expr     the expression that is going to be used for filtering.
     */
    virtual void setFilterExpression(const std::string& expr)
    {
        m_PyDataSource.attr("setFilterExpression")(expr);
    }

    //! Returns the name of the source that is currently being used.
    virtual std::string getName() const
    {
        return extract<std::string>(m_PyDataSource.attr("getName")());
    }

    //! Returns true if the source, which is currently opened, is a file.
    virtual bool isFile() const
    {
        return extract<bool>(m_PyDataSource.attr("isFile")());
    }

    //! Returns the link type as specified in the libpcap documentation.
    virtual int getLinkType() const
    {
        return extract<int>(m_PyDataSource.attr("getLinkType")());
    }

    //! Returns the snapshot length.
    virtual int getSnapshot() const
    {
        return extract<int>(m_PyDataSource.attr("getSnapshot")());
    }

    //! Returns the link type as a string.
    virtual std::string getLinkTypeName() const
    {
        return extract<std::string>(m_PyDataSource.attr("getLinkTypeName")());
    }

    //! Returns the total amount of packets that have been captured by this object.
    virtual size_t getPacketsCaptured() const
    {
        return extract<size_t>(m_PyDataSource.attr("getPacketsCaptured")());
    }

    //! Returns the total amount of packets that have been captured by the kernel.
    virtual size_t getPacketsCapturedKernel() const
    {
        return extract<size_t>(m_PyDataSource.attr("getPacketsCapturedKernel")());
    }

    //! Returns the total amount of packets dropped by the kernel.
    virtual size_t getPacketsDroppedKernel() const
    {
        return extract<size_t>(m_PyDataSource.attr("getPacketsDroppedKernel")());
    }

    //! Returns the total amount of packets dropped by the driver.
    virtual size_t getPacketsDroppedDriver() const
    {
        return extract<size_t>(m_PyDataSource.attr("getPacketsDroppedDriver")());
    }

    //! Returns the total amount of packets dropped due to buffer overflow.
    virtual size_t getPacketsDroppedBuffer() const
    {
        return extract<size_t>(m_PyDataSource.attr("getPacketsDroppedBuffer")());
    }
};

typedef boost::shared_ptr<ProcessorWrapper> ProcessorWrapperPtr;
typedef boost::shared_ptr<DataSink> DataSinkWrapperPtr;
typedef boost::shared_ptr<DataSource> DataSourceWrapperPtr;



PythonBindingPlugin::PythonBindingPlugin()
{
    PyImport_AppendInittab("RCDCap", &PyInit_RCDCap );
    Py_Initialize();
    PyEval_InitThreads();
}

PythonBindingPlugin::~PythonBindingPlugin()
{
    Py_Finalize();
}

void PythonBindingPlugin::init(boost::asio::io_service& io_service,
                               popt::options_description& opts)
{
    using namespace boost::filesystem;
    char buf[1024];
    if(readlink("/proc/self/exe", buf, sizeof(buf)) < 0)
        THROW_EXCEPTION(std::string("could not read executable absolute path from /proc/self/exe: ") + strerror(errno));
    path exe_path(buf);
    path p = exe_path.parent_path().parent_path()/"share"/"rcdcap"/"plugins";
    if(exists(p) && is_directory(p))
        for(auto i = directory_iterator(p); i != directory_iterator(); ++i)
        {
            try
            {
                if(is_directory(i->path()) || i->path().extension() != ".py")
                    continue;
                dict locals;
                object main_module = import("__main__");
                object main_namespace = main_module.attr("__dict__");
                exec_file(str(i->path().native()), main_namespace);
                object _plugin = main_namespace["RCDCapCreatePlugin"]();
                _plugin.attr("init")(boost::ref(io_service), boost::ref(opts));
                m_Plugins.push_back(_plugin);
            }
            catch(error_already_set const &)
            {
                THROW_PYTHON_EXCEPTION("python-binding: ");
            }
        }
}

void dummy_func() {}

DataSourcePtr PythonBindingPlugin::hasSource(const popt::variables_map& vm)
{
    DataSourceWrapperPtr data_source;
    try
    {
        for(auto i = m_Plugins.begin(); i != m_Plugins.end(); ++i)
        {
            object source = i->attr("hasSource")(boost::ref(vm));
            DataSourcePtr tmp = extract<DataSourcePtr>(source);
            if(!tmp)
                continue;
            if(data_source)
                THROW_EXCEPTION("python-binding: more than a single data source is unsupported");
            data_source = boost::make_shared<DataSourceWrapper>(*m_IOService, &dummy_func, 1, false, vm["burst-size"].as<size_t>(), vm["timeout"].as<size_t>(), source);
        }
    }
    catch(error_already_set const &)
    {
        THROW_PYTHON_EXCEPTION("python-binding: ");
    }
    return data_source;
}

ProcessorPtr PythonBindingPlugin::hasProcessor(DataSource& src,
                                               const popt::variables_map& vm)
{
    ProcessorWrapperPtr proc_wrap;
    try
    {
        for(auto i = m_Plugins.begin(); i != m_Plugins.end(); ++i)
        {
            object proc = i->attr("hasProcessor")(boost::ref(src), boost::ref(vm));
            ProcessorPtr tmp = extract<ProcessorPtr>(proc);
            if(!tmp)
                continue;
            if(!proc_wrap)
                proc_wrap = boost::make_shared<ProcessorWrapper>();
            proc_wrap->attachPluginProcessor(proc);
        }
    }
    catch(error_already_set const &)
    {
        THROW_PYTHON_EXCEPTION("python-binding: ");
    }

    return proc_wrap;
}

DataSinkPtr PythonBindingPlugin::hasSink(DataSource& src,
                                         const popt::variables_map& vm)
{
    DataSinkWrapperPtr data_sink;
    try
    {
        for(auto i = m_Plugins.begin(); i != m_Plugins.end(); ++i)
        {
            object sink = i->attr("hasSink")(boost::ref(src), boost::ref(vm));
            DataSinkPtr tmp = extract<DataSinkPtr>(sink);
            if(!tmp)
                continue;
            if(data_sink)
                THROW_EXCEPTION("python-binding: more than a single data source is unsupported");
            data_sink = boost::make_shared<DataSinkWrapper>(*m_IOService, src, sink);
        }
    }
    catch(error_already_set const &)
    {
        THROW_PYTHON_EXCEPTION("python-binding: ");
    }
    return data_sink;
}

void ThrowPythonException(const std::string& excstr)
{
    auto        exception = excstr;
    PyObject    *exc,
                *val,
                *tb;
    PyErr_Fetch(&exc,&val,&tb);
    PyErr_NormalizeException(&exc,&val,&tb);
    handle<>    hexc(exc),
                hval(allow_null(val)),
                htb(allow_null(tb));
    if(!hval)
    {
        std::string pyexcstr = extract<std::string>(str(hexc));
        exception += ':' + pyexcstr;
    }
    else
    {
        object traceback(import("traceback"));
        object format_exception(traceback.attr("format_exception"));
        object formatted_list(format_exception(hexc, hval, htb));
        object formatted(str("").join(formatted_list));
        std::string pyexcstr = extract<std::string>(formatted);
        exception += ':' + pyexcstr;
    }
    THROW_EXCEPTION(exception);
}
