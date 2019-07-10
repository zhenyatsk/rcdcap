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

#ifndef _PYTHON_WRAPPING_HH_
#define _PYTHON_WRAPPING_HH_

#include <vector>
#include <iostream>
#include <iterator>

using std::vector;

// HACK! HACK! HACK! HACK! HACK! HACK! HACK! HACK! HACK! HACK! HACK! HACK!
namespace boost
{
//! Outputs the contents of a vector object to the standard output.
template<class T>
std::ostream& operator<<(std::ostream& os, const std::vector<T>& v)
{
    std::copy(v.begin(), v.end(), std::ostream_iterator<T>(os, " ")); 
    return os;
}
}
// HACK! HACK! HACK! HACK! HACK! HACK! HACK! HACK! HACK! HACK! HACK! HACK!


#include "rcdcap/plugin.hh"
#include "rcdcap/source.hh"
#include "rcdcap/processor.hh"
#include "rcdcap/packet-hierarchy.hh"

#include <boost/system/error_code.hpp>
#include <boost/python.hpp>
#include <boost/python/suite/indexing/vector_indexing_suite.hpp>
#include <boost/program_options.hpp>

using namespace RCDCap;
using namespace boost::python;

//! Used for re-throwing exception raised in Python in C++.
#define THROW_PYTHON_EXCEPTION(excstr) \
    ThrowPythonException(__FILE__ ":" TO_STRING(__LINE__) ": " + std::string(excstr))
/*! \brief Reads and re-throws a Python exception in C++
 *  \param excstr   
 */
void ThrowPythonException(const std::string& excstr);

std::mutex GlobalPythonPluginLock;

//! Python GIL RAII
class PythonGIL
{
    //! GIL state.
    PyGILState_STATE    m_GState;
public:
    //! Acquires the Global Interpreter Lock.
    PythonGIL()
        :   m_GState(PyGILState_Ensure()) {}
    //! Releases the Global Interpreter Lock.
    ~PythonGIL() { PyGILState_Release(m_GState); }
};

//! Wraps RCDCap's Source class.
class SourceWrap: public Source, public wrapper<Source>
{
public:
    //! Constructor.
    explicit SourceWrap() {}

    //! Destructor.
    virtual ~SourceWrap() {}

    //! Wraps Source::attach.
    virtual void attach(const SinkPtr& _sink)
    {
        if(override override_attach = this->get_override("attach"))
            override_attach(_sink);
        else
            Source::attach(_sink);
    }

    //! Calls the default implementation of Source::attach.
    void default_attach(const SinkPtr& _sink)
        { Source::attach(_sink); }
};

//! Wraps RCDCap's DataSource class.
class DataSourceWrap: public DataSource, public wrapper<DataSource>
{
public:
    /*! Constructor.
     *  \param io_service           a reference to Boost.ASIO I/O Service.
     *  \param hnd                  a termination handler which is called when the capturing process is terminated prematurely.
     *  \param buffer_size          specifies the size of the RCDCap's internal buffer.
     *  \param memory_locking       specifies whether the internal buffer memory must be locked.
     */
    explicit DataSourceWrap(boost::asio::io_service& io_service,
                            termination_handler hnd,
                            size_t buffer_size, bool memory_locking,
                            size_t burst_size, size_t timeout)
        :   DataSource(io_service, hnd, buffer_size, memory_locking, burst_size, timeout) {}

    //! Destructor.
    virtual ~DataSourceWrap() {}

    //! Wraps DataSource::startAsync.
    virtual void startAsync()
        { this->get_override("startAsync")(); }

    //! Wraps DataSource::start.
    virtual void start()
        { this->get_override("start")(); }

    //! Wraps DataSource::stop.
    virtual void stop()
        { this->get_override("stop")(); }

    //! Wraps DataSource::setFilterExpression.
    virtual void setFilterExpression(const std::string& expr)
        { this->get_override("setFilterExpression")(expr); }

    //! Wraps DataSource::getName.
    virtual std::string getName() const
        { return this->get_override("getName")(); }

    //! Wraps DataSource::isFile.
    virtual bool isFile() const
        { return this->get_override("isFile")(); }

    //! Wraps DataSource::getLinkType.
    virtual int getLinkType() const
        { return this->get_override("getLinkType")(); }

    //! Wraps DataSource::getSnapshot.
    virtual int getSnapshot() const
        { return this->get_override("getSnapshot")(); }

    //! Wraps DataSource::getLinkTypeName.
    virtual std::string getLinkTypeName() const
        { return this->get_override("getLinkTypeName")(); }

    //! Wraps DataSource::getPacketsCaptured.
    virtual size_t getPacketsCaptured() const
        { return this->get_override("getPacketsCaptured")(); }
    
    //! Wraps DataSource::getPacketsCapturedKernel.
    virtual size_t getPacketsCapturedKernel() const
        { return this->get_override("getPacketsCapturedKernel")(); }

    //! Wraps DataSource::getPacketsDroppedKernel.
    virtual size_t getPacketsDroppedKernel() const
        { return this->get_override("getPacketsDroppedKernel")(); }

    //! Wraps DataSource::getPacketsDroppedDriver.
    virtual size_t getPacketsDroppedDriver() const
        { return this->get_override("getPacketsDroppedDriver")(); }

    //! Wraps DataSource::getPacketsDroppedBuffer.
    virtual size_t getPacketsDroppedBuffer() const
        { return this->get_override("getPacketsDroppedBuffer")(); }
};

//! Wraps RCDCap's Sink class.
class SinkWrap: public Sink, public wrapper<Sink>
{
public:
    //! Constructor.
    explicit SinkWrap() {}

    //! Destructor.
    virtual ~SinkWrap() {}

    //! Wraps Sink::notify.
    virtual void notify(PacketInfo* packet_info, size_t packets) override
        { this->get_override("notify")(ptr(packet_info), packets); }
};

//! Wraps RCDCap's DataSink class.
class DataSinkWrap: public DataSink, public wrapper<DataSink>
{
public:
    /*! Constructor.
     *  \param io_service       a reference to Boost.ASIO I/O Service.
     *  \param src              a reference to the data source inside RCDCap's pipeline.
     */
    explicit DataSinkWrap(boost::asio::io_service& io_service, DataSource& src)
        : DataSink(io_service, src) {}

    //! Destructor.
    virtual ~DataSinkWrap() {}

    //! Wraps DataSink::notify.
    virtual void notify(PacketInfo* packet_info, size_t packets) override
        { this->get_override("notify")(ptr(packet_info), packets); }
};

//! Wraps RCDCap's Processor class.
class ProcessorWrap: public Processor, public wrapper<Processor>
{
public:
    //! Constructor.
    explicit ProcessorWrap() {}

    //! Destructor.
    virtual ~ProcessorWrap() {}

    //! Wraps Processor::attach.
    virtual void attach(const SinkPtr& _sink)
    {
        if(override override_attach = this->get_override("attach"))
            override_attach(_sink);
        else
            Source::attach(_sink);
    }

    //! Calls the default implementation of Processor::attach.
    void default_attach(const SinkPtr& _sink)
    { Source::attach(_sink); }

    //! Wraps Processor::notify.
    virtual void notify(PacketInfo* packet_info, size_t packets) override
    {
        this->get_override("notify")(ptr(packet_info), packets);
    }
};

//! Wraps RCDCap's Plugin class.
class PluginWrap: public Plugin, public wrapper<Plugin>
{
public:
    //! Constructor.
    explicit PluginWrap() {}

    //! Destructor.
    virtual ~PluginWrap() {}

    //! Wraps Plugin::init.
    virtual void init(boost::asio::io_service& io_service,
                      popt::options_description& opts)
        { this->get_override("init")(io_service, opts); }


    //! Wraps Plugin::hasSource.
    virtual DataSourcePtr hasSource(const popt::variables_map& vm)
    {
        if(override override_hasSource = this->get_override("hasSource"))
            return override_hasSource(vm); // *note*
        return Plugin::hasSource(vm);
    }

    //! Calls the default implementation of Plugin::hasSource.
    DataSourcePtr default_hasSource(const popt::variables_map& vm)
        { return this->Plugin::hasSource(vm); }

    //! Wraps Plugin::hasProcessor.
    virtual ProcessorPtr hasProcessor(DataSource& src,
                                      const popt::variables_map& vm)
    {
        if(override override_hasProcessor = this->get_override("hasProcessor"))
            return override_hasProcessor(src, vm); // *note*
        return Plugin::hasProcessor(src, vm);
    }

    //! Calls the default implementation of Plugin::hasProcessor.
    ProcessorPtr default_hasProcessor(DataSource& src, 
                                      const popt::variables_map& vm)
        { return this->Plugin::hasProcessor(src, vm); }

    //! Wraps Plugin::hasSink.
    virtual DataSinkPtr hasSink(DataSource& src, const popt::variables_map& vm)
    {
        if(override override_hasSink = this->get_override("hasSink"))
            return override_hasSink(src, vm); // *note*
        return Plugin::hasSink(src, vm);
    }

    //! Calls the default implementation of Plugin::hasSink.
    DataSinkPtr default_hasSink(DataSource& src,
                                const popt::variables_map& vm)
        { return this->Plugin::hasSink(src, vm); }
};

// Overrides associated with boost::asio::io_service.
BOOST_PYTHON_MEMBER_FUNCTION_OVERLOADS(io_service_run_overloads, run, 0, 1)
BOOST_PYTHON_MEMBER_FUNCTION_OVERLOADS(io_service_run_one_overloads, run_one, 0, 1)
BOOST_PYTHON_MEMBER_FUNCTION_OVERLOADS(io_service_poll_overloads, poll, 0, 1)
BOOST_PYTHON_MEMBER_FUNCTION_OVERLOADS(io_service_poll_one_overloads, poll_one, 0, 1)

// Overrides associated with boost::program_options::options_description_easy_init.
popt::options_description_easy_init& (popt::options_description_easy_init::*opp1)(const char*, const char*) =
    &popt::options_description_easy_init::operator();
popt::options_description_easy_init& (popt::options_description_easy_init::*opp2)(const char*, const popt::value_semantic*) =
    &popt::options_description_easy_init::operator();
popt::options_description_easy_init& (popt::options_description_easy_init::*opp3)(const char*, const popt::value_semantic*, const char*) =
    &popt::options_description_easy_init::operator();

//! Wraps Boost Program Options' value_semantic class.
class value_semantic_wrap: public popt::value_semantic, public wrapper<popt::value_semantic>
{
public:
    //! Constructor.
    explicit value_semantic_wrap() {}

    //! Destructor.
    virtual ~value_semantic_wrap() {}

    //! Wraps boost::program_options::value_semantic::name.
    virtual std::string name() const
    {
        return this->get_override("name")();
    }

    //! Wraps boost::program_options::value_semantic::min_tokens.
    virtual unsigned min_tokens() const
    {
        return this->get_override("min_tokens")();
    }

    //! Wraps boost::program_options::value_semantic::max_tokens.
    virtual unsigned max_tokens() const
    {
        return this->get_override("max_tokens")();
    }

    //! Wraps boost::program_options::value_semantic::is_composing.
    virtual bool is_composing() const
    {
        return this->get_override("is_composing")();
    }

    //! Wraps boost::program_options::value_semantic::is_required.
    virtual bool is_required() const
    {
        return this->get_override("is_required")();
    }

    //! Wraps boost::program_options::value_semantic::parse.
    virtual void parse(boost::any& value_store, 
                       const vector<std::string>& new_tokens,
                       bool utf8) const 
    {
        this->get_override("parse")(value_store, new_tokens, utf8);
    }

    //! Wraps boost::program_options::value_semantic::apply_default.
    virtual bool apply_default(boost::any& value_store) const
    {
        return this->get_override("apply_default")(value_store);
    }

    //! Wraps boost::program_options::value_semantic::notify.
    virtual void notify(const boost::any& value_store) const
    {
        this->get_override("notify")(value_store);
    }
};

// Defines overrides of some function of boost::program_options::typed_value<T>
// exposed by this plug-in.
#define OVERLOADS_TYPED_VALUE(_type, _name) \
    popt::typed_value<_type, char>* (popt::typed_value<_type, char>::*_name##_default_value1)(const _type&) = &popt::typed_value<_type, char>::default_value;\
    popt::typed_value<_type, char>* (popt::typed_value<_type, char>::*_name##_default_value2)(const _type&, const std::string&) = &popt::typed_value<_type, char>::default_value;\
    popt::typed_value<_type, char>* (popt::typed_value<_type, char>::*_name##_implicit_value1)(const _type &) = &popt::typed_value<_type, char>::implicit_value;\
    popt::typed_value<_type, char>* (popt::typed_value<_type, char>::*_name##_implicit_value2)(const _type &, const std::string&) = &popt::typed_value<_type, char>::implicit_value;

// Simplifies the process of wrapping boost::program_options::typed_value<T>.
#define WRAP_TYPED_VALUE(_type, _name) \
    OVERLOADS_TYPED_VALUE(_type, _name) \
    class_<popt::typed_value<_type, char>, bases<popt::value_semantic>, boost::noncopyable>(TO_STRING(typed_##_name), no_init) \
        .def("default_value", _name##_default_value1, return_value_policy<reference_existing_object>()) \
        .def("default_value", _name##_default_value2, return_value_policy<reference_existing_object>()) \
        .def("value_name", &popt::typed_value<_type, char>::value_name, return_value_policy<reference_existing_object>()) \
        .def("implicit_value", _name##_implicit_value1, return_value_policy<reference_existing_object>()) \
        .def("implicit_value", _name##_implicit_value2, return_value_policy<reference_existing_object>()) \
        .def("notifier", &popt::typed_value<_type, char>::notifier, return_value_policy<reference_existing_object>()) \
        .def("composing", &popt::typed_value<_type, char>::composing, return_value_policy<reference_existing_object>()) \
        .def("multitoken", &popt::typed_value<_type, char>::multitoken, return_value_policy<reference_existing_object>()) \
        .def("zero_tokens", &popt::typed_value<_type, char>::zero_tokens, return_value_policy<reference_existing_object>()) \
        .def("required", &popt::typed_value<_type, char>::required, return_value_policy<reference_existing_object>()) \
    /* overrides */ \
        .def("name", &popt::typed_value<_type, char>::name) \
        .def("is_composing", &popt::typed_value<_type, char>::is_composing) \
        .def("min_tokens", &popt::typed_value<_type, char>::min_tokens) \
        .def("max_tokens", &popt::typed_value<_type, char>::max_tokens) \
        .def("is_required", &popt::typed_value<_type, char>::is_required) \
        .def("xparse", &popt::typed_value<_type, char>::xparse) \
        .def("apply_default", &popt::typed_value<_type, char>::apply_default) \
        .def("notify", &popt::typed_value<_type, char>::notify) \
    ; \
    popt::typed_value<_type, char>* (*_name##_val_func1)() = &popt::value<_type>; \
    popt::typed_value<_type, char>* (*_name##_val_func2)(_type*) = &popt::value<_type>; \
    def(TO_STRING(_name), _name##_val_func1, return_value_policy<reference_existing_object>()); \
    def(TO_STRING(_name), _name##_val_func2, return_value_policy<reference_existing_object>());

// Typedefs of the vector object implementations exposed by this plug-in.
typedef vector<char> VectorChar;
typedef vector<int> VectorInt;
typedef vector<short> VectorShort;
typedef vector<long long> VectorLongLong;
typedef vector<unsigned char> VectorUnsignedChar;
typedef vector<unsigned int> VectorUnsignedInt;
typedef vector<unsigned short> VectorUnsignedShort;
typedef vector<unsigned long long> VectorUnsignedLongLong;
typedef vector<float> VectorFloat;
typedef vector<double> VectorDouble;
typedef vector<std::string> VectorString;

// Overrides of boost::program_options::variable_value::as<T> which are exposed
// by this plug-in.
const char& (popt::variable_value::*char_func1)() const = &popt::variable_value::as<char>;
const int& (popt::variable_value::*int_func1)() const = &popt::variable_value::as<int>;
const short& (popt::variable_value::*short_func1)() const = &popt::variable_value::as<short>;
const long long& (popt::variable_value::*long_long_func1)() const = &popt::variable_value::as<long long>;
const unsigned char& (popt::variable_value::*uchar_func1)() const = &popt::variable_value::as<unsigned char>;
const unsigned int& (popt::variable_value::*uint_func1)() const = &popt::variable_value::as<unsigned int>;
const unsigned short& (popt::variable_value::*ushort_func1)() const = &popt::variable_value::as<unsigned short>;
const unsigned long long& (popt::variable_value::*ulong_long_func1)() const = &popt::variable_value::as<unsigned long long>;
const float& (popt::variable_value::*float_func1)() const = &popt::variable_value::as<float>;
const double& (popt::variable_value::*double_func1)() const = &popt::variable_value::as<double>;
const std::string& (popt::variable_value::*string_func1)() const = &popt::variable_value::as<std::string>;
const VectorChar& (popt::variable_value::*vector_char_func1)() const = &popt::variable_value::as<VectorChar>;
const VectorInt& (popt::variable_value::*vector_int_func1)() const = &popt::variable_value::as<VectorInt>;
const VectorShort& (popt::variable_value::*vector_short_func1)() const = &popt::variable_value::as<VectorShort>;
const VectorLongLong& (popt::variable_value::*vector_long_long_func1)() const = &popt::variable_value::as<VectorLongLong>;
const VectorUnsignedChar& (popt::variable_value::*vector_uchar_func1)() const = &popt::variable_value::as<VectorUnsignedChar>;
const VectorUnsignedInt& (popt::variable_value::*vector_uint_func1)() const = &popt::variable_value::as<VectorUnsignedInt>;
const VectorUnsignedShort& (popt::variable_value::*vector_ushort_func1)() const = &popt::variable_value::as<VectorUnsignedShort>;
const VectorUnsignedLongLong& (popt::variable_value::*vector_ulong_long_func1)() const = &popt::variable_value::as<VectorUnsignedLongLong>;
const VectorFloat& (popt::variable_value::*vector_float_func1)() const = &popt::variable_value::as<VectorFloat>;
const VectorDouble& (popt::variable_value::*vector_double_func1)() const = &popt::variable_value::as<VectorDouble>;
const VectorString& (popt::variable_value::*vector_string_func1)() const = &popt::variable_value::as<VectorString>;
char& (popt::variable_value::*char_func2)() = &popt::variable_value::as<char>;
int& (popt::variable_value::*int_func2)() = &popt::variable_value::as<int>;
short& (popt::variable_value::*short_func2)() = &popt::variable_value::as<short>;
long long& (popt::variable_value::*long_long_func2)() = &popt::variable_value::as<long long>;
unsigned char& (popt::variable_value::*uchar_func2)() = &popt::variable_value::as<unsigned char>;
unsigned int& (popt::variable_value::*uint_func2)() = &popt::variable_value::as<unsigned int>;
unsigned short& (popt::variable_value::*ushort_func2)() = &popt::variable_value::as<unsigned short>;
unsigned long long& (popt::variable_value::*ulong_long_func2)() = &popt::variable_value::as<unsigned long long>;
float& (popt::variable_value::*float_func2)() = &popt::variable_value::as<float>;
double& (popt::variable_value::*double_func2)() = &popt::variable_value::as<double>;
std::string& (popt::variable_value::*string_func2)() = &popt::variable_value::as<std::string>;
VectorChar& (popt::variable_value::*vector_char_func2)() = &popt::variable_value::as<VectorChar>;
VectorInt& (popt::variable_value::*vector_int_func2)() = &popt::variable_value::as<VectorInt>;
VectorShort& (popt::variable_value::*vector_short_func2)() = &popt::variable_value::as<VectorShort>;
VectorLongLong& (popt::variable_value::*vector_long_long_func2)() = &popt::variable_value::as<VectorLongLong>;
VectorUnsignedChar& (popt::variable_value::*vector_uchar_func2)() = &popt::variable_value::as<VectorUnsignedChar>;
VectorUnsignedInt& (popt::variable_value::*vector_uint_func2)() = &popt::variable_value::as<VectorUnsignedInt>;
VectorUnsignedShort& (popt::variable_value::*vector_ushort_func2)() = &popt::variable_value::as<VectorUnsignedShort>;
VectorUnsignedLongLong& (popt::variable_value::*vector_ulong_long_func2)() = &popt::variable_value::as<VectorUnsignedLongLong>;
VectorFloat& (popt::variable_value::*vector_float_func2)() = &popt::variable_value::as<VectorFloat>;
VectorDouble& (popt::variable_value::*vector_double_func2)() = &popt::variable_value::as<VectorDouble>;
VectorString& (popt::variable_value::*vector_string_func2)() = &popt::variable_value::as<VectorString>;

// Overrides of some function exposed by ip_t.
ip_t::reference (ip_t::*ip_t_func1)(size_t) = &ip_t::operator[];
ip_t::const_reference (ip_t::*ip_t_func2)(size_t) const= &ip_t::operator[];

// Overrides of some function exposed by mac_t.
mac_t::reference (mac_t::*mac_t_func1)(size_t) = &mac_t::operator[];
mac_t::const_reference (mac_t::*mac_t_func2)(size_t) const = &mac_t::operator[];

//! Converts a specific type string.
template<class T>
std::string to_string(const T& t)
{
    std::stringstream ss;
    ss << t;
    return ss.str();
}

/*! \brief Wraps a callable Python object, so that it is usable by
 *         boost::asio::io_service::dispatch and boost::asio::io_service::post
 */
class io_service_completion_handler
{
    object                  m_Callable; //!< Represents the actual callable object.
public:
    /*! \brief Constructor.
     *  \param callable     a reference to callable Python object.
     */
    io_service_completion_handler(const object& callable)
        :   m_Callable(callable) {}

    //! Executes the callable object.
    void operator()()
    {
        try
        {
            std::lock_guard<std::mutex> _lock(GlobalPythonPluginLock);
            m_Callable();
        }
        catch(error_already_set&)
        {
            THROW_PYTHON_EXCEPTION("python-binding: ");
        }
    }
};

//! Wraps boost::asio::io_service::post.
void io_service_post_wrapper(boost::asio::io_service& io_service, const object& callable)
{
    io_service.post(boost::function<void ()>(io_service_completion_handler(callable)));
}

//! Wraps boost::asio::io_service::dispatch.
void io_service_dispatch_wrapper(boost::asio::io_service& io_service, const object& callable)
{
    io_service.dispatch(boost::function<void ()>(io_service_completion_handler(callable)));
}

BOOST_PYTHON_MODULE(RCDCap)
{
    // Wraps RCDCap's EtherType enumerator type.
    enum_<EtherType>("EtherType")
        .value("RCDCAP_ETHER_TYPE_PARC", EtherType::RCDCAP_ETHER_TYPE_PARC)
        .value("RCDCAP_ETHER_TYPE_IPv4", EtherType::RCDCAP_ETHER_TYPE_IPv4)
        .value("RCDCAP_ETHER_TYPE_ARP", EtherType::RCDCAP_ETHER_TYPE_ARP)
        .value("RCDCAP_ETHER_TYPE_DECnetIV", EtherType::RCDCAP_ETHER_TYPE_DECnetIV)
        .value("RCDCAP_ETHER_TYPE_RARP", EtherType::RCDCAP_ETHER_TYPE_RARP)
        .value("RCDCAP_ETHER_TYPE_EtherTalk", EtherType::RCDCAP_ETHER_TYPE_EtherTalk)
        .value("RCDCAP_ETHER_TYPE_AARP", EtherType::RCDCAP_ETHER_TYPE_AARP)
        .value("RCDCAP_ETHER_TYPE_802_1Q", EtherType::RCDCAP_ETHER_TYPE_802_1Q)
        .value("RCDCAP_ETHER_TYPE_IPX", EtherType::RCDCAP_ETHER_TYPE_IPX)
        .value("RCDCAP_ETHER_TYPE_Novell", EtherType::RCDCAP_ETHER_TYPE_Novell)
        .value("RCDCAP_ETHER_TYPE_QNX", EtherType::RCDCAP_ETHER_TYPE_QNX)
        .value("RCDCAP_ETHER_TYPE_IPv6", EtherType::RCDCAP_ETHER_TYPE_IPv6)
        .value("RCDCAP_ETHER_TYPE_MPCP", EtherType::RCDCAP_ETHER_TYPE_MPCP)
        .value("RCDCAP_ETHER_TYPE_MPLS_unicast", EtherType::RCDCAP_ETHER_TYPE_MPLS_unicast)
        .value("RCDCAP_ETHER_TYPE_MPLS_multicast", EtherType::RCDCAP_ETHER_TYPE_MPLS_multicast)
        .value("RCDCAP_ETHER_TYPE_PPPoE_Discovery", EtherType::RCDCAP_ETHER_TYPE_PPPoE_Discovery)
        .value("RCDCAP_ETHER_TYPE_PPPoE_Session", EtherType::RCDCAP_ETHER_TYPE_PPPoE_Session)
        .value("RCDCAP_ETHER_TYPE_NLB", EtherType::RCDCAP_ETHER_TYPE_NLB)
        .value("RCDCAP_ETHER_TYPE_Jumbo", EtherType::RCDCAP_ETHER_TYPE_Jumbo)
        .value("RCDCAP_ETHER_TYPE_EAPoL", EtherType::RCDCAP_ETHER_TYPE_EAPoL)
        .value("RCDCAP_ETHER_TYPE_PROFINET", EtherType::RCDCAP_ETHER_TYPE_PROFINET)
        .value("RCDCAP_ETHER_TYPE_HyperSCSI", EtherType::RCDCAP_ETHER_TYPE_HyperSCSI)
        .value("RCDCAP_ETHER_TYPE_ATAoE", EtherType::RCDCAP_ETHER_TYPE_ATAoE)
        .value("RCDCAP_ETHER_TYPE_EtherCAT", EtherType::RCDCAP_ETHER_TYPE_EtherCAT)
        .value("RCDCAP_ETHER_TYPE_ProviderBridging", EtherType::RCDCAP_ETHER_TYPE_ProviderBridging)
        .value("RCDCAP_ETHER_TYPE_Powerlink", EtherType::RCDCAP_ETHER_TYPE_Powerlink)
        .value("RCDCAP_ETHER_TYPE_LLDP", EtherType::RCDCAP_ETHER_TYPE_LLDP)
        .value("RCDCAP_ETHER_TYPE_SERCOSIII", EtherType::RCDCAP_ETHER_TYPE_SERCOSIII)
        .value("RCDCAP_ETHER_TYPE_MEF_8", EtherType::RCDCAP_ETHER_TYPE_MEF_8)
        .value("RCDCAP_ETHER_TYPE_HomePlug", EtherType::RCDCAP_ETHER_TYPE_HomePlug)
        .value("RCDCAP_ETHER_TYPE_MRP", EtherType::RCDCAP_ETHER_TYPE_MRP)
        .value("RCDCAP_ETHER_TYPE_MACsecu", EtherType::RCDCAP_ETHER_TYPE_MACsecu)
        .value("RCDCAP_ETHER_TYPE_PTime", EtherType::RCDCAP_ETHER_TYPE_PTime)
        .value("RCDCAP_ETHER_TYPE_FCoE", EtherType::RCDCAP_ETHER_TYPE_FCoE)
    ;

    // Wraps RCDCap's ProtocolType enumerator type.
    enum_<ProtocolType>("ProtocolType")
        .value("RCDCAP_PROTOCOL_TYPE_HOPOPT", ProtocolType::RCDCAP_PROTOCOL_TYPE_HOPOPT)
        .value("RCDCAP_PROTOCOL_TYPE_ICMP", ProtocolType::RCDCAP_PROTOCOL_TYPE_ICMP)
        .value("RCDCAP_PROTOCOL_TYPE_IGMP", ProtocolType::RCDCAP_PROTOCOL_TYPE_IGMP)
        .value("RCDCAP_PROTOCOL_TYPE_GGP", ProtocolType::RCDCAP_PROTOCOL_TYPE_GGP)
        .value("RCDCAP_PROTOCOL_TYPE_IPv4", ProtocolType::RCDCAP_PROTOCOL_TYPE_IPv4)
        .value("RCDCAP_PROTOCOL_TYPE_ST", ProtocolType::RCDCAP_PROTOCOL_TYPE_ST)
        .value("RCDCAP_PROTOCOL_TYPE_TCP", ProtocolType::RCDCAP_PROTOCOL_TYPE_TCP)
        .value("RCDCAP_PROTOCOL_TYPE_CBT", ProtocolType::RCDCAP_PROTOCOL_TYPE_CBT)
        .value("RCDCAP_PROTOCOL_TYPE_EGP", ProtocolType::RCDCAP_PROTOCOL_TYPE_EGP)
        .value("RCDCAP_PROTOCOL_TYPE_IGP", ProtocolType::RCDCAP_PROTOCOL_TYPE_IGP)
        .value("RCDCAP_PROTOCOL_TYPE_BBN_RCC_MON", ProtocolType::RCDCAP_PROTOCOL_TYPE_BBN_RCC_MON)
        .value("RCDCAP_PROTOCOL_TYPE_NVP_II", ProtocolType::RCDCAP_PROTOCOL_TYPE_NVP_II)
        .value("RCDCAP_PROTOCOL_TYPE_PUP", ProtocolType::RCDCAP_PROTOCOL_TYPE_PUP)
        .value("RCDCAP_PROTOCOL_TYPE_ARGUS", ProtocolType::RCDCAP_PROTOCOL_TYPE_ARGUS)
        .value("RCDCAP_PROTOCOL_TYPE_EMCON", ProtocolType::RCDCAP_PROTOCOL_TYPE_EMCON)
        .value("RCDCAP_PROTOCOL_TYPE_XNET", ProtocolType::RCDCAP_PROTOCOL_TYPE_XNET)
        .value("RCDCAP_PROTOCOL_TYPE_CHAOS", ProtocolType::RCDCAP_PROTOCOL_TYPE_CHAOS)
        .value("RCDCAP_PROTOCOL_TYPE_UDP", ProtocolType::RCDCAP_PROTOCOL_TYPE_UDP)
        .value("RCDCAP_PROTOCOL_TYPE_MUX", ProtocolType::RCDCAP_PROTOCOL_TYPE_MUX)
        .value("RCDCAP_PROTOCOL_TYPE_DCN_MEAS", ProtocolType::RCDCAP_PROTOCOL_TYPE_DCN_MEAS)
        .value("RCDCAP_PROTOCOL_TYPE_HMP", ProtocolType::RCDCAP_PROTOCOL_TYPE_HMP)
        .value("RCDCAP_PROTOCOL_TYPE_PRM", ProtocolType::RCDCAP_PROTOCOL_TYPE_PRM)
        .value("RCDCAP_PROTOCOL_TYPE_XNS_IDP", ProtocolType::RCDCAP_PROTOCOL_TYPE_XNS_IDP)
        .value("RCDCAP_PROTOCOL_TYPE_TRUNK_1", ProtocolType::RCDCAP_PROTOCOL_TYPE_TRUNK_1)
        .value("RCDCAP_PROTOCOL_TYPE_TRUNK_2", ProtocolType::RCDCAP_PROTOCOL_TYPE_TRUNK_2)
        .value("RCDCAP_PROTOCOL_TYPE_LEAF_1", ProtocolType::RCDCAP_PROTOCOL_TYPE_LEAF_1)
        .value("RCDCAP_PROTOCOL_TYPE_LEAF_2", ProtocolType::RCDCAP_PROTOCOL_TYPE_LEAF_2)
        .value("RCDCAP_PROTOCOL_TYPE_RDP", ProtocolType::RCDCAP_PROTOCOL_TYPE_RDP)
        .value("RCDCAP_PROTOCOL_TYPE_IRTP", ProtocolType::RCDCAP_PROTOCOL_TYPE_IRTP)
        .value("RCDCAP_PROTOCOL_TYPE_ISO_TP4", ProtocolType::RCDCAP_PROTOCOL_TYPE_ISO_TP4)
        .value("RCDCAP_PROTOCOL_TYPE_NETBLT", ProtocolType::RCDCAP_PROTOCOL_TYPE_NETBLT)
        .value("RCDCAP_PROTOCOL_TYPE_MFE_NSP", ProtocolType::RCDCAP_PROTOCOL_TYPE_MFE_NSP)
        .value("RCDCAP_PROTOCOL_TYPE_MERIT_INP", ProtocolType::RCDCAP_PROTOCOL_TYPE_MERIT_INP)
        .value("RCDCAP_PROTOCOL_TYPE_DCCP", ProtocolType::RCDCAP_PROTOCOL_TYPE_DCCP)
        .value("RCDCAP_PROTOCOL_TYPE_3PC", ProtocolType::RCDCAP_PROTOCOL_TYPE_3PC)
        .value("RCDCAP_PROTOCOL_TYPE_IDPR", ProtocolType::RCDCAP_PROTOCOL_TYPE_IDPR)
        .value("RCDCAP_PROTOCOL_TYPE_XTP", ProtocolType::RCDCAP_PROTOCOL_TYPE_XTP)
        .value("RCDCAP_PROTOCOL_TYPE_DDP", ProtocolType::RCDCAP_PROTOCOL_TYPE_DDP)
        .value("RCDCAP_PROTOCOL_TYPE_IDPR_CMTP", ProtocolType::RCDCAP_PROTOCOL_TYPE_IDPR_CMTP)
        .value("RCDCAP_PROTOCOL_TYPE_TPXX", ProtocolType::RCDCAP_PROTOCOL_TYPE_TPXX)
        .value("RCDCAP_PROTOCOL_TYPE_IL", ProtocolType::RCDCAP_PROTOCOL_TYPE_IL)
        .value("RCDCAP_PROTOCOL_TYPE_IPv6", ProtocolType::RCDCAP_PROTOCOL_TYPE_IPv6)
        .value("RCDCAP_PROTOCOL_TYPE_SDRP", ProtocolType::RCDCAP_PROTOCOL_TYPE_SDRP)
        .value("RCDCAP_PROTOCOL_TYPE_IPv6_Route", ProtocolType::RCDCAP_PROTOCOL_TYPE_IPv6_Route)
        .value("RCDCAP_PROTOCOL_TYPE_IPv6_Flag", ProtocolType::RCDCAP_PROTOCOL_TYPE_IPv6_Flag)
        .value("RCDCAP_PROTOCOL_TYPE_IDRP", ProtocolType::RCDCAP_PROTOCOL_TYPE_IDRP)
        .value("RCDCAP_PROTOCOL_TYPE_RSVP", ProtocolType::RCDCAP_PROTOCOL_TYPE_RSVP)
        .value("RCDCAP_PROTOCOL_TYPE_GRE", ProtocolType::RCDCAP_PROTOCOL_TYPE_GRE)
        .value("RCDCAP_PROTOCOL_TYPE_DSR", ProtocolType::RCDCAP_PROTOCOL_TYPE_DSR)
        .value("RCDCAP_PROTOCOL_TYPE_BNA", ProtocolType::RCDCAP_PROTOCOL_TYPE_BNA)
        .value("RCDCAP_PROTOCOL_TYPE_ESP", ProtocolType::RCDCAP_PROTOCOL_TYPE_ESP)
        .value("RCDCAP_PROTOCOL_TYPE_AH", ProtocolType::RCDCAP_PROTOCOL_TYPE_AH)
        .value("RCDCAP_PROTOCOL_TYPE_I_NLSP", ProtocolType::RCDCAP_PROTOCOL_TYPE_I_NLSP)
        .value("RCDCAP_PROTOCOL_TYPE_SWIPE", ProtocolType::RCDCAP_PROTOCOL_TYPE_SWIPE)
        .value("RCDCAP_PROTOCOL_TYPE_NARP", ProtocolType::RCDCAP_PROTOCOL_TYPE_NARP)
        .value("RCDCAP_PROTOCOL_TYPE_MOBILE", ProtocolType::RCDCAP_PROTOCOL_TYPE_MOBILE)
        .value("RCDCAP_PROTOCOL_TYPE_TLSP", ProtocolType::RCDCAP_PROTOCOL_TYPE_TLSP)
        .value("RCDCAP_PROTOCOL_TYPE_SKIP", ProtocolType::RCDCAP_PROTOCOL_TYPE_SKIP)
        .value("RCDCAP_PROTOCOL_TYPE_IPv6_ICMP", ProtocolType::RCDCAP_PROTOCOL_TYPE_IPv6_ICMP)
        .value("RCDCAP_PROTOCOL_TYPE_IPv6_NoNxt", ProtocolType::RCDCAP_PROTOCOL_TYPE_IPv6_NoNxt)
        .value("RCDCAP_PROTOCOL_TYPE_IPv6_Opts", ProtocolType::RCDCAP_PROTOCOL_TYPE_IPv6_Opts)
        .value("RCDCAP_PROTOCOL_TYPE_CFTP", ProtocolType::RCDCAP_PROTOCOL_TYPE_CFTP)
        .value("RCDCAP_PROTOCOL_TYPE_SAT_EXPAK", ProtocolType::RCDCAP_PROTOCOL_TYPE_SAT_EXPAK)
        .value("RCDCAP_PROTOCOL_TYPE_KRYPTOLAN", ProtocolType::RCDCAP_PROTOCOL_TYPE_KRYPTOLAN)
        .value("RCDCAP_PROTOCOL_TYPE_RVD", ProtocolType::RCDCAP_PROTOCOL_TYPE_RVD)
        .value("RCDCAP_PROTOCOL_TYPE_IPPC", ProtocolType::RCDCAP_PROTOCOL_TYPE_IPPC)
        .value("RCDCAP_PROTOCOL_TYPE_SAT_MON", ProtocolType::RCDCAP_PROTOCOL_TYPE_SAT_MON)
        .value("RCDCAP_PROTOCOL_TYPE_VISA", ProtocolType::RCDCAP_PROTOCOL_TYPE_VISA)
        .value("RCDCAP_PROTOCOL_TYPE_IPCV", ProtocolType::RCDCAP_PROTOCOL_TYPE_IPCV)
        .value("RCDCAP_PROTOCOL_TYPE_CPNX", ProtocolType::RCDCAP_PROTOCOL_TYPE_CPNX)
        .value("RCDCAP_PROTOCOL_TYPE_CPHB", ProtocolType::RCDCAP_PROTOCOL_TYPE_CPHB)
        .value("RCDCAP_PROTOCOL_TYPE_WSN", ProtocolType::RCDCAP_PROTOCOL_TYPE_WSN)
        .value("RCDCAP_PROTOCOL_TYPE_PVP", ProtocolType::RCDCAP_PROTOCOL_TYPE_PVP)
        .value("RCDCAP_PROTOCOL_TYPE_BR_SAT_MON", ProtocolType::RCDCAP_PROTOCOL_TYPE_BR_SAT_MON)
        .value("RCDCAP_PROTOCOL_TYPE_SUN_ND", ProtocolType::RCDCAP_PROTOCOL_TYPE_SUN_ND)
        .value("RCDCAP_PROTOCOL_TYPE_WB_MON", ProtocolType::RCDCAP_PROTOCOL_TYPE_WB_MON)
        .value("RCDCAP_PROTOCOL_TYPE_WB_EXPAK", ProtocolType::RCDCAP_PROTOCOL_TYPE_WB_EXPAK)
        .value("RCDCAP_PROTOCOL_TYPE_ISO_IP", ProtocolType::RCDCAP_PROTOCOL_TYPE_ISO_IP)
        .value("RCDCAP_PROTOCOL_TYPE_VMTP", ProtocolType::RCDCAP_PROTOCOL_TYPE_VMTP)
        .value("RCDCAP_PROTOCOL_TYPE_SECURE_VMTP", ProtocolType::RCDCAP_PROTOCOL_TYPE_SECURE_VMTP)
        .value("RCDCAP_PROTOCOL_TYPE_VINES", ProtocolType::RCDCAP_PROTOCOL_TYPE_VINES)
        .value("RCDCAP_PROTOCOL_TYPE_TTP", ProtocolType::RCDCAP_PROTOCOL_TYPE_TTP)
        .value("RCDCAP_PROTOCOL_TYPE_IPTM", ProtocolType::RCDCAP_PROTOCOL_TYPE_IPTM)
        .value("RCDCAP_PROTOCOL_TYPE_NSFNET_IGP", ProtocolType::RCDCAP_PROTOCOL_TYPE_NSFNET_IGP)
        .value("RCDCAP_PROTOCOL_TYPE_DGP", ProtocolType::RCDCAP_PROTOCOL_TYPE_DGP)
        .value("RCDCAP_PROTOCOL_TYPE_EIGRP", ProtocolType::RCDCAP_PROTOCOL_TYPE_EIGRP)
        .value("RCDCAP_PROTOCOL_TYPE_OSPFIGP", ProtocolType::RCDCAP_PROTOCOL_TYPE_OSPFIGP)
        .value("RCDCAP_PROTOCOL_TYPE_Sprite_RPC", ProtocolType::RCDCAP_PROTOCOL_TYPE_Sprite_RPC)
        .value("RCDCAP_PROTOCOL_TYPE_LARP", ProtocolType::RCDCAP_PROTOCOL_TYPE_LARP)
        .value("RCDCAP_PROTOCOL_TYPE_MTP", ProtocolType::RCDCAP_PROTOCOL_TYPE_MTP)
        .value("RCDCAP_PROTOCOL_TYPE_AX25", ProtocolType::RCDCAP_PROTOCOL_TYPE_AX25)
        .value("RCDCAP_PROTOCOL_TYPE_IPIP", ProtocolType::RCDCAP_PROTOCOL_TYPE_IPIP)
        .value("RCDCAP_PROTOCOL_TYPE_MICP", ProtocolType::RCDCAP_PROTOCOL_TYPE_MICP)
        .value("RCDCAP_PROTOCOL_TYPE_SCC_SP", ProtocolType::RCDCAP_PROTOCOL_TYPE_SCC_SP)
        .value("RCDCAP_PROTOCOL_TYPE_ETHERIP", ProtocolType::RCDCAP_PROTOCOL_TYPE_ETHERIP)
        .value("RCDCAP_PROTOCOL_TYPE_ENCAP", ProtocolType::RCDCAP_PROTOCOL_TYPE_ENCAP)
        .value("RCDCAP_PROTOCOL_TYPE_GMTP", ProtocolType::RCDCAP_PROTOCOL_TYPE_GMTP)
        .value("RCDCAP_PROTOCOL_TYPE_IFMP", ProtocolType::RCDCAP_PROTOCOL_TYPE_IFMP)
        .value("RCDCAP_PROTOCOL_TYPE_PNNI", ProtocolType::RCDCAP_PROTOCOL_TYPE_PNNI)
        .value("RCDCAP_PROTOCOL_TYPE_PIM", ProtocolType::RCDCAP_PROTOCOL_TYPE_PIM)
        .value("RCDCAP_PROTOCOL_TYPE_ARIS", ProtocolType::RCDCAP_PROTOCOL_TYPE_ARIS)
        .value("RCDCAP_PROTOCOL_TYPE_SCPS", ProtocolType::RCDCAP_PROTOCOL_TYPE_SCPS)
        .value("RCDCAP_PROTOCOL_TYPE_QNX", ProtocolType::RCDCAP_PROTOCOL_TYPE_QNX)
        .value("RCDCAP_PROTOCOL_TYPE_AN", ProtocolType::RCDCAP_PROTOCOL_TYPE_AN)
        .value("RCDCAP_PROTOCOL_TYPE_IPComp", ProtocolType::RCDCAP_PROTOCOL_TYPE_IPComp)
        .value("RCDCAP_PROTOCOL_TYPE_SNP", ProtocolType::RCDCAP_PROTOCOL_TYPE_SNP)
        .value("RCDCAP_PROTOCOL_TYPE_Compaq_Peer", ProtocolType::RCDCAP_PROTOCOL_TYPE_Compaq_Peer)
        .value("RCDCAP_PROTOCOL_TYPE_IPX_in_IP", ProtocolType::RCDCAP_PROTOCOL_TYPE_IPX_in_IP)
        .value("RCDCAP_PROTOCOL_TYPE_VRRP", ProtocolType::RCDCAP_PROTOCOL_TYPE_VRRP)
        .value("RCDCAP_PROTOCOL_TYPE_PGM", ProtocolType::RCDCAP_PROTOCOL_TYPE_PGM)
        .value("RCDCAP_PROTOCOL_TYPE_L2TP", ProtocolType::RCDCAP_PROTOCOL_TYPE_L2TP)
        .value("RCDCAP_PROTOCOL_TYPE_DDX", ProtocolType::RCDCAP_PROTOCOL_TYPE_DDX)
        .value("RCDCAP_PROTOCOL_TYPE_IATP", ProtocolType::RCDCAP_PROTOCOL_TYPE_IATP)
        .value("RCDCAP_PROTOCOL_TYPE_STP", ProtocolType::RCDCAP_PROTOCOL_TYPE_STP)
        .value("RCDCAP_PROTOCOL_TYPE_SRP", ProtocolType::RCDCAP_PROTOCOL_TYPE_SRP)
        .value("RCDCAP_PROTOCOL_TYPE_UTI", ProtocolType::RCDCAP_PROTOCOL_TYPE_UTI)
        .value("RCDCAP_PROTOCOL_TYPE_SMP", ProtocolType::RCDCAP_PROTOCOL_TYPE_SMP)
        .value("RCDCAP_PROTOCOL_TYPE_SM", ProtocolType::RCDCAP_PROTOCOL_TYPE_SM)
        .value("RCDCAP_PROTOCOL_TYPE_PTP", ProtocolType::RCDCAP_PROTOCOL_TYPE_PTP)
        .value("RCDCAP_PROTOCOL_TYPE_ISIS_over_IPv4", ProtocolType::RCDCAP_PROTOCOL_TYPE_ISIS_over_IPv4)
        .value("RCDCAP_PROTOCOL_TYPE_FIRE", ProtocolType::RCDCAP_PROTOCOL_TYPE_FIRE)
        .value("RCDCAP_PROTOCOL_TYPE_CRTP", ProtocolType::RCDCAP_PROTOCOL_TYPE_CRTP)
        .value("RCDCAP_PROTOCOL_TYPE_CRUDP", ProtocolType::RCDCAP_PROTOCOL_TYPE_CRUDP)
        .value("RCDCAP_PROTOCOL_TYPE_SSCOPMCE", ProtocolType::RCDCAP_PROTOCOL_TYPE_SSCOPMCE)
        .value("RCDCAP_PROTOCOL_TYPE_IPLT", ProtocolType::RCDCAP_PROTOCOL_TYPE_IPLT)
        .value("RCDCAP_PROTOCOL_TYPE_SPS", ProtocolType::RCDCAP_PROTOCOL_TYPE_SPS)
        .value("RCDCAP_PROTOCOL_TYPE_PIPE", ProtocolType::RCDCAP_PROTOCOL_TYPE_PIPE)
        .value("RCDCAP_PROTOCOL_TYPE_SCTP", ProtocolType::RCDCAP_PROTOCOL_TYPE_SCTP)
        .value("RCDCAP_PROTOCOL_TYPE_FC", ProtocolType::RCDCAP_PROTOCOL_TYPE_FC)
        .value("RCDCAP_PROTOCOL_TYPE_RSVP_E2E_IGNORE", ProtocolType::RCDCAP_PROTOCOL_TYPE_RSVP_E2E_IGNORE)
        .value("RCDCAP_PROTOCOL_TYPE_Mobility_Header", ProtocolType::RCDCAP_PROTOCOL_TYPE_Mobility_Header)
        .value("RCDCAP_PROTOCOL_TYPE_UDPLite", ProtocolType::RCDCAP_PROTOCOL_TYPE_UDPLite)
        .value("RCDCAP_PROTOCOL_TYPE_MPLS_in_IP", ProtocolType::RCDCAP_PROTOCOL_TYPE_MPLS_in_IP)
        .value("RCDCAP_PROTOCOL_TYPE_manet", ProtocolType::RCDCAP_PROTOCOL_TYPE_manet)
        .value("RCDCAP_PROTOCOL_TYPE_HIP", ProtocolType::RCDCAP_PROTOCOL_TYPE_HIP)
        .value("RCDCAP_PROTOCOL_TYPE_Shim6", ProtocolType::RCDCAP_PROTOCOL_TYPE_Shim6)
        .value("RCDCAP_PROTOCOL_TYPE_WESP", ProtocolType::RCDCAP_PROTOCOL_TYPE_WESP)
        .value("RCDCAP_PROTOCOL_TYPE_ROHC", ProtocolType::RCDCAP_PROTOCOL_TYPE_ROHC)
    ;

    // Wraps RCDCap's ARPOpcode enumerator type.
    enum_<ARPOpcode>("ARPOpcode")
        .value("RCDCAP_ARP_RESERVED", ARPOpcode::RCDCAP_ARP_RESERVED)
        .value("RCDCAP_ARP_REQUEST", ARPOpcode::RCDCAP_ARP_REQUEST)
        .value("RCDCAP_ARP_REPLY", ARPOpcode::RCDCAP_ARP_REPLY)
        .value("RCDCAP_ARP_REQUEST_RESERVE", ARPOpcode::RCDCAP_ARP_REQUEST_RESERVE)
        .value("RCDCAP_ARP_REPLY_RESERVE", ARPOpcode::RCDCAP_ARP_REPLY_RESERVE)
        .value("RCDCAP_ARP_DRARP_REQUEST", ARPOpcode::RCDCAP_ARP_DRARP_REQUEST)
        .value("RCDCAP_ARP_DRARP_REPLY", ARPOpcode::RCDCAP_ARP_DRARP_REPLY)
        .value("RCDCAP_ARP_DRARP_ERROR", ARPOpcode::RCDCAP_ARP_DRARP_ERROR)
        .value("RCDCAP_ARP_inARP_REQUEST", ARPOpcode::RCDCAP_ARP_inARP_REQUEST)
        .value("RCDCAP_ARP_inARP_REPLY", ARPOpcode::RCDCAP_ARP_inARP_REPLY)
        .value("RCDCAP_ARP_NAK", ARPOpcode::RCDCAP_ARP_NAK)
        .value("RCDCAP_ARP_MARS_REQUEST", ARPOpcode::RCDCAP_ARP_MARS_REQUEST)
        .value("RCDCAP_ARP_MARS_MULTI", ARPOpcode::RCDCAP_ARP_MARS_MULTI)
        .value("RCDCAP_ARP_MARS_MSERV", ARPOpcode::RCDCAP_ARP_MARS_MSERV)
        .value("RCDCAP_ARP_MARS_JOIN", ARPOpcode::RCDCAP_ARP_MARS_JOIN)
        .value("RCDCAP_ARP_MARS_LEAVE", ARPOpcode::RCDCAP_ARP_MARS_LEAVE)
        .value("RCDCAP_ARP_MARS_NAK", ARPOpcode::RCDCAP_ARP_MARS_NAK)
        .value("RCDCAP_ARP_MARS_UNSERV", ARPOpcode::RCDCAP_ARP_MARS_UNSERV)
        .value("RCDCAP_ARP_MARS_SJOIN", ARPOpcode::RCDCAP_ARP_MARS_SJOIN)
        .value("RCDCAP_ARP_MARS_SLEAVE", ARPOpcode::RCDCAP_ARP_MARS_SLEAVE)
        .value("RCDCAP_ARP_MARS_GROUPLIST_REQUEST", ARPOpcode::RCDCAP_ARP_MARS_GROUPLIST_REQUEST)
        .value("RCDCAP_ARP_MARS_GROUPLIST_REPLY", ARPOpcode::RCDCAP_ARP_MARS_GROUPLIST_REPLY)
        .value("RCDCAP_ARP_MARS_REDIRECT_MAP", ARPOpcode::RCDCAP_ARP_MARS_REDIRECT_MAP)
        .value("RCDCAP_MAPOS_UNARP", ARPOpcode::RCDCAP_MAPOS_UNARP)
        .value("RCDCAP_ARP_OP_EXP1", ARPOpcode::RCDCAP_ARP_OP_EXP1)
        .value("RCDCAP_ARP_OP_EXP2", ARPOpcode::RCDCAP_ARP_OP_EXP2)
    ;

    // Wraps RCDCap's ARPHardwareType enumerator type.
    enum_<ARPHardwareType>("ARPHardwareType")
        .value("RCDCAP_ARP_HW_Reserved1", ARPHardwareType::RCDCAP_ARP_HW_Reserved1)
        .value("RCDCAP_ARP_HW_Ethernet", ARPHardwareType::RCDCAP_ARP_HW_Ethernet)
        .value("RCDCAP_ARP_HW_EXP_Ethernet", ARPHardwareType::RCDCAP_ARP_HW_EXP_Ethernet)
        .value("RCDCAP_ARP_HW_AX25", ARPHardwareType::RCDCAP_ARP_HW_AX25)
        .value("RCDCAP_ARP_HW_PRONET", ARPHardwareType::RCDCAP_ARP_HW_PRONET)
        .value("RCDCAP_ARP_HW_CHAOS", ARPHardwareType::RCDCAP_ARP_HW_CHAOS)
        .value("RCDCAP_ARP_HW_IEEE802", ARPHardwareType::RCDCAP_ARP_HW_IEEE802)
        .value("RCDCAP_ARP_HW_ARCNET", ARPHardwareType::RCDCAP_ARP_HW_ARCNET)
        .value("RCDCAP_ARP_HW_Hyperchannel", ARPHardwareType::RCDCAP_ARP_HW_Hyperchannel)
        .value("RCDCAP_ARP_HW_Lanstar", ARPHardwareType::RCDCAP_ARP_HW_Lanstar)
        .value("RCDCAP_ARP_HW_ASA", ARPHardwareType::RCDCAP_ARP_HW_ASA)
        .value("RCDCAP_ARP_HW_LocalTalk", ARPHardwareType::RCDCAP_ARP_HW_LocalTalk)
        .value("RCDCAP_ARP_HW_LocalNet", ARPHardwareType::RCDCAP_ARP_HW_LocalNet)
        .value("RCDCAP_ARP_HW_UltraLink", ARPHardwareType::RCDCAP_ARP_HW_UltraLink)
        .value("RCDCAP_ARP_HW_SMDS", ARPHardwareType::RCDCAP_ARP_HW_SMDS)
        .value("RCDCAP_ARP_HW_FrameRelay", ARPHardwareType::RCDCAP_ARP_HW_FrameRelay)
        .value("RCDCAP_ARP_HW_ATM1", ARPHardwareType::RCDCAP_ARP_HW_ATM1)
        .value("RCDCAP_ARP_HW_HDLC", ARPHardwareType::RCDCAP_ARP_HW_HDLC)
        .value("RCDCAP_ARP_HW_FibreChannel", ARPHardwareType::RCDCAP_ARP_HW_FibreChannel)
        .value("RCDCAP_ARP_HW_ATM2", ARPHardwareType::RCDCAP_ARP_HW_ATM2)
        .value("RCDCAP_ARP_HW_SerialLine", ARPHardwareType::RCDCAP_ARP_HW_SerialLine)
        .value("RCDCAP_ARP_HW_ATM3", ARPHardwareType::RCDCAP_ARP_HW_ATM3)
        .value("RCDCAP_ARP_HW_MIL", ARPHardwareType::RCDCAP_ARP_HW_MIL)
        .value("RCDCAP_ARP_HW_Metricom", ARPHardwareType::RCDCAP_ARP_HW_Metricom)
        .value("RCDCAP_ARP_HW_IEEE1394", ARPHardwareType::RCDCAP_ARP_HW_IEEE1394)
        .value("RCDCAP_ARP_HW_MAPOS", ARPHardwareType::RCDCAP_ARP_HW_MAPOS)
        .value("RCDCAP_ARP_HW_Twinaxial", ARPHardwareType::RCDCAP_ARP_HW_Twinaxial)
        .value("RCDCAP_ARP_HW_EUI64", ARPHardwareType::RCDCAP_ARP_HW_EUI64)
        .value("RCDCAP_ARP_HW_HIPARP", ARPHardwareType::RCDCAP_ARP_HW_HIPARP)
        .value("RCDCAP_ARP_HW_IPARPoverISO", ARPHardwareType::RCDCAP_ARP_HW_IPARPoverISO)
        .value("RCDCAP_ARP_HW_ARPSec", ARPHardwareType::RCDCAP_ARP_HW_ARPSec)
        .value("RCDCAP_ARP_HW_IPsec", ARPHardwareType::RCDCAP_ARP_HW_IPsec)
        .value("RCDCAP_ARP_HW_Infiniband", ARPHardwareType::RCDCAP_ARP_HW_Infiniband)
        .value("RCDCAP_ARP_HW_CAI", ARPHardwareType::RCDCAP_ARP_HW_CAI)
        .value("RCDCAP_ARP_HW_Wiegand", ARPHardwareType::RCDCAP_ARP_HW_Wiegand)
        .value("RCDCAP_ARP_HW_PureIP", ARPHardwareType::RCDCAP_ARP_HW_PureIP)
        .value("RCDCAP_ARP_HW_EXP1", ARPHardwareType::RCDCAP_ARP_HW_EXP1)
        .value("RCDCAP_ARP_HW_EXP2", ARPHardwareType::RCDCAP_ARP_HW_EXP2)
        .value("RCDCAP_ARP_HW_Reserved2", ARPHardwareType::RCDCAP_ARP_HW_Reserved2)
    ;

    // Wraps the data link type related enumerated values.
    enum_<size_t>("DataLinks")
        .value("DLT_NULL", DLT_NULL)
        .value("DLT_EN10MB", DLT_EN10MB)
        .value("DLT_IEEE802", DLT_IEEE802)
        .value("DLT_ARCNET", DLT_ARCNET)
        .value("DLT_SLIP", DLT_SLIP)
        .value("DLT_PPP", DLT_PPP)
        .value("DLT_FDDI", DLT_FDDI)
        .value("DLT_ATM_RFC1483", DLT_ATM_RFC1483)
        .value("DLT_RAW", DLT_RAW)
        .value("DLT_PPP_SERIAL", DLT_PPP_SERIAL)
        .value("DLT_PPP_ETHER", DLT_PPP_ETHER)
        .value("DLT_C_HDLC", DLT_C_HDLC)
        .value("DLT_IEEE802_11", DLT_IEEE802_11)
        .value("DLT_FRELAY", DLT_FRELAY)
        .value("DLT_LOOP", DLT_LOOP)
        .value("DLT_LINUX_SLL", DLT_LINUX_SLL)
        .value("DLT_LTALK", DLT_LTALK)
        .value("DLT_PFLOG", DLT_PFLOG)
        .value("DLT_PRISM_HEADER", DLT_PRISM_HEADER)
        .value("DLT_IP_OVER_FC", DLT_IP_OVER_FC)
        .value("DLT_SUNATM", DLT_SUNATM)
        .value("DLT_IEEE802_11_RADIO", DLT_IEEE802_11_RADIO)
        .value("DLT_ARCNET_LINUX", DLT_ARCNET_LINUX)
        .value("DLT_LINUX_IRDA", DLT_LINUX_IRDA)
        .value("DLT_LINUX_LAPD", DLT_LINUX_LAPD)
    ;

    // Wraps RCDCap's IPv4 address representation type.
    class_<ip_t>("IPType")
        .def("__getitem__", ip_t_func1, return_value_policy<copy_non_const_reference>())
        .def("__setitem__", ip_t_func1, return_value_policy<copy_non_const_reference>())
        .def("__getitem__", ip_t_func2, return_value_policy<copy_const_reference>())
        .def("__setitem__", ip_t_func2, return_value_policy<copy_const_reference>())
        .def("__str__", &to_string<ip_t>)
    ;

    // Wraps RCDCap's MAC address representation type.
    class_<mac_t>("MACType")
        .def("__getitem__", mac_t_func1, return_value_policy<copy_non_const_reference>())
        .def("__setitem__", mac_t_func1, return_value_policy<copy_non_const_reference>())
        .def("__getitem__", mac_t_func2, return_value_policy<copy_const_reference>())
        .def("__setitem__", mac_t_func2, return_value_policy<copy_const_reference>())
        .def("__str__", &to_string<mac_t>)
    ;

    // Wraps RCDCap's Time class (PCAP-related).
    class_<Time>("PCAPTime", init<uint32, uint32>())
        .add_property("seconds", &Time::getSeconds, &Time::setSeconds)
        .add_property("microseconds", &Time::getMicroseconds, &Time::setMicroseconds)
        .def("swapBytes", &Time::swapBytes)
        .def(self == self)
        .def(self - self)
        .def(self > self)
        .def(self < self)
    ;

    // Wraps RCDCap's PCAPPacketHeader class.
    class_<PCAPPacketHeader, boost::noncopyable>("PCAPPacketHeader")
        .add_property("timestamp", &PCAPPacketHeader::getTimestamp, &PCAPPacketHeader::setTimestamp)
        .add_property("origlen", &PCAPPacketHeader::getOriginalLength, &PCAPPacketHeader::setOriginalLength)
        .add_property("caplen", &PCAPPacketHeader::getCapturedLength, &PCAPPacketHeader::setCapturedLength)
    ;

    // Wraps RCDCap's UDPHeader class.
    class_<UDPHeader, boost::noncopyable>("UDPHeader")
        .add_property("src_port", &UDPHeader::getSourcePort, &UDPHeader::setSourcePort)
        .add_property("dst_port", &UDPHeader::getDestinationPort, &UDPHeader::setDestinationPort)
        .add_property("length", &UDPHeader::getLength, &UDPHeader::setLength)
        .add_property("checksum", &UDPHeader::getChecksum, &UDPHeader::setChecksum)
    ;

    // Wraps RCDCap's IPv4Header class.
    class_<IPv4Header, boost::noncopyable>("IPv4Header")
        .add_property("version", &IPv4Header::getVersion, &IPv4Header::setVersion)
        .add_property("IHL", &IPv4Header::getIHL, &IPv4Header::setIHL)
        .add_property("total_length", &IPv4Header::getTotalLength, &IPv4Header::setTotalLength)
        .add_property("identification", &IPv4Header::getIdentification, &IPv4Header::setIdentification)
        .add_property("fragment", &IPv4Header::getFragment, &IPv4Header::setFragment)
        .add_property("flags", &IPv4Header::getFlags, &IPv4Header::setFlags)
        .add_property("TTL", &IPv4Header::getTTL, &IPv4Header::setTTL)
        .add_property("protocol_type", &IPv4Header::getProtocol, &IPv4Header::setProtocol)
        .add_property("checksum", &IPv4Header::getChecksum, &IPv4Header::setChecksum)
        .add_property("src_ip", &IPv4Header::getSourceIP, &IPv4Header::setSourceIP)
        .add_property("dst_ip", &IPv4Header::getDestinationIP, &IPv4Header::setDestinationIP)
    ;

    // Wraps RCDCap's IPv6Header class.
    class_<IPv6Header, boost::noncopyable>("IPv6Header")
        .add_property("version", &IPv6Header::getVersion, &IPv6Header::setVersion)
        .add_property("traffic_class", &IPv6Header::getTrafficClass, &IPv6Header::setTrafficClass)
        .add_property("flow_label", &IPv6Header::getFlowLabel, &IPv6Header::setFlowLabel)
        .add_property("payload_length", &IPv6Header::getPayloadLength, &IPv6Header::setPayloadLength)
        .add_property("next_header", &IPv6Header::getNextHeader, &IPv6Header::setNextHeader)
        .add_property("hop_limit", &IPv6Header::getHopLimit, &IPv6Header::setHopLimit)
        .add_property("src_ip", &IPv6Header::getSourceIP, &IPv6Header::setSourceIP)
        .add_property("dst_ip", &IPv6Header::getDestinationIP, &IPv6Header::setDestinationIP)
    ;

    // Wraps RCDCap's ARPHeader class.
    class_<ARPHeader, boost::noncopyable>("ARPHeader")
        .add_property("hardware_type", &ARPHeader::getHardwareType, &ARPHeader::setHardwareType)
        .add_property("protocol_type", &ARPHeader::getProtocolType, &ARPHeader::setProtocolType)
        .add_property("hardware_address_length", &ARPHeader::getHardwareAddressLength, &ARPHeader::setHardwareAddressLength)
        .add_property("protocol_address_length", &ARPHeader::getProtocolAddressLength, &ARPHeader::setProtocolAddressLength)
        .add_property("opcode", &ARPHeader::getOpcode, &ARPHeader::setOpcode)
    ;

    // Wraps RCDCap's ARPIPv4ReplyFields class.
    class_<ARPIPv4ReplyFields>("ARPIPv4ReplyFields")
        .add_property("src_hardware_address", &ARPIPv4ReplyFields::getSourceHardwareAddress, &ARPIPv4ReplyFields::setSourceHardwareAddress)
        .add_property("dst_hardware_address", &ARPIPv4ReplyFields::getDestinationHardwareAddress, &ARPIPv4ReplyFields::setDestinationHardwareAddress)
        .add_property("src_protocol_address", &ARPIPv4ReplyFields::getSourceProtocolAddress, &ARPIPv4ReplyFields::setSourceProtocolAddress)
        .add_property("dst_protocol_address", &ARPIPv4ReplyFields::getDestinationProtocolAddress, &ARPIPv4ReplyFields::setDestinationProtocolAddress)
    ;

    // Wraps RCDCap's ARPIPv4RequestFields class.
    class_<ARPIPv4RequestFields>("ARPIPv4RequestFields")
        .add_property("src_hardware_address", &ARPIPv4RequestFields::getSourceHardwareAddress, &ARPIPv4RequestFields::setSourceHardwareAddress)
        .add_property("src_protocol_address", &ARPIPv4RequestFields::getSourceProtocolAddress, &ARPIPv4RequestFields::setSourceProtocolAddress)
    ;

    // Wraps RCDCap's MACHeader class.
    class_<MACHeader, boost::noncopyable>("MACHeader")
        .add_property("dst_mac", &MACHeader::getDMacAddress, &MACHeader::setDMacAddress)
        .add_property("src_mac", &MACHeader::getSMacAddress, &MACHeader::setSMacAddress)
        .add_property("ether_type", &MACHeader::getEtherType, &MACHeader::setEtherType)
    ;

    // Wraps RCDCap's MACHeader802_1Q class.
    class_<MACHeader802_1Q, boost::noncopyable>("MACHeader802_1Q")
        .add_property("vlan_priority", &MACHeader802_1Q::getVLANPriority, &MACHeader802_1Q::setVLANPriority)
        .add_property("vlan_cfi", &MACHeader802_1Q::getVLANCanonical, &MACHeader802_1Q::setVLANCanonical)
        .add_property("vlan_id", &MACHeader802_1Q::getVLANIdentifier, &MACHeader802_1Q::setVLANIdentifier)
        .add_property("dst_mac", &MACHeader802_1Q::getDMacAddress, &MACHeader802_1Q::setDMacAddress)
        .add_property("src_mac", &MACHeader802_1Q::getSMacAddress, &MACHeader802_1Q::setSMacAddress)
        .add_property("ether_type", &MACHeader802_1Q::getEtherType, &MACHeader802_1Q::setEtherType)
    ;

    // Wraps RCDCap's UDP class.
    class_<UDP, boost::noncopyable>("UDP")
        .def("header", &UDP::header, return_value_policy<reference_existing_object>())
//        .def("nextHeader", &UDP::nextHeader, return_value_policy<copy_non_const_reference>())
        .def("size", &UDP::size)
    ;

    // Wraps RCDCap's IPv4 class.
    class_<IPv4, boost::noncopyable>("IPv4")
        .def("header", &IPv4::header, return_value_policy<reference_existing_object>())
//        .def("nextHeader", &IPv4::nextHeader, return_value_policy<copy_non_const_reference>())
        .def("size", &IPv4::size)
        .def("udp", &IPv4::udp, return_value_policy<reference_existing_object>())
    ;

    // Wraps RCDCap's IPv6 class.
    class_<IPv6, boost::noncopyable>("IPv6")
        .def("header", &IPv6::header, return_value_policy<reference_existing_object>())
//        .def("nextHeader", &IPv6::nextHeader, return_value_policy<copy_non_const_reference>())
        .def("size", &IPv6::size)
        .def("udp", &IPv6::udp, return_value_policy<reference_existing_object>())
    ;

    // Wraps RCDCap's ARP class.
    class_<ARP, boost::noncopyable>("ARP")
         .def("header", &ARP::header, return_value_policy<reference_existing_object>())
//        .def("nextHeader", &ARP::nextHeader, return_value_policy<copy_non_const_reference>())
        .def("size", &ARP::size)
        .def("ipv4Reply", &ARP::ipv4Reply, return_value_policy<reference_existing_object>())
        .def("ipv4Request", &ARP::ipv4Request, return_value_policy<reference_existing_object>())
    ;

    // Wraps RCDCap's Ethernet class.
    class_<Ethernet, boost::noncopyable>("Ethernet")
        .def("header", &Ethernet::header, return_value_policy<reference_existing_object>())
//        .def("nextHeader", &Ethernet::nextHeader, return_value_policy<copy_non_const_reference>())
        .def("size", &Ethernet::size)
        .def("ipv4", &Ethernet::ipv4, return_value_policy<reference_existing_object>())
        .def("ipv6", &Ethernet::ipv6, return_value_policy<reference_existing_object>())
        .def("arp", &Ethernet::arp, return_value_policy<reference_existing_object>())
    ;

    // Wraps RCDCap's IEEE802_1Q class.
    class_<IEEE802_1Q, boost::noncopyable>("IEEE802_1Q")
        .def("header", &IEEE802_1Q::header, return_value_policy<reference_existing_object>())
//       .def("nextHeader", &IEEE802_1Q::nextHeader, return_value_policy<copy_non_const_reference>())
        .def("size", &IEEE802_1Q::size)
        .def("ipv4", &IEEE802_1Q::ipv4, return_value_policy<reference_existing_object>())
        .def("ipv6", &IEEE802_1Q::ipv6, return_value_policy<reference_existing_object>())
        .def("arp", &IEEE802_1Q::arp, return_value_policy<reference_existing_object>())
    ;

    // Wraps RCDCap's PacketHierarchy class.
    class_<PacketHierarchy, boost::noncopyable>("PacketHierarchy")
        .def("ethernet", &PacketHierarchy::ethernet, return_value_policy<reference_existing_object>())
        .def("dotQ", &PacketHierarchy::dotQ, return_value_policy<reference_existing_object>())
    ;

    // Wraps RCDCap's GetPacketHierarchy function.
    def("GetPacketHierarchy", &GetPacketHierarchy, return_value_policy<reference_existing_object>());

    // Wraps Boost Program Options' variable_value class.
    class_<popt::variable_value, boost::noncopyable>("variable_value")
        .def("as_char", char_func1, return_value_policy<copy_const_reference>())
        .def("as_int", int_func1, return_value_policy<copy_const_reference>())
        .def("as_short", short_func1, return_value_policy<copy_const_reference>())
        .def("as_long_long", long_long_func1, return_value_policy<copy_const_reference>())
        .def("as_uchar", uchar_func1, return_value_policy<copy_const_reference>())
        .def("as_uint", uint_func1, return_value_policy<copy_const_reference>())
        .def("as_ushort", ushort_func1, return_value_policy<copy_const_reference>())
        .def("as_ulong_long", ulong_long_func1, return_value_policy<copy_const_reference>())
        .def("as_float", float_func1, return_value_policy<copy_const_reference>())
        .def("as_double", double_func1, return_value_policy<copy_const_reference>())
        .def("as_string", string_func1, return_value_policy<copy_const_reference>())
        .def("as_vector_char", vector_char_func1, return_value_policy<copy_const_reference>())
        .def("as_vector_int", vector_int_func1, return_value_policy<copy_const_reference>())
        .def("as_vector_short", vector_short_func1, return_value_policy<copy_const_reference>())
        .def("as_vector_long_long", vector_long_long_func1, return_value_policy<copy_const_reference>())
        .def("as_vector_uchar", vector_uchar_func1, return_value_policy<copy_const_reference>())
        .def("as_vector_uint", vector_uint_func1, return_value_policy<copy_const_reference>())
        .def("as_vector_ushort", vector_ushort_func1, return_value_policy<copy_const_reference>())
        .def("as_vector_ulong_long", vector_ulong_long_func1, return_value_policy<copy_const_reference>())
        .def("as_vector_float", vector_float_func1, return_value_policy<copy_const_reference>())
        .def("as_vector_double", vector_double_func1, return_value_policy<copy_const_reference>())
        .def("as_vector_string", vector_string_func1, return_value_policy<copy_const_reference>())
        .def("as_char", char_func2, return_value_policy<copy_non_const_reference>())
        .def("as_int", int_func2, return_value_policy<copy_non_const_reference>())
        .def("as_short", short_func2, return_value_policy<copy_non_const_reference>())
        .def("as_long_long", long_long_func2, return_value_policy<copy_non_const_reference>())
        .def("as_uchar", uchar_func2, return_value_policy<copy_non_const_reference>())
        .def("as_uint", uint_func2, return_value_policy<copy_non_const_reference>())
        .def("as_ushort", ushort_func2, return_value_policy<copy_non_const_reference>())
        .def("as_ulong_long", ulong_long_func2, return_value_policy<copy_non_const_reference>())
        .def("as_float", float_func2, return_value_policy<copy_non_const_reference>())
        .def("as_double", double_func2, return_value_policy<copy_non_const_reference>())
        .def("as_string", string_func2, return_value_policy<copy_non_const_reference>())
        .def("as_vector_char", vector_char_func2, return_value_policy<copy_non_const_reference>())
        .def("as_vector_int", vector_int_func2, return_value_policy<copy_non_const_reference>())
        .def("as_vector_short", vector_short_func2, return_value_policy<copy_non_const_reference>())
        .def("as_vector_long_long", vector_long_long_func2, return_value_policy<copy_non_const_reference>())
        .def("as_vector_uchar", vector_uchar_func2, return_value_policy<copy_non_const_reference>())
        .def("as_vector_uint", vector_uint_func2, return_value_policy<copy_non_const_reference>())
        .def("as_vector_ushort", vector_ushort_func2, return_value_policy<copy_non_const_reference>())
        .def("as_vector_ulong_long", vector_ulong_long_func2, return_value_policy<copy_non_const_reference>())
        .def("as_vector_float", vector_float_func2, return_value_policy<copy_non_const_reference>())
        .def("as_vector_double", vector_double_func2, return_value_policy<copy_non_const_reference>())
        .def("as_vector_string", vector_string_func2, return_value_policy<copy_non_const_reference>())
        .def("empty", &popt::variable_value::empty)
        .def("defaulted", &popt::variable_value::defaulted)
    ;

    // Wraps Boost Program Options' variables_map class.
    class_<popt::variables_map, boost::noncopyable>("variables_map")
        .def("__getitem__", &popt::variables_map::operator[], return_value_policy<reference_existing_object>())
        .def("__setitem__", &popt::variables_map::operator[], return_value_policy<reference_existing_object>())
        .def("clear", &popt::variables_map::clear)
        .def("notify", &popt::variables_map::notify)
        .def("count", &popt::variables_map::count)
    ;

    // Wraps Boost Program Options' value_semantic class.
    class_<value_semantic_wrap, boost::noncopyable>("value_semantic")
        .def("name", pure_virtual(&popt::value_semantic::name))
        .def("min_tokens", pure_virtual(&popt::value_semantic::min_tokens))
        .def("max_tokens", pure_virtual(&popt::value_semantic::max_tokens))
        .def("is_composing", pure_virtual(&popt::value_semantic::is_composing))
        .def("is_required", pure_virtual(&popt::value_semantic::is_required))
        .def("parse", pure_virtual(&popt::value_semantic::parse))
        .def("apply_default", pure_virtual(&popt::value_semantic::apply_default))
        .def("notify", pure_virtual(&popt::value_semantic::notify))
    ;

    // Wraps Boost ASIO's io_service class.
    class_<boost::asio::io_service, boost::noncopyable>("io_service", no_init)
        .def("run", (std::size_t (boost::asio::io_service::*)(boost::system::error_code&))0, io_service_run_overloads())
        .def("run_one", (std::size_t (boost::asio::io_service::*)(boost::system::error_code&))0, io_service_run_one_overloads())
        .def("poll", (std::size_t (boost::asio::io_service::*)(boost::system::error_code&))0, io_service_poll_overloads())
        .def("poll_one", (std::size_t (boost::asio::io_service::*)(boost::system::error_code&))0, io_service_poll_one_overloads())
        .def("stop", &boost::asio::io_service::stop)
        .def("stopped", &boost::asio::io_service::stopped)
        .def("reset", &boost::asio::io_service::reset)
        .def("post", &io_service_post_wrapper)
        .def("dispatch", &io_service_dispatch_wrapper)
    ;

    // Wraps Boost Program Options' options_description_easy_init class.
    class_<popt::options_description_easy_init>("options_description_easy_init", no_init)
        .def("__call__", opp1, return_value_policy<copy_non_const_reference>())
        .def("__call__", opp2, return_value_policy<copy_non_const_reference>())
        .def("__call__", opp3, return_value_policy<copy_non_const_reference>())
    ;

    // Wraps Boost Program Options' options_description class.
    class_<popt::options_description>("options_description", no_init)
        .def("add_options", &popt::options_description::add_options)
    //    .def("find", &popt::options_description::find)
    //    .def("find_nothrow", &popt::options_description::find_nothrow)
    //    .def("options", &popt::options_description::options)
    //    .def("print", &popt::options_description::print)
    ;

    // Wraps RCDCap's Plugin class.
    class_<PluginWrap, boost::noncopyable>("Plugin")
        .def("init", pure_virtual(&Plugin::init))
        .def("hasSource", &Plugin::hasSource, &PluginWrap::default_hasSource)
        .def("hasProcessor", &Plugin::hasProcessor, &PluginWrap::default_hasProcessor)
        .def("hasSink", &Plugin::hasSink, &PluginWrap::default_hasSink)
    ;

    // Wraps RCDCap's Source class.
    class_<SourceWrap, boost::noncopyable>("Source")
        .def("attach", &Source::attach, &SourceWrap::default_attach)
        .def("getMainSink", &Source::getMainSink)
    ;

    // Wraps RCDCap's CommonBuffer class.
    class_<CommonBuffer, boost::noncopyable>("Buffer", init<size_t, bool>())
        .def("push", &CommonBuffer::push, return_value_policy<reference_existing_object>())
        .def("pop", &CommonBuffer::pop)
        .def("popSequence", &CommonBuffer::popSequence)
        .def("begin", &CommonBuffer::begin, return_value_policy<reference_existing_object>())
        .def("offset", &CommonBuffer::offset)
        .def("next", &CommonBuffer::next, return_value_policy<reference_existing_object>())
        .def("capacity", &CommonBuffer::capacity)
        .def("size", &CommonBuffer::size)
    ;

    // Wraps RCDCap's DataSource class.
    class_<DataSourceWrap, boost::noncopyable>("DataSource", init<boost::asio::io_service&, DataSource::termination_handler, size_t, bool, size_t, size_t>())
        .def("getBuffer", pure_virtual(&DataSource::getBuffer), return_value_policy<reference_existing_object>())
        .def("startAsync", pure_virtual(&DataSource::startAsync))
        .def("start", pure_virtual(&DataSource::start))
        .def("stop", pure_virtual(&DataSource::stop))
        .def("setFilterExpression", pure_virtual(&DataSource::setFilterExpression))
        .def("getName", pure_virtual(&DataSource::getName))
        .def("isFile", pure_virtual(&DataSource::isFile))
        .def("getLinkType", pure_virtual(&DataSource::getLinkType))
        .def("getSnapshot", pure_virtual(&DataSource::getSnapshot))
        .def("getLinkTypeName", pure_virtual(&DataSource::getLinkTypeName))
        .def("getPacketsCaptured", pure_virtual(&DataSource::getPacketsCaptured))
        .def("getPacketsCapturedKernel", pure_virtual(&DataSource::getPacketsCapturedKernel))
        .def("getPacketsDroppedKernel", pure_virtual(&DataSource::getPacketsDroppedKernel))
        .def("getPacketsDroppedDriver", pure_virtual(&DataSource::getPacketsDroppedDriver))
        .def("getPacketsDroppedBuffer", pure_virtual(&DataSource::getPacketsDroppedBuffer))
    ;

    // Wraps RCDCap's Sink class.
    class_<SinkWrap, boost::noncopyable>("Sink")
        .def("notify", pure_virtual(&Sink::notify))
    ;

    // Wraps RCDCap's DataSink class.
    class_<DataSinkWrap, bases<Sink>, boost::noncopyable>("DataSink", init<boost::asio::io_service&, DataSource&>())
        .add_property("getProcessed", &DataSink::getProcessed)
    ;

    // Wraps RCDCap's Processor class.
    class_<ProcessorWrap, bases<Source, Sink>, boost::noncopyable>("Processor")
    //    .def("notify", pure_virtual(&Sink::notify))
        .def("attach", &Source::attach, &ProcessorWrap::default_attach)
    ;

    // Wraps the PacketInfo structure which provides information about the contents of a packet.
    class_<PacketInfo, boost::noncopyable>("PacketInfo", no_init)
        .def("getPCAPHeader", &PacketInfo::getPCAPHeader, return_value_policy<reference_existing_object>())
        .def("getAllocatedSize", &PacketInfo::getAllocatedSize)
        .def("setProcessed", &ProcessedFlag::setProcessed)
        .def("tryProcessed", &ProcessedFlag::tryProcessed)
    ;

    // Wraps all implementations of std::vector used by this plug-in.
    class_<VectorChar>("VectorChar")
        .def(vector_indexing_suite<VectorChar>())
    ;
    class_<VectorInt>("VectorInt")
        .def(vector_indexing_suite<VectorInt>())
    ;
    class_<VectorShort>("VectorShort")
        .def(vector_indexing_suite<VectorShort>())
    ;
    class_<VectorLongLong>("VectorLongLong")
        .def(vector_indexing_suite<VectorLongLong>())
    ;
    class_<VectorUnsignedChar>("VectorUnsignedChar")
        .def(vector_indexing_suite<VectorUnsignedChar>())
    ;
    class_<VectorUnsignedInt>("VectorUnsignedInt")
        .def(vector_indexing_suite<VectorUnsignedInt>())
    ;
    class_<VectorUnsignedShort>("VectorUnsignedShort")
        .def(vector_indexing_suite<VectorUnsignedShort>())
    ;
    class_<VectorUnsignedLongLong>("VectorUnsignedLongLong")
        .def(vector_indexing_suite<VectorUnsignedLongLong>())
    ;
    class_<VectorFloat> ("VectorFloat")
        .def(vector_indexing_suite<VectorFloat>())
    ;
    class_<VectorDouble> ("VectorDouble")
        .def(vector_indexing_suite<VectorDouble>())
    ;
    class_<VectorString> ("VectorString")
        .def(vector_indexing_suite<VectorString>())
    ;

    // Initializes all implementations of boost::program_options::typed_value
    // supported by this plug-in.
    WRAP_TYPED_VALUE(char, char_value)
    WRAP_TYPED_VALUE(int, int_value)
    WRAP_TYPED_VALUE(short, short_value)
    WRAP_TYPED_VALUE(long long, long_long_value)
    WRAP_TYPED_VALUE(unsigned char, uchar_value)
    WRAP_TYPED_VALUE(unsigned int, uint_value)
    WRAP_TYPED_VALUE(unsigned short, ushort_value)
    WRAP_TYPED_VALUE(unsigned long long, ulong_long_value)
    WRAP_TYPED_VALUE(float, float_value)
    WRAP_TYPED_VALUE(double, double_value)
    WRAP_TYPED_VALUE(std::string, string_value)
    WRAP_TYPED_VALUE(VectorChar, vector_char_value)
    WRAP_TYPED_VALUE(VectorInt, vector_int_value)
    WRAP_TYPED_VALUE(VectorShort, vector_short_value)
    WRAP_TYPED_VALUE(VectorLongLong, vector_long_long_value)
    WRAP_TYPED_VALUE(VectorUnsignedChar, vector_uchar_value)
    WRAP_TYPED_VALUE(VectorUnsignedInt, vector_uint_value)
    WRAP_TYPED_VALUE(VectorUnsignedShort, vector_ushort_value)
    WRAP_TYPED_VALUE(VectorUnsignedLongLong, vector_ulong_long_value)
    WRAP_TYPED_VALUE(VectorFloat, vector_float_value)
    WRAP_TYPED_VALUE(VectorDouble, vector_double_value)
    WRAP_TYPED_VALUE(VectorString, vector_string_value)

    // Registers all smart pointers associated with RCDCap types.
    register_ptr_to_python<PluginPtr>();
    register_ptr_to_python<SinkPtr>();
    register_ptr_to_python<ProcessorPtr>();
    register_ptr_to_python<DataSourcePtr>();
    register_ptr_to_python<DataSinkPtr>();
}

#endif /* _PYTHON_WRAPPING_HH_ */