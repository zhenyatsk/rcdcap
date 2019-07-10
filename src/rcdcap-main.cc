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

#include "rcdcap/sink.hh"
#include "rcdcap/rcdcap.hh"
#include "rcdcap/source.hh"
#include "rcdcap/processor.hh"
#include "rcdcap/exception.hh"
#include "rcdcap/memory.hh"
#include "rcdcap/byte-swap.hh"
#include "rcdcap/hp-erm-processor.hh"
#include "rcdcap/erspan-processor.hh"

#ifdef HAS_PF_RING
#   include "rcdcap/pfring-source.hh"
#endif

#include <string>
#include <cstdlib>
#include <memory>
#include <thread>
#include <algorithm>
#include <functional>
#include <iostream>
#include <sstream>

#ifdef _WIN32
#include <codecvt>
#else
#include <unistd.h>
#endif

#include <boost/program_options/options_description.hpp>
#include <boost/program_options/parsers.hpp>
#include <boost/filesystem.hpp>
#include <boost/make_shared.hpp>
#include <boost/asio.hpp>

namespace asio = boost::asio;
namespace bsys = boost::system;

namespace RCDCap
{
Bytes::Bytes(const std::string& _size)
{
    std::stringstream ss(_size);
    ss >> *this;
}

Bytes& Bytes::operator=(size_t _size)
{
    m_Size = _size;
    return *this;
}

std::ostream& operator<<(std::ostream& os, const Bytes& b)
{
    double res;
    if((res = b / (1024LL*1024LL*1024LL*1024LL)) > 1.0)
        os << res << "TB";
    else if((res = b / (1024LL*1024LL*1024LL)) > 1.0)
        os << res << "GB";
    else if((res = b / (1024LL*1024LL)) > 1.0)
        os << res << "MB";
    else if((res = b / 1024LL) > 1.0)
        os << res << "KB";
    else
        os << b << "B";
    return os;
}

std::istream& operator>>(std::istream& is, Bytes& b)
{
    double          res;
    std::string     suffix;
    is >> res >> suffix;
    if(suffix == "TB")
        b = res*(1024LL*1024LL*1024LL*1024LL);
    else if(suffix == "GB")
        b = res*(1024LL*1024LL*1024LL);
    else if(suffix == "MB")
        b = res*(1024LL*1024LL);
    else if(suffix == "KB")
        b = res*(1024LL);
    else if(suffix == "B")
        b = res;
    else
        is.setstate(std::ios::failbit);
    return is;
}

RCDCapApplication::RCDCapApplication()
    :   m_Description("Usage: rcdcap [OPTIONS]... [EXPRESSION]...\n\n"
                      "Captures packets from the specified network interface.\n\n"
                      "Available options"),
        m_Signals(RCDCap::make_unique<boost::asio::signal_set>(m_IOService, SIGINT, SIGTERM))
{
    m_Description.add_options()
        ("disable-memory-locking", "Disable buffer memory locking")
        ("load-plugins", popt::value<std::vector<std::string>>(), "Load the specified plug-in files")
        ("disable-vlan-tag", "Disable the insertion of the 802.1Q VLAN Tag inside the decapsulated packet by some processors")
        ("hp-erm-server,H", popt::value<size_t>()->implicit_value(7932), "Run the application as a HP ERM destination host")
        ("thread-pinning", popt::value<std::string>()->default_value("disable"), "Set the threads to run on the 'same' cpu, 'different' or 'disable' it and let the scheduler decide") 
        ("capture-mode", popt::value<std::string>()->default_value("auto"), "Specify whether the capturing process should run separately or compete for resources with the rest of the application")
        ("worker-threads", popt::value<size_t>(), "Force the application to spawn a given amount of worker threads")
        ("dummy", "Ignore any other output options and just count packets")
        ("tap-device,t", popt::value<std::string>(),
                         "Output the raw packets to a TAP device")
        ("tap-dev-addr", popt::value<std::string>(),
                         "Set the address of the TAP device to the specified (this option is valid only if --tap-device is specified)")
        ("tap-persist", "Set the TAP device to persistent mode")
        ("read-binary,r", popt::value<std::string>(),
                         "Read the raw packets from the specified file or stdin, if ``-'' is passed")
        ("write-text,o", popt::value<std::string>(),
                         "Write some information about the captured packets in text format to the specified"
                         "file or stdout, if ``-'' is passed (this option is used by default when no output"
                         "method is specified)")
        ("write-binary,w", popt::value<std::string>(),
                           "Write the raw packets to the specified file or stdout, if ``-'' is passed")
        ("discard-packets,D", "Discard all packets after processing")
        ("inject,I", popt::value<std::string>(),
                     "Write the raw packets to the specified Ethernet device")
        ("interface,i", popt::value<std::string>(), "Set the network interface to listen on")
        ("buffer-size,b", popt::value<Bytes>()->default_value(Bytes("100MB")), "Set the internal buffer to the specified size in the specified unit")
        ("snaplen,s", popt::value<size_t>()->default_value(1518), "Set the snapshot length in bytes")
#ifdef HAS_PF_RING
        ("pfring", "Use libpfring as a library for capturing data (this option is valid only when a conventional network device is specified)")
#endif
        ("hp-erm", popt::value<uint16>(), "Enable the HP ERM decapsulating processor")
        ("erspan", "Enable the ERSPAN decapsulating processor")
        ("ignore-incomplete,y", "Ignore incomplete packets")
        ("force-incomplete,f", "Ignore incomplete packets")
        ("daemonize,d", "Launch RCDCap as separate ")
        ("timeout,T", popt::value<size_t>()->default_value(1), "Specifies how much the application should wait in milliseconds before breaking"
                                                                "the capture process to send the packets to the next element in the pipeline")
        ("burst-size,B", popt::value<size_t>()->default_value(10),  "How many packets should be processed at a time")
        ("expression", "Set the PCAP filter expression")
        ("help", "Display this help and exit")
        ("version", "Output version information and exit")
    ;
}

std::string GetExecutablePath()
{
    char buffer[1024];
#ifdef _WIN32
    if(GetModuleFileName(nullptr, buffer, sizeof(buffer)) == 0)
        return std::string();
#elif defined(LINUX)
    size_t len = readlink("/proc/self/exe", buffer, 1023);
    if(len < 0)
        return std::string();
    buffer[len] = 0;
#else
#	error "Unsupported platform"
#endif
    return buffer;
}

void RCDCapApplication::initPlugins(popt::variables_map& vm)
{
    using namespace boost::filesystem;
    path exe_path(GetExecutablePath());
    path p = exe_path.parent_path().parent_path()/"share"/"rcdcap"/"plugins";
    if(exists(p) && is_directory(p))
        for(auto i = directory_iterator(p); i != directory_iterator(); ++i)
        {
            if(is_directory(i->path()) || i->path().extension() != ".so")
                continue;
        #ifdef _WIN32
            std::wstring path(i->path().native());
            using convert_type = std::codecvt_utf8<wchar_t>;
            std::wstring_convert<convert_type, wchar_t> converter;
            m_PluginLibs.push_back(boost::make_shared<Library>(converter.to_bytes(path)));
        #else
            m_PluginLibs.push_back(boost::make_shared<Library>(i->path().native()));
        #endif
            m_Plugins.push_back(LoadRCDCapPlugin(*m_PluginLibs.back()));
        }

    if(vm.count("load-plugins"))
    {
        auto plugins = vm["load-plugins"].as<std::vector<std::string>>();
        for(auto i = plugins.begin(); i != plugins.end(); ++i)
        {
            m_PluginLibs.push_back(boost::make_shared<Library>(*i));
            m_Plugins.push_back(LoadRCDCapPlugin(*m_PluginLibs.back()));
        }
    }
    
    for(auto i = m_Plugins.begin(); i != m_Plugins.end(); ++i)
        (*i)->init(m_IOService, m_Description);
}

RCDCapApplication::~RCDCapApplication()
{
}

void RCDCapApplication::daemonize()
{
#ifndef _WIN32
    // Inform the io_service that we are about to become a daemon.
    m_IOService.notify_fork(boost::asio::io_service::fork_prepare);

    // Fork the process and have the parent exit.
    if (pid_t pid = fork())
    {
        if (pid > 0)
            // We're in the parent process and need to exit.
            exit(0);
        else
            THROW_EXCEPTION("First fork failed");
     }

    // Make the process a new session leader. This detaches it from the
    // terminal.
    setsid();

    // We don't want to hold a mounted partition if the process was started
    // from it.
    chdir("/");

    // We don't want to restrict the permissions on files created by the
    // daemon, so the mask is cleared.
    umask(0);

    // A second fork ensures the process cannot acquire a controlling terminal.
    if (pid_t pid = fork())
    {
        if (pid > 0)
            exit(0);
        else
            THROW_EXCEPTION("Second fork failed");
    }

    // Close the standard streams. This decouples the daemon from the terminal
    // that started it.
    close(0);
    close(1);
    close(2);

    // We don't want the daemon to have any standard input.
    if(open("/dev/null", O_RDONLY) < 0)
        THROW_EXCEPTION("Unable to open /dev/null");

    // Send standard output to a log file.
    const char* output = "/var/log/rcdcap";
    const int flags = O_WRONLY | O_CREAT | O_APPEND;
    const mode_t mode = S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH;
    if (open(output, flags, mode) < 0)
        THROW_EXCEPTION("Unable to open output file");

    // Also send standard error to the same log file.
    if (dup(1) < 0)
        THROW_EXCEPTION("Unable to dup output descriptor");

    // Inform the io_service that we have finished becoming a daemon.
    m_IOService.notify_fork(boost::asio::io_service::fork_child);
#endif
}

void RCDCapApplication::run(int argc, char* argv[])
{
    ThreadGroup                             threads;
    try
    {
    {
    popt::variables_map                     vm;
    popt::store(popt::command_line_parser(argc, argv).allow_unregistered().options(m_Description).run(), vm);
    popt::notify(vm);
    initPlugins(vm);
    }

    popt::variables_map                     vm;
    auto parsed_opts = popt::command_line_parser(argc, argv).options(m_Description).run(); 
    auto exprs = popt::collect_unrecognized(parsed_opts.options, popt::include_positional);
    for(auto& expr : exprs)
        m_Expression += expr + ' ';
    popt::store(parsed_opts, vm);
    popt::notify(vm);
    
    if(vm.count("help"))
    {
        this->showHelp();
        return;
    }
    
    if(vm.count("version"))
    {
        this->showVersion();
        return;
    }
    
    bool output_info = (!vm.count("write-binary") || vm["write-binary"].as<std::string>() != "-");
    if(vm.count("hp-erm-server"))
    {
        bool plugin_src = false,
             memory_locking = !vm.count("disable-memory-locking");
        for(auto i = m_Plugins.begin(); i != m_Plugins.end(); ++i)
            plugin_src |= (bool)(*i)->hasSource(vm);
        if(vm.count("interface") || vm.count("read-binary") || plugin_src)
            THROW_EXCEPTION("capturing from more than one device or file is currently unsupported");
        m_Source = boost::make_shared<HPERMUDPDataSource>(m_IOService, std::bind(&RCDCapApplication::terminate, this),
                                                        vm["buffer-size"].as<Bytes>(), memory_locking,
                                                        vm["hp-erm-server"].as<size_t>(),
                                                        vm["burst-size"].as<size_t>(),
                                                        vm["timeout"].as<size_t>());
        auto hperm_proc = boost::make_shared<HPERMProcessor>(m_IOService, m_Source->getBuffer(), vm["hp-erm-server"].as<size_t>(), !vm.count("disable-vlan-tag"));
        if(output_info)
            std::cout << "listening on " << m_Source->getName() << std::endl;
        if(!vm.count("dummy"))
        {
            m_Source->attach(hperm_proc);
            if(vm.count("erspan"))
                THROW_EXCEPTION("CISCO ERSPAN decapsulation is not supported in this mode");
            SourcePtr _last = hperm_proc;
            for(auto i = m_Plugins.begin(); i != m_Plugins.end(); ++i)
            {
                auto _tmp = (*i)->hasProcessor(*m_Source, vm);
                if(_tmp)
                {
                    _last->attach(_tmp);
                    _last = _tmp;
                }
            }
            initSink(vm, _last);
        }
    }
    else
    {
        initSource(vm);
        
        if(!vm.count("dummy"))
        {
            SourcePtr _last;
            initPipeline(vm, _last);
            initSink(vm, _last);
        }
    }
    
    m_Signals->async_wait(std::bind(&RCDCap::RCDCapApplication::terminate, this));
    
    if(vm.count("daemonize"))
        this->daemonize();    
    
    spawnWorkerThreads(vm, threads);
    
    auto capmode = vm["capture-mode"].as<std::string>();
    auto start = std::chrono::high_resolution_clock::now();
    if(threads.size() == 0)
    {
        if(capmode == "sync")
            THROW_EXCEPTION("synchronous capturing mode is not available on a single thread");
        else if(capmode == "async" || capmode == "auto")
        {
            m_Source->startAsync();
            m_IOService.run();
        }
        else
            THROW_EXCEPTION("unknown capturing mode");
    }
    else
    {
        if(capmode == "async")
        {
            m_Source->startAsync();
            m_IOService.run();
        }
        else if(capmode == "sync" || capmode == "auto")
            m_Source->start();
        else
            THROW_EXCEPTION("unknown capturing mode");
    }
    for(auto i = threads.begin(); i != threads.end(); ++i)
#ifndef RCDCAP_STATIC
            i->join();
#else
            (*i)->join();
#endif
    if(output_info)
    {
        auto dur = std::chrono::high_resolution_clock::now() - start;
        size_t msec = std::chrono::duration_cast<std::chrono::milliseconds>(dur).count();
        std::cout << "\n\n" << std::dec
                  << m_Source->getPacketsCaptured() << " packets were captured by the application\n";
        if(!vm.count("read-binary"))
            std::cout << m_Source->getPacketsCapturedKernel() << " packets were captured by the kernel\n"
                      << m_Source->getPacketsDroppedKernel() << " packets were dropped by the kernel\n"
                      << m_Source->getPacketsDroppedDriver() << " packets were dropped by the driver\n";
        std::cout << m_Source->getPacketsDroppedBuffer() << " packets were dropped due to buffer overflow\n" 
                  << msec << " ms execution time" << std::endl;
        if(m_Sink)
            std::cout << static_cast<DataSink&>(*m_Sink).getProcessed() << " packets were processed" << std::endl;
    }
    }
    catch(...)
    {
        m_IOService.stop();
        for(auto i = threads.begin(); i != threads.end(); ++i)
#ifndef RCDCAP_STATIC
            i->join();
#else
            (*i)->join();
#endif
        throw;
    }
}

void RCDCapApplication::showHelp()
{
    std::cout << m_Description << std::endl;
}

void RCDCapApplication::showVersion()
{
    std::cout << "RCDCap " TO_STRING(RCDCap_VERSION_MAJOR) "." TO_STRING(RCDCap_VERSION_MINOR) "\n"
            "Copyright (C) 2012  Zdravko Velinov\n"
            "License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>.\n"
            "This is free software: you are free to change and redistribute it.\n"
            "There is NO WARRANTY, to the extent permitted by law."
            << std::endl;
}

uint32_t GetNumberOfProcessors()
{
    uint32_t concurrency = std::thread::hardware_concurrency();
    if(concurrency)
        return concurrency;
#ifdef _WIN32
    return GetMaximumProcessorCount(0xFFFF);
#else
    return sysconf(_SC_NPROCESSORS_ONLN);
#endif
}

void RCDCapApplication::spawnWorkerThreads(popt::variables_map& vm, ThreadGroup& threads)
{
    auto tpin = vm["thread-pinning"].as<std::string>();
    size_t  mode = 0,
            offset_cpu = 0,
            pin_cpu = 0,
            num_cpu = GetNumberOfProcessors(),
            worker_count;
    assert(num_cpu);
    bool output_info = (!vm.count("write-binary") || vm["write-binary"].as<std::string>() != "-");
#undef max
    if(vm.count("worker-threads"))
    {
        worker_count = vm["worker-threads"].as<size_t>();
        if(!worker_count)
            THROW_EXCEPTION("you must specify at least one worker thread");
    }
    else
        worker_count = std::max(2u, std::thread::hardware_concurrency());
    if(output_info)
        std::cout << "worker threads: " << worker_count << " on " << num_cpu << " CPUs" << std::endl;
    
    if(tpin == "different")
        mode = 2;
    else if(tpin == "irq-different")
    {
        mode = 3;
        if(num_cpu == 1)
            THROW_EXCEPTION("this option is not support on single CPU");
        if(!vm.count("interface"))
            THROW_EXCEPTION("you must specify a regular network interface");
        pin_cpu = offset_cpu = 1;
        m_SMPAffinityRAII = RCDCap::make_unique<RCDCapApplication::SMPAffinityRAII>(vm["interface"].as<std::string>(), 1);
    }
    else if(tpin != "disable")
    {
        mode = 1;
        std::stringstream ss(tpin);
        ss >> pin_cpu;
        if(!ss)
            THROW_EXCEPTION("unknown type of thread pinning");
        if(pin_cpu >= num_cpu)
            THROW_EXCEPTION("there is no such CPU available on this system");
    }
    
#ifdef _WIN32

#else
    static std::unique_ptr<cpu_set_t[]> cpu_data(new cpu_set_t[num_cpu]);
    for(auto i = 0u; i < num_cpu; ++i)
    {
        CPU_ZERO(&cpu_data[i]);
        CPU_SET(i, &cpu_data[i]);
    }
    if(mode)
    {
        pthread_t _self = pthread_self();
        if(pthread_setaffinity_np(_self, sizeof(cpu_set_t), &cpu_data[pin_cpu]))
            THROW_EXCEPTION("failed to schedule the thread on the specified CPU");
    }
#endif
    for(size_t i = 0u, cpu = 1u % (num_cpu - offset_cpu); i < worker_count - 1;
        ++i, cpu = (cpu + 1u) % (num_cpu - offset_cpu))
    {
#ifndef RCDCAP_STATIC
        threads.push_back(std::thread(boost::bind(&asio::io_service::run, &m_IOService)));
        auto hnd = threads[i].native_handle();
#else
        // Broken move semantic workaround
        threads.push_back(RCDCap::make_unique<std::thread>(boost::bind(&asio::io_service::run, &m_IOService)));
        auto hnd = threads[i]->native_handle();
#endif

#ifdef _WIN32
#else
        if(mode == 1)
        {
            if(pthread_setaffinity_np(hnd, sizeof(cpu_set_t), &cpu_data[pin_cpu]))
                THROW_EXCEPTION("failed to schedule the thread on the specified CPU");
        }
        else if(mode == 2 || mode == 3)
        {
            if(pthread_setaffinity_np(hnd, sizeof(cpu_set_t), &cpu_data[cpu + offset_cpu]))
                THROW_EXCEPTION("failed to schedule the thread on the specified CPU");
        }
#endif
    }
}

void RCDCapApplication::initSource(popt::variables_map& vm)
{
    std::string operation;
    auto ic = vm.count("interface"),
         rc = vm.count("read-binary");

    auto inputc = ic + rc;
    bool memory_locking = !vm.count("disable-memory-locking");
#ifdef HAS_PF_RING
    auto pc = vm.count("pfring");
#endif
    for(auto i = m_Plugins.begin(); i != m_Plugins.end(); ++i)
    {
        if(inputc > 1)
            THROW_EXCEPTION("capturing from more than one device or file is currently unsupported");
        m_Source = (*i)->hasSource(vm);
        if(m_Source)
            ++inputc;
    }
    
    if(inputc > 1)
        THROW_EXCEPTION("capturing from more than one device or file is currently unsupported");
    
    if(ic == 1)
    {
        operation = "listening on ";
#ifdef HAS_PF_RING
        if(pc)
        {
            m_Source = boost::make_shared<PF_RINGDataSource>(m_IOService,
                                                             std::bind(&RCDCapApplication::terminate, this),
                                                             vm["buffer-size"].as<Bytes>(), memory_locking,
                                                             vm["burst-size"].as<size_t>(), vm["timeout"].as<size_t>());
            reinterpret_cast<PF_RINGDataSource&>(*m_Source).openDevice(vm["interface"].as<std::string>(), vm["snaplen"].as<size_t>());
        }
        else
        {
#endif
            m_Source = boost::make_shared<PCAPDataSource>(m_IOService,
                                                          std::bind(&RCDCapApplication::terminate, this),
                                                          vm["buffer-size"].as<Bytes>(), memory_locking,
                                                          vm["burst-size"].as<size_t>(), vm["timeout"].as<size_t>());
            reinterpret_cast<PCAPDataSource&>(*m_Source).openDevice(vm["interface"].as<std::string>(), vm["snaplen"].as<size_t>());
#ifdef HAS_PF_RING
        }
#endif
    }
    else if(rc == 1)
    {
        operation = "reading from ";
#ifdef HAS_PF_RING
        if(pc)
            THROW_EXCEPTION("PF_RING does not provide support for reading from file");
#endif
        m_Source = boost::make_shared<PCAPDataSource>(m_IOService,
                                                      std::bind(&RCDCapApplication::terminate, this),
                                                      vm["buffer-size"].as<Bytes>(), memory_locking,
                                                      vm["burst-size"].as<size_t>(), vm["timeout"].as<size_t>());
        reinterpret_cast<PCAPDataSource&>(*m_Source).openFile(vm["read-binary"].as<std::string>());
    }
    else
    {
        operation = "listening on ";
#ifdef HAS_PF_RING
        if(pc)
        {
            m_Source = boost::make_shared<PF_RINGDataSource>(m_IOService,
                                                             std::bind(&RCDCapApplication::terminate, this),
                                                             vm["buffer-size"].as<Bytes>(), memory_locking,
                                                             vm["burst-size"].as<size_t>(), vm["timeout"].as<size_t>());
            reinterpret_cast<PF_RINGDataSource&>(*m_Source).openDefaultDevice(vm["snaplen"].as<size_t>());
        }
        else
        {
#endif
            m_Source = boost::make_shared<PCAPDataSource>(m_IOService,
                                                          std::bind(&RCDCapApplication::terminate, this),
                                                          vm["buffer-size"].as<Bytes>(), memory_locking,
                                                          vm["burst-size"].as<size_t>(), vm["timeout"].as<size_t>());
            reinterpret_cast<PCAPDataSource&>(*m_Source).openDefaultDevice(vm["snaplen"].as<size_t>());
#ifdef HAS_PF_RING
        }
#endif
    }
    
    if(!m_Expression.empty())
        m_Source->setFilterExpression(m_Expression);
    if(!vm.count("write-binary") || vm["write-binary"].as<std::string>() != "-")
        std::cout << operation << m_Source->getName() << " (" << m_Source->getLinkTypeName() << "), " << "capture size " << m_Source->getSnapshot() << " bytes" << std::endl;
}

void RCDCapApplication::initSink(popt::variables_map& vm, const SourcePtr& _last)
{
    uint32 ip = 0, flags = 0;
    auto tc = vm.count("write-text"),
         bc = vm.count("write-binary"),
         tapc = vm.count("tap-device"),
         injc = vm.count("inject"),
         tnc = vm.count("tap-dev-addr"),
         tpc = vm.count("tap-persist"),
         ignore = vm.count("ignore-incomplete"),
         force = vm.count("force-incomplete"),
         dc = vm.count("discard-packets");
    auto outputc = tc + bc + tapc + injc + dc;
    if(tnc == 1 && tapc == 1)
    {
        std::string ipaddr = vm["tap-dev-addr"].as<std::string>();
        ip = ByteSwap(boost::asio::ip::address_v4::from_string(ipaddr).to_ulong());
    }

    for(auto i = m_Plugins.begin(); i != m_Plugins.end(); ++i)
    {
        if(outputc > 1)
            THROW_EXCEPTION("writing to more than one sink is currently unsupported");
        m_Sink = (*i)->hasSink(*m_Source, vm);
        if(m_Sink)
            ++outputc;
    }
    
#ifndef _WIN32
    if(tpc == 1)
    {
        if(tapc == 1)
            flags |= RCDCAP_SINK_OPTION_PERSIST;
        else
            THROW_EXCEPTION("you must specify that you want to initialize a TAP device");
    }
    
#endif
    if (force)
        flags |= RCDCAP_SINK_OPTION_FORCE;

    if (ignore)
        flags |= RCDCAP_SINK_OPTION_IGNORE;

    if(outputc > 1)
        THROW_EXCEPTION("writing to more than one sink is currently unsupported");
    
    if(tc)
    {
        std::string filename = vm["write-text"].as<std::string>();
        if(filename == "-")
            m_Sink = boost::make_shared<RCDCap::ConsoleSink>(m_IOService, *m_Source);
        else
            m_Sink = boost::make_shared<RCDCap::TextFileSink>(m_IOService, *m_Source, filename);
    }
    else if(bc)
    {
        std::string filename = vm["write-binary"].as<std::string>();
        if(filename == "-")
            m_Sink = boost::make_shared<RCDCap::BinaryConsoleSink>(m_IOService, *m_Source);
        else
            m_Sink = boost::make_shared<RCDCap::BinaryFileSink>(m_IOService, *m_Source, filename);
    }
#ifndef _WIN32
    else if(tapc)
    {
        std::string devname = vm["tap-device"].as<std::string>();
        m_Sink = boost::make_shared<RCDCap::TAPDeviceSink>(m_IOService, *m_Source, ip, devname, flags);
    }
    else if(injc)
    {
        std::string devname = vm["inject"].as<std::string>();
        m_Sink = boost::make_shared<RCDCap::InjectionSink>(m_IOService, *m_Source, devname);
    }
#endif
    else if(dc)
    {
        m_Sink = boost::make_shared<RCDCap::DiscardSink>(m_IOService, *m_Source);
    }
    else if(outputc == 0)
        m_Sink = boost::make_shared<RCDCap::ConsoleSink>(m_IOService, *m_Source);
        
    _last->attach(m_Sink);
}

void RCDCapApplication::initPipeline(popt::variables_map& vm, SourcePtr& _last)
{
    auto hp_enable = vm.count("hp-erm"),
         erspan_enable = vm.count("erspan");
    _last = m_Source;
    if(hp_enable)
    {
        auto _tmp = boost::make_shared<HPERMProcessor>(m_IOService, m_Source->getBuffer(), vm["hp-erm"].as<uint16>(), !vm.count("disable-vlan-tag"));
        _last->attach(_tmp);
        _last = _tmp;
    }
    if(erspan_enable)
    {
        auto _tmp = boost::make_shared<ERSPANProcessor>(m_IOService, m_Source->getBuffer(), !vm.count("disable-vlan-tag"));
        _last->attach(_tmp);
        _last = _tmp;
    }
    for(auto i = m_Plugins.begin(); i != m_Plugins.end(); ++i)
    {
        auto _tmp = (*i)->hasProcessor(*m_Source, vm);
        if(_tmp)
        {
            _last->attach(_tmp);
            _last = _tmp;
        }
    }
}

void RCDCapApplication::terminate()
{
    m_Source->stop();
    m_Signals.reset();
}

RCDCapApplication::SMPAffinityRAII::SMPAffinityRAII(const std::string& dev, size_t cpu_mask)
{
#ifndef _WIN32
    using namespace boost::filesystem;
    path p("/proc/irq");
    if(!exists(p) || !is_directory(p))
        THROW_EXCEPTION("could not access the IRQ kernel interface at /proc/irq");
    for(auto i = directory_iterator(p);; ++i)
    {
        if(i == directory_iterator())
            THROW_EXCEPTION("could not found the IRQ for the specified device");
        if(!is_directory(i->path()))
            continue;
        auto has_eth0 = std::find_if(directory_iterator(i->path()), directory_iterator(), [&dev](const path& pt) { return pt.filename() == dev; });
        if(has_eth0 != directory_iterator())
        {
            auto has_smp_affinity = std::find_if(directory_iterator(i->path()), directory_iterator(), [](const path& pt) { return pt.filename() == "smp_affinity"; });
            if(has_smp_affinity == directory_iterator())
                THROW_EXCEPTION("SMP affinity is not available");
            m_Path = has_smp_affinity->path().native();
            std::fstream fs(m_Path.c_str(), std::ios::out | std::ios::in);
            fs >> m_OldValue;
            fs.seekg(0);
            fs << cpu_mask;
            break;
        }
    }
#endif
}

RCDCapApplication::SMPAffinityRAII::~SMPAffinityRAII()
{
    std::fstream fs(m_Path.c_str(), std::ios::out);
    fs << m_OldValue;
}
}

int main(int argc, char* argv[])
{
    RCDCap::RCDCapApplication rcdcap;
    
    try
    {
        rcdcap.run(argc, argv);
    }
    catch(const popt::error& e)
    {
        std::cerr << "rcdcap: " << e.what() << "\n\n";
        rcdcap.showHelp();
        return EXIT_FAILURE;
    }
    catch(const bsys::system_error& e)
    {
        std::cerr << "rcdcap: error: " << e.what() << std::endl;
        return EXIT_FAILURE;
    }
    catch(const RCDCap::Exception& e)
    {
        std::cerr << "rcdcap:" << e.what() << std::endl;
        return EXIT_FAILURE;
    }
    
    return EXIT_SUCCESS;
}
