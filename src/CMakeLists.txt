SET(LIBRCDCAP_INC
    ${CMAKE_SOURCE_DIR}/include/rcdcap/source.hh
    ${CMAKE_SOURCE_DIR}/include/rcdcap/exception.hh
    ${CMAKE_SOURCE_DIR}/include/rcdcap/byte-swap.hh
    ${CMAKE_SOURCE_DIR}/include/rcdcap/global.hh
    ${CMAKE_SOURCE_DIR}/include/rcdcap/packet-headers.hh
    ${CMAKE_SOURCE_DIR}/include/rcdcap/types.hh
    ${CMAKE_SOURCE_DIR}/include/rcdcap/memory.hh
    ${CMAKE_SOURCE_DIR}/include/rcdcap/processor.hh
    ${CMAKE_SOURCE_DIR}/include/rcdcap/sink.hh
    ${CMAKE_SOURCE_DIR}/include/rcdcap/erspan-processor.hh
    ${CMAKE_SOURCE_DIR}/include/rcdcap/hp-erm-processor.hh
    ${CMAKE_SOURCE_DIR}/include/rcdcap/decapsulating-processor.hh
    ${CMAKE_SOURCE_DIR}/include/rcdcap/byte-order.hh
    ${CMAKE_SOURCE_DIR}/include/rcdcap/byte-order.ii
    ${CMAKE_SOURCE_DIR}/include/rcdcap/common-buffer.hh
    ${CMAKE_SOURCE_DIR}/include/rcdcap/pcap.hh
    ${CMAKE_SOURCE_DIR}/include/rcdcap/library.hh
    ${CMAKE_SOURCE_DIR}/include/rcdcap/plugin.hh
    ${CMAKE_SOURCE_DIR}/include/rcdcap/threads.hh
   )

SET(RCDCAP_INC
    ${CMAKE_SOURCE_DIR}/include/rcdcap/rcdcap.hh
   )

SET(LIBRCDCAP_SRC
    source.cc
    sink.cc
    erspan-processor.cc
    hp-erm-processor.cc
    decapsulating-processor.cc
    packet-headers.cc
    byte-order.cc
    common-buffer.cc
    pcap.cc
    library.cc
    packet-hierarchy.cc
   )

SET(RCDCAP_SRC
    rcdcap-main.cc
   )

IF(HAS_PF_RING)
    SET(RCDCAP_SRC ${RCDCAP_SRC} pfring-source.cc)
    SET(RCDCAP_INC ${RCDCAP_INC} ${CMAKE_SOURCE_DIR}/include/rcdcap/pfring-source.hh)
    SET(EXTRA_INCS ${EXTRA_INCS} ${LIBPFRING_INCLUDE_DIR})
    SET(EXTRA_LIBS ${EXTRA_LIBS} ${LIBPFRING_LIBRARY})
ENDIF()

LINK_DIRECTORIES(${Boost_LIBRARY_DIRS})

INCLUDE_DIRECTORIES(${Boost_INCLUDE_DIR}
                    ${LIBPCAP_INCLUDE_DIR}
                    ${EXTRA_INCS}
                    ${CMAKE_BINARY_DIR}/include
                    ${CMAKE_SOURCE_DIR}/include
                    ${LIBPCAP_INCLUDE_DIR})

ADD_LIBRARY(rcdcap_core SHARED ${LIBRCDCAP_SRC} ${LIBRCDCAP_INC})

SET_PROPERTY(TARGET rcdcap_core APPEND PROPERTY COMPILE_DEFINITIONS RCDCAP_CORE=1)

IF(CMAKE_MAJOR_VERSION GREATER 2)
    SET(Boost_SUBSET_LIBRARIES Boost::system Boost::thread Boost::date_time Boost::filesystem Boost::regex)
ELSE()
    SET(Boost_SUBSET_LIBRARIES ${Boost_system_LIBRARY} ${Boost_thread_LIBRARY} ${Boost_date_time_LIBRARY} ${Boost_filesystem_LIBRARY} ${Boost_regex_LIBRARY})
ENDIF()

IF(WIN32)
    TARGET_LINK_LIBRARIES(rcdcap_core ${Boost_SUBSET_LIBRARIES} ${LIBPCAP_LIBRARY} ${EXTRA_LIBS})
ELSE()
    TARGET_LINK_LIBRARIES(rcdcap_core ${Boost_LIBRARIES} ${LIBPCAP_LIBRARY} -lsupc++ ${EXTRA_LIBS} -ldl -lpthread)
ENDIF()

ADD_EXECUTABLE(rcdcap ${RCDCAP_SRC} ${RCDCAP_INC})

IF(CMAKE_MAJOR_VERSION GREATER 2)
    TARGET_LINK_LIBRARIES(rcdcap rcdcap_core Boost::program_options)
ELSE()
    TARGET_LINK_LIBRARIES(rcdcap rcdcap_core ${Boost_program_options_LIBRARY})
ENDIF()

INSTALL(TARGETS rcdcap DESTINATION bin)
INSTALL(TARGETS rcdcap_core DESTINATION lib)
