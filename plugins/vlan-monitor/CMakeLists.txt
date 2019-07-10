IF(LIBPFRING_FOUND)
	SET(EXTRA_INCS ${LIBPFRING_INCLUDE_DIR})
ENDIF()

INCLUDE_DIRECTORIES(${Boost_INCLUDE_DIR}
                    ${LIBPCAP_INCLUDE_DIR}
                    ${EXTRA_INCS}
                    ${CMAKE_SOURCE_DIR}/include
                    ${CMAKE_BINARY_DIR}/include)

MESSAGE("-- Installing VLAN Monitor plug-in: yes")

ADD_LIBRARY(vlan-monitor MODULE vlan-monitor-processor.cc
                                vlan-monitor-processor.hh)

TARGET_LINK_LIBRARIES(vlan-monitor rcdcap_core)

INSTALL(TARGETS vlan-monitor DESTINATION share/rcdcap/plugins)
