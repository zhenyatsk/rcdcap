IF(LIBPFRING_FOUND)
    SET(EXTRA_INCS ${LIBPFRING_INCLUDE_DIR})
ENDIF()

INCLUDE_DIRECTORIES(${Boost_INCLUDE_DIR}
                    ${LIBPCAP_INCLUDE_DIR}
                    ${EXTRA_INCS}
                    ${CMAKE_SOURCE_DIR}/include
                    ${CMAKE_BINARY_DIR}/include)

MESSAGE("-- Installing Statistics Sink plug-in: yes")

ADD_LIBRARY(statistics-sink MODULE statistics-sink.cc)

TARGET_LINK_LIBRARIES(statistics-sink rcdcap_core)

INSTALL(TARGETS statistics-sink DESTINATION share/rcdcap/plugins)