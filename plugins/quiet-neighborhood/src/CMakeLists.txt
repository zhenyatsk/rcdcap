IF(LIBPFRING_FOUND)
    SET(EXTRA_INCS ${LIBPFRING_INCLUDE_DIR})
ENDIF()

MESSAGE("-- Installing Quiet Neighborhood Toolbox: yes")
INCLUDE_DIRECTORIES(${Boost_INCLUDE_DIR}
                    ${LIBPCAP_INCLUDE_DIR}
                    ${EXTRA_INCS}
                    ${CMAKE_SOURCE_DIR}/include
                    ${CMAKE_BINARY_DIR}/include
                    ${CMAKE_SOURCE_DIR}/external/MurmurHash3
                    ${CMAKE_SOURCE_DIR}/external/xxhash)

ADD_DEFINITIONS(-mcx16)

SET(MURMURHASH3_SRC
    ${CMAKE_SOURCE_DIR}/external/MurmurHash3/MurmurHash3.cpp
    ${CMAKE_SOURCE_DIR}/external/MurmurHash3/MurmurHash3.h)

SET(XXHASH_SRC
    ${CMAKE_SOURCE_DIR}/external/xxhash/xxhash.c
    ${CMAKE_SOURCE_DIR}/external/xxhash/xxhash.h)

ADD_LIBRARY(quiet-neighborhood MODULE arp-monitor.cc
                                      dhcp-monitor.cc
                                      quiet-neighborhood-monitor.hh
                                      quiet-neighborhood-monitor.cc
                                      ndp-monitor.cc
                                      quiet-neighborhood.hh
                                      quiet-neighborhood.cc
                                      network-cache.cc
                                      network-cache.hh
                                      ${MURMURHASH3_SRC}
                                      ${XXHASH_SRC})

TARGET_LINK_LIBRARIES(quiet-neighborhood rcdcap_core)

INSTALL(TARGETS quiet-neighborhood DESTINATION share/rcdcap/plugins)