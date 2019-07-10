FIND_PACKAGE(Boost 1.47 COMPONENTS unit_test_framework REQUIRED)

INCLUDE_DIRECTORIES(${Boost_INCLUDE_DIR}
                    ${CMAKE_SOURCE_DIR}/include
                    ${CMAKE_BINARY_DIR}/include
                    ${CMAKE_SOURCE_DIR}/plugins/quiet-neighborhood/src
                    ${CMAKE_SOURCE_DIR}/external/MurmurHash3
                    ${CMAKE_SOURCE_DIR}/external/xxhash)

SET(MURMURHASH3_SRC
    ${CMAKE_SOURCE_DIR}/external/MurmurHash3/MurmurHash3.cpp
    ${CMAKE_SOURCE_DIR}/external/MurmurHash3/MurmurHash3.h)

SET(XXHASH_SRC
    ${CMAKE_SOURCE_DIR}/external/xxhash/xxhash.c
    ${CMAKE_SOURCE_DIR}/external/xxhash/xxhash.h)

ADD_DEFINITIONS(-DBOOST_TEST_DYN_LINK -mcx16)

ADD_EXECUTABLE(NetworkCacheTest WIN32 network-cache-test.cc
                                      ${CMAKE_SOURCE_DIR}/plugins/quiet-neighborhood/src/network-cache.cc
                                      ${MURMURHASH3_SRC}
                                      ${XXHASH_SRC})

TARGET_LINK_LIBRARIES(NetworkCacheTest rcdcap_core ${Boost_LIBRARIES} pthread)

ADD_TEST(NetworkCacheTest NetworkCacheTest)

ADD_EXECUTABLE(ComputeSubnetTest WIN32 compute-subnet-mask.cc)

TARGET_LINK_LIBRARIES(ComputeSubnetTest rcdcap_core ${Boost_LIBRARIES} pthread)

ADD_TEST(ComputeSubnetTest ComputeSubnetTest)