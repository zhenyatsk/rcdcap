FIND_PACKAGE(Boost 1.47 COMPONENTS unit_test_framework REQUIRED)

INCLUDE_DIRECTORIES(${Boost_INCLUDE_DIR}
                    ${CMAKE_SOURCE_DIR}/include
                    ${CMAKE_BINARY_DIR}/include)

ADD_DEFINITIONS(-DBOOST_TEST_DYN_LINK) 

ADD_EXECUTABLE(AddressConversionTest address-conversion.cc)

TARGET_LINK_LIBRARIES(AddressConversionTest rcdcap_core ${Boost_LIBRARIES})

ADD_TEST(AddressConversionTest AddressConversionTest)

ADD_EXECUTABLE(ByteSwapTest byte-swap-test.cc)

TARGET_LINK_LIBRARIES(ByteSwapTest rcdcap_core ${Boost_LIBRARIES})

ADD_TEST(ByteSwapTest ByteSwapTest)