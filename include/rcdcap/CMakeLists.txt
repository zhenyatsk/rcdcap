CONFIGURE_FILE(config.hh.in ${CMAKE_BINARY_DIR}/include/rcdcap/config.hh)

SET(RCDCAP_INC
    byte-order.hh
    byte-order.ii
    byte-swap.hh
    common-buffer.hh
    ${CMAKE_BINARY_DIR}/include/rcdcap/config.hh
    decapsulating-processor.hh
    erspan-processor.hh
    exception.hh
    global.hh
    hp-erm-processor.hh
    library.hh
    memory.hh
    packet-headers.hh
    pcap.hh
    plugin.hh
    processor.hh
#   rcdcap.hh
    sink.hh
    source.hh
    types.hh
    threads.hh
   )

IF(LIBPFRING_FOUND)
    SET(RCDCAP_INC ${RCDCAP_INC} pfring-source.hh)
ENDIF()

INSTALL(FILES ${RCDCAP_INC} DESTINATION "include/rcdcap")
