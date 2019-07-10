FIND_PACKAGE(Boost COMPONENTS python)
FIND_PACKAGE(PythonLibs)

SET(PYTHON_PLUGINS
    ${CMAKE_CURRENT_SOURCE_DIR}/vlan-monitor.py.example
    ${CMAKE_CURRENT_SOURCE_DIR}/dummy-processor.py.example
   )

IF(LIBPFRING_FOUND)
	SET(EXTRA_INCS ${LIBPFRING_INCLUDE_DIR})
ENDIF()

IF(Boost_PYTHON_FOUND AND PYTHONLIBS_FOUND)
    MESSAGE("-- Installing Python binding plug-in: yes")
    INCLUDE_DIRECTORIES(${Boost_INCLUDE_DIR}
                        ${LIBPCAP_INCLUDE_DIR}
                        ${EXTRA_INCS}
                        ${PYTHON_INCLUDE_DIRS}
                        ${CMAKE_SOURCE_DIR}/include
                        ${CMAKE_BINARY_DIR}/include)

    ADD_LIBRARY(python-binding MODULE python-binding.cc
                                      python-binding.hh)

    TARGET_LINK_LIBRARIES(python-binding rcdcap_core ${PYTHON_LIBRARIES} ${Boost_PYTHON_LIBRARY})

    INSTALL(TARGETS python-binding  DESTINATION share/rcdcap/plugins)
    INSTALL(FILES ${PYTHON_PLUGINS} DESTINATION share/rcdcap/plugins)
ELSE()
    MESSAGE("-- Installing Python binding plug-in: no")
ENDIF()
