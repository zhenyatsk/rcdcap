CMAKE_MINIMUM_REQUIRED(VERSION 2.8)

PROJECT(RCDCap)

SET(CMAKE_VERBOSE_MAKEFILE on)

SET(RCDCap_VERSION "0.9.1")
SET(RCDCap_VERSION_MAJOR 0)
SET(RCDCap_VERSION_MINOR 9)
SET(RCDCap_VERSION_PATCH 0)

SET(CPACK_PACKAGE_VERSION ${RCDCap_VERSION})
SET(CPACK_PACKAGE_VERSION_MAJOR ${RCDCap_VERSION_MAJOR})
SET(CPACK_PACKAGE_VERSION_MINOR ${RCDCap_VERSION_MINOR})
SET(CPACK_PACKAGE_VERSION_PATCH ${RCDCap_VERSION_PATCH})

SET(CMAKE_MODULE_PATH ${CMAKE_SOURCE_DIR}/cmake_modules)

INCLUDE(Fedora)
INCLUDE(Ubuntu)
INCLUDE(CPack)

FIND_PACKAGE(Doxygen)
FIND_PACKAGE(LATEX)

SET(RCDCAP_HTML "YES")
IF(RCDCAP_LATEX)
    SET(RCDCAP_HTML "NO")
ENDIF()

#SET(CMAKE_CXX_FLAGS_DEBUG "-g -O0 -ggdb3 -fno-default-inline -fkeep-inline-functions")

IF(APPLE)
    ADD_DEFINITIONS("-DAPPLE")
ELSEIF(UNIX)
    ADD_DEFINITIONS("-DLINUX")
ENDIF()

IF(CMAKE_COMPILER_IS_GNUCXX)
	SET(CMAKE_CXX_FLAGS_DEBUG "-g -O0")
	EXEC_PROGRAM(${CMAKE_CXX_COMPILER}
				 ARGS ${CMAKE_CXX_COMPILER_ARG1} -dumpversion
				 OUTPUT_VARIABLE GCC_COMPILER_VERSION)
	IF(GCC_COMPILER_VERSION VERSION_LESS "4.5")
		MESSAGE(FATAL_ERROR "the version of GCC, which is currently installed, is too old")
	ENDIF()
	ADD_DEFINITIONS("-pedantic -Wall -Wno-long-long -std=c++0x -mcx16 -msse -msse2 -mssse3")
ELSEIF(IS_CLANG)
	SET(CMAKE_CXX_FLAGS_DEBUG "-g -O0")
	ADD_DEFINITIONS("-std=c++11")
	FIND_LIBRARY(HAS_LIBCXX NAMES c++)
	IF(HAS_LIBCXX)
		ADD_DEFINITIONS("-stdlib=libc++")
	ENDIF()
ELSEIF(WIN32)
	
ELSE()
	MESSAGE(FATAL_ERROR "unsupported compiler")
ENDIF()

IF(DOXYGEN_FOUND AND LATEX_COMPILER)
	SET(RCDCAP_DOXYFILE ${CMAKE_BINARY_DIR}/Doxyfile)

	CONFIGURE_FILE(${CMAKE_SOURCE_DIR}/Doxyfile.in
				   ${RCDCAP_DOXYFILE}
				   @ONLY)

	ADD_CUSTOM_TARGET(rcdcap_docs
					  ${DOXYGEN_EXECUTABLE} ${RCDCAP_DOXYFILE}
					  WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
					  VERBATIM)
ENDIF(DOXYGEN_FOUND AND LATEX_COMPILER)

IF(RCDCAP_NODEPS OR RCDCAP_STATIC)
	SET(Boost_USE_STATIC_LIBS    ON)
	SET(Boost_USE_MULTITHREADED  ON)
	SET(Boost_USE_STATIC_RUNTIME ON)
	IF(CMAKE_COMPILER_IS_GNUCXX)
		ADD_DEFINITIONS("-static -pthread")
		IF(RCDCAP_STATIC)
			ADD_DEFINITIONS("-static-libstdc++ -static-libgcc")
		ENDIF()
	ENDIF()
	SET(PCAP_STATIC				 ON)
	SET(PFRING_STATIC			 ON)
	IF(RCDCAP_STATIC)
		SET(CMAKE_CXX_LINK_EXECUTABLE "${CMAKE_CXX_LINK_EXECUTABLE} -Wl,-Bstatic -static-libstdc++ -static-libgcc -static -lpthread")
	ELSE()
		SET(CMAKE_CXX_LINK_EXECUTABLE "${CMAKE_CXX_LINK_EXECUTABLE} -Wl,-Bstatic -static-libstdc++ -static-libgcc -lstdc++ -Wl,-Bdynamic -lpthread")
	ENDIF()
ELSE()
	SET(Boost_USE_STATIC_LIBS    OFF)
	SET(Boost_USE_MULTITHREADED   ON)
	SET(Boost_USE_STATIC_RUNTIME OFF)
	IF(CMAKE_COMPILER_IS_GNUCXX)
		ADD_DEFINITIONS("-pthread")
	ENDIF()
ENDIF()
FIND_PACKAGE(LibPCAP REQUIRED)
FIND_PACKAGE(PF_RING)
IF(LIBPFRING_FOUND)
	SET(HAS_PF_RING ON)
ENDIF()

FIND_PACKAGE(Boost 1.47 COMPONENTS program_options system thread date_time filesystem regex REQUIRED)

ADD_SUBDIRECTORY(src)
ADD_SUBDIRECTORY(include)
ADD_SUBDIRECTORY(share)
ADD_SUBDIRECTORY(tests)

IF(RCDCAP_INSTALL_PLUGINS)
    ADD_SUBDIRECTORY(plugins)
ENDIF()
