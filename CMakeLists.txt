cmake_minimum_required(VERSION 3.6)

SET(PROJECT_NAME dhcp)
SET(DHCP_NETWORK src/dhcp-network)
SET(DHCP_CLI src/dhcp-cli)
SET(DHCP_LEASE src/dhcp-lease)
SET(DHCPD src/dhcpd)

PROJECT(${PROJECT_NAME})

FIND_PACKAGE(Git QUIET)

FIND_PATH(CUNIT_INCLUDE_DIR NAMES CUnit/CUnit.h)

FIND_LIBRARY(CUNIT_LIBRARY NAMES 
    cunit
    libcunit
    cunitlib
)

IF(NOT CUNIT_INCLUDE_DIR)
    message(FATAL_ERROR "Cunit header files not found")
ENDIF()


IF(NOT CUNIT_LIBRARY)
    message(FATAL_ERROR "Cunit library not found")
ENDIF()

message("\n--------------------------------\n")
message("PROJECT NAME:\t\t${PROJECT_NAME}")
message("CMAKE_SYSTEM_NAME:\t${CMAKE_SYSTEM_NAME}")
message("CMAKE_C_COMPILER:\t${CMAKE_C_COMPILER}")
message("CMAKE_CXX_COMPILER:\t${CMAKE_CXX_COMPILER}")
message("CMAKE_BINARY_DIR:\t${CMAKE_BINARY_DIR}")
message("CUNIT_LIBRARY:\t\t${CUNIT_LIBRARY}")
message("\n--------------------------------\n")

IF(GIT_FOUND AND EXISTS "../.git")
    option(GIT_SUBMODULE "Check submodules during build" ON)
    if(GIT_SUBMODULE)
        message(STATUS "Submodule update")
        execute_process(COMMAND ${GIT_EXECUTABLE} submodule update --init --recursive
                        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
                        RESULT_VARIABLE GIT_SUBMOD_RESULT)
        if(NOT GIT_SUBMOD_RESULT EQUAL "0")
            message(FATAL_ERROR "git submodule update --init --recursive failed with ${GIT_SUBMOD_RESULT}, please checkout submodules")
        endif()
    endif()
endif()

add_subdirectory(${DHCP_NETWORK})
add_subdirectory(${DHCP_CLI})
add_subdirectory(${DHCP_LEASE})
add_subdirectory(${DHCPD})