cmake_minimum_required (VERSION 2.8)

# cmake -G 'Unix Makefiles' -DCMAKE_BUILD_TYPE=Release

find_package( Boost REQUIRED )
#include(../boost147/CMakeInclude.txt) # boost 147 not supported by find_package

IF(NOT DEFINED CMAKE_BUILD_TYPE)
   SET(CMAKE_BUILD_TYPE Debug CACHE STRING "Choose the type of build, options are: Debug Release RelWithDebInfo MinSizeRel.")
ENDIF()

add_definitions(-Wall)
add_definitions(-std=gnu++0x)
add_definitions(-DBOOST_TEST_DYN_LINK)

if(NOT CMAKE_BUILD_TYPE OR CMAKE_BUILD_TYPE STREQUAL "Debug" OR CMAKE_BUILD_TYPE STREQUAL "RelWithDebInfo")
	set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -ggdb3")
endif()
if(NOT CMAKE_BUILD_TYPE OR CMAKE_BUILD_TYPE STREQUAL "Debug")
	set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -DDEBUG")
	set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -D_GLIBCXX_DEBUG")
else()
	set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -DNDEBUG")
endif()


include_directories(${Boost_INCLUDE_DIRS})
link_directories(${Boost_LIBRARY_DIRS})

add_library(reass
		ip_address.cpp
		packet.cpp
		pcap_reader.cpp
		tcp_reassembler.cpp
		shared/misc.cpp
		)
target_link_libraries(reass pcap)


add_executable(reass_thingy reass_thingy.cpp)
target_link_libraries(reass_thingy reass ssl)

add_executable(reass_speedtest reass_speedtest.cpp)
target_link_libraries(reass_speedtest reass)

add_executable(pcap_manual_reorder reorder_main.cpp)
target_link_libraries(pcap_manual_reorder reass)
