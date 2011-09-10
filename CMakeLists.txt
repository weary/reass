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
	set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -DDEBUG")
	set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -D_GLIBCXX_DEBUG")
endif()




include_directories(${Boost_INCLUDE_DIRS})
link_directories(${Boost_LIBRARY_DIRS})


file(GLOB ALLCPP "*.cpp")
add_executable(reass ${ALLCPP} shared/misc.cpp)
target_link_libraries(reass pcap)
#target_link_libraries(reass libmisc.a)

#add_executable(blob test.cpp)


