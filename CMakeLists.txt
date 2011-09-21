cmake_minimum_required (VERSION 2.8)

project(reass)

find_package( Boost REQUIRED )
#include(../boost147/CMakeInclude.txt) # boost 147 not supported by find_package

IF(NOT DEFINED CMAKE_BUILD_TYPE)
   SET(CMAKE_BUILD_TYPE Debug CACHE STRING "Choose the type of build, options are: Debug Release RelWithDebInfo MinSizeRel.")
ENDIF()

add_definitions(-Wall)
add_definitions(-std=gnu++0x)
add_definitions(-DBOOST_TEST_DYN_LINK)
add_definitions(-march=native)

if(NOT CMAKE_BUILD_TYPE OR CMAKE_BUILD_TYPE STREQUAL "Debug" OR CMAKE_BUILD_TYPE STREQUAL "RelWithDebInfo")
	set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -ggdb3")
endif()
if(NOT CMAKE_BUILD_TYPE OR CMAKE_BUILD_TYPE STREQUAL "Debug")
	set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -DDEBUG")
	set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -D_GLIBCXX_DEBUG")
else()
	set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -DNDEBUG")
endif()


include_directories(.)
include_directories(${Boost_INCLUDE_DIRS})
link_directories(${Boost_LIBRARY_DIRS})

subdirs(lib)
subdirs(demo)
subdirs(testcases)

