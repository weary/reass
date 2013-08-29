cmake_minimum_required (VERSION 2.8)

project(reass)

#set(Boost_INCLUDE_DIRS "/usr/include")  # specify directory containing the "boost" subdirectory
if (NOT Boost_INCLUDE_DIRS)
	find_package( Boost REQUIRED )
	message("${Boost_VERSION}")
	if (NOT Boost_FOUND OR Boost_VERSION EQUAL 104800)
		message("Boost NOT found (or boost 1.48 found, which is unusable)")
		message(FATAL_ERROR "Please update the top CMakeLists.txt and specify your boost path in Boost_INCLUDE_DIRS")
	endif()
endif()

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
	#set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -D_GLIBCXX_DEBUG")
	#message("Building reass with debug libstdc++, make sure to define -D_GLIBCXX_DEBUG when using this library this way")
else()
	set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -DNDEBUG")
endif()


include_directories(.)
include_directories(${Boost_INCLUDE_DIRS})

subdirs(lib)
subdirs(demo)
subdirs(testcases)

