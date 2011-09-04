cmake_minimum_required (VERSION 2.8)

# find_package( Boost 1.47.0 COMPONENTS thread REQUIRED ) does not work, 1.47 not supported
set(BOOSTDIR /home/weary/code/boost147)
set(Boost_INCLUDE_DIRS ${BOOSTDIR}/include)
set(Boost_LIBRARY_DIRS ${BOOSTDIR}/lib)
set(Boost_THREAD_LIBRARY boost_thread)
#set(Boost_TEST_LIBRARY ${Boost_LIBRARY_DIRS}/libboost_unit_test_framework.a)
set(Boost_TEST_LIBRARY boost_unit_test_framework)

add_definitions(-ggdb3)
add_definitions(-Wall)
add_definitions(-std=gnu++0x)
add_definitions(-DBOOST_TEST_DYN_LINK)
add_definitions(-DDEBUG)
add_definitions(-D_GLIBCXX_DEBUG)
#add_definitions(-DNDEBUG)
#add_definitions(-O3)
include_directories(${Boost_INCLUDE_DIRS} ..)
link_directories(${Boost_LIBRARY_DIRS} ../shared)


file(GLOB ALLCPP "*.cpp")
add_executable(reass ${ALLCPP})
target_link_libraries(reass pcap)
target_link_libraries(reass libmisc.a)



