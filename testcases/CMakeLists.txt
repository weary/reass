cmake_minimum_required (VERSION 2.8)

include_directories(../lib)

add_executable(unittest
		test_refpcap.cpp
		testmain.cpp
		)

target_link_libraries(unittest boost_unit_test_framework)
target_link_libraries(unittest reass)




