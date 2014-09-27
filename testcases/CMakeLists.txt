cmake_minimum_required (VERSION 2.8)

include_directories(../lib)

if(Boost_UNIT_TEST_FRAMEWORK_LIBRARY)
	add_executable(unittest
			test_refpcap.cpp
			test_freelist.cpp
			test_seqnr.cpp
			testmain.cpp)

	target_link_libraries(unittest ${Boost_UNIT_TEST_FRAMEWORK_LIBRARY})
	target_link_libraries(unittest libreass)

	add_test(Unittests unittest)
else()
	message("Not building unittest, boost_unit_test_framework not found")
endif()
