cmake_minimum_required (VERSION 2.8)

add_executable(reass_speedtest reass_speedtest.cpp)
target_link_libraries(reass_speedtest reass)

add_executable(pcap_manual_reorder reorder_main.cpp)
target_link_libraries(pcap_manual_reorder reass)

add_executable(reass_printall reass_printall.cpp)
target_link_libraries(reass_printall reass)

add_executable(reass_monitor_packetloss reass_monitor_packetloss.cpp)
target_link_libraries(reass_monitor_packetloss reass)

if(Boost_REGEX_LIBRARY)
	add_executable(reass_find reass_find.cpp)
	target_link_libraries(reass_find reass ${Boost_REGEX_LIBRARY})
else()
	message("Not building reass_find, because boost_regex could not be found")
endif()
