cmake_minimum_required (VERSION 2.8)

if(Boost_SYSTEM_LIBRARY AND Boost_FILESYSTEM_LIBRARY)
	add_executable(reass_speedtest reass_speedtest.cpp)
	target_link_libraries(reass_speedtest libreass)
	target_link_libraries(reass_speedtest ${Boost_SYSTEM_LIBRARY} ${Boost_FILESYSTEM_LIBRARY})

	add_executable(pcap_manual_reorder reorder_main.cpp)
	target_link_libraries(pcap_manual_reorder libreass ${Boost_FILESYSTEM_LIBRARY})
	target_link_libraries(pcap_manual_reorder ${Boost_SYSTEM_LIBRARY} ${Boost_FILESYSTEM_LIBRARY})

	add_executable(reass_printall reass_printall.cpp)
	target_link_libraries(reass_printall libreass ${Boost_FILESYSTEM_LIBRARY})
	target_link_libraries(reass_printall ${Boost_SYSTEM_LIBRARY} ${Boost_FILESYSTEM_LIBRARY})

	add_executable(reass_monitor_packetloss reass_monitor_packetloss.cpp)
	target_link_libraries(reass_monitor_packetloss libreass ${Boost_FILESYSTEM_LIBRARY})
	target_link_libraries(reass_monitor_packetloss ${Boost_SYSTEM_LIBRARY} ${Boost_FILESYSTEM_LIBRARY})
else()
	message("Not building demo applications, boost-system or boost-filesystem not found")
endif()
