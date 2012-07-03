cmake_minimum_required (VERSION 2.8)

SET(SOURCES
		ip_address.cpp
		packet.cpp
		pcap_reader.cpp
		tcp_reassembler.cpp
		udp_reassembler.cpp
		../shared/misc.cpp)
add_library(reass ${SOURCES})
target_link_libraries(reass pcap)

