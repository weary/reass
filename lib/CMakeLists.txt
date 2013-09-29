cmake_minimum_required (VERSION 2.8)

SET(SOURCES
		ip_address.cpp
		packet.cpp
		pcap_reader.cpp
		tcp_reassembler.cpp
		udp_reassembler.cpp
		helpers/misc.cpp)
SET(HEADERS
		common_reassembler.h
		common_reassembler.hpp
		config.h
		force_inline.h
		free_list.h
		ip_address.h
		likely.h
		packet.h
		packet_listener.h
		pcap_reader.h
		pcap_writer.h
		tcp_reassembler.h
		timeout.h
		udp_reassembler.h)
SET(HELPERS
		helpers/misc.h
		helpers/timeval_helpers.h)
add_library(libreass ${SOURCES})
set_target_properties(libreass PROPERTIES OUTPUT_NAME "reass")
target_link_libraries(libreass pcap)

INSTALL(FILES ${HEADERS} DESTINATION include/reass)
INSTALL(FILES ${HELPERS} DESTINATION include/reass/helpers)
INSTALL(TARGETS libreass
	RUNTIME DESTINATION bin
	LIBRARY DESTINATION lib
	ARCHIVE DESTINATION lib)
