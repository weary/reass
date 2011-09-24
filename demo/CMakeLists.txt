cmake_minimum_required (VERSION 2.8)

include_directories(../lib)

add_executable(reass_speedtest reass_speedtest.cpp)
target_link_libraries(reass_speedtest reass)

add_executable(pcap_manual_reorder reorder_main.cpp)
target_link_libraries(pcap_manual_reorder reass)

add_executable(reass_printall reass_printall.cpp)
target_link_libraries(reass_printall reass)
