/*
 * Copyright 2011 Hylke Vellinga
 */


#ifndef __REASS_PCAP_READER_H__
#define __REASS_PCAP_READER_H__

#include "packet_listener.h"
#include "free_list.h"
#include <string>
#include <pcap.h>

//#define NO_MEMBER_CALLBACK

struct tcp_reassembler_t;
struct udp_reassembler_t;

struct pcap_reader_t : private free_list_container_t<packet_t>
{
	pcap_reader_t(const std::string &fname, packet_listener_t *listener);
	~pcap_reader_t();

	void read_packets(); // read one bufferful of packets

	// FIXME: make interface more flexible.. allow multiple files, live capture, etc

	void flush();
protected:
	void handle_packet(const struct pcap_pkthdr *hdr, const u_char *data); // callback from libpcap
#ifdef NO_MEMBER_CALLBACK
	friend void extra_callback_hop(u_char *user, const struct pcap_pkthdr *hdr, const u_char *data);
#endif

	pcap_t *d_pcap;
	uint64_t d_packetnr;
	int d_linktype;
	packet_listener_t *d_listener;

	tcp_reassembler_t *d_tcp_reassembler;
	udp_reassembler_t *d_udp_reassembler;
};

#endif // __REASS_PCAP_READER_H__
