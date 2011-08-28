/*
 * Copyright 2011 Hylke Vellinga
 */


#ifndef __REASS_PCAP_READER_H__
#define __REASS_PCAP_READER_H__

#include "packet_listener.h"
#include <string>
#include <pcap.h>

struct tcp_reassembler_t;
struct udp_reassembler_t;

struct pcap_reader_t
{
	pcap_reader_t(const std::string &fname, packet_listener_t *listener);
	~pcap_reader_t();

	void read_packets(); // read one bufferful of packets

protected:
	void handle_packet(const struct pcap_pkthdr *hdr, const u_char *data); // callback from libpcap

	pcap_t *d_pcap;
	uint64_t d_packetnr;
	int d_linktype;
	packet_listener_t *d_listener;

	tcp_reassembler_t *d_tcp_reassembler;
	udp_reassembler_t *d_udp_reassembler;

	packet_t *d_free_head;
};

#endif // __REASS_PCAP_READER_H__
