/*
 * Copyright 2011 Hylke Vellinga
 */


#ifndef __REASS_PCAP_READER_H__
#define __REASS_PCAP_READER_H__

#include "reass/packet_listener.h"
#include "reass/free_list.h"
#include "reass/config.h"
#include <string>
#include <pcap.h>

struct tcp_reassembler_t;
struct udp_reassembler_t;

struct pcap_reader_t : private free_list_container_t<packet_t>
{
	pcap_reader_t(packet_listener_t *listener = NULL,
			bool enable_tcp = true, bool enable_udp = true);
	~pcap_reader_t();

	// read_file does open_file, read_packets, close_file together
	void read_file(const std::string &fname, const std::string &bpf = std::string());
	void open_file(const std::string &fname, const std::string &bpf = std::string());
	void close_file();

	void open_live_capture(const std::string &device, bool promiscuous, const std::string &bpf = std::string());
	void close_live_capture();
	void read_packets(); // read one bufferful of packets

	void set_listener(packet_listener_t *listener);
	void flush();

	void enable_tcp_reassembly(bool en); // enabled by default
	void enable_udp_reassembly(bool en); // enabled by default

	// only valid after read_file started
	int linktype() const { return d_linktype; }
	int snaplen() const { return pcap_snapshot(d_pcap); }

	tcp_reassembler_t *tcp_reassembler() const { return d_tcp_reassembler; }
	udp_reassembler_t *udp_reassembler() const { return d_udp_reassembler; }

	uint64_t packets_seen() const { return d_packetnr; }

protected:
	void handle_packet(const struct pcap_pkthdr *hdr, const u_char *data); // callback from libpcap
#ifdef NO_MEMBER_CALLBACK
	friend void extra_callback_hop(u_char *user, const struct pcap_pkthdr *hdr, const u_char *data);
#endif

	void set_bpf(const std::string &bpf);

	pcap_t *d_pcap;
	bpf_program d_bpf;
	int d_linktype;
	packet_listener_t *d_listener;

	uint64_t d_packetnr;

	tcp_reassembler_t *d_tcp_reassembler;
	udp_reassembler_t *d_udp_reassembler;
};

#endif // __REASS_PCAP_READER_H__
