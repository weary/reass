/*
 * Copyright 2011 Hylke Vellinga
 */


#ifndef __REASS_PCAP_READER_H__
#define __REASS_PCAP_READER_H__

#include "reass/packet_entrypoint.h"
#include <pcap.h>


struct pcap_reader_t : protected packet_entrypoint_t
{
	pcap_reader_t(packet_listener_t *listener = NULL,
			bool enable_tcp = true, bool enable_udp = true);
	~pcap_reader_t();

	// read_file does open_file, read_packets, close_file together
	void read_file(const std::string &fname, const std::string &bpf = std::string());
	void open_file(const std::string &fname, const std::string &bpf = std::string());
	void close_file();

	void open_live_capture(const std::string &device, bool promiscuous, const std::string &bpf = std::string(),
			int snaplen=2048, int buffersize=0 /*platform default*/);
	void close_live_capture();
	void read_packets(); // read one bufferful of packets

	void stop_reading(); // stop pcap_readpackets

	// only valid after read_file started
	int linktype() const { return packet_entrypoint_t::linktype(); }
	int snaplen() const { return pcap_snapshot(d_pcap); }

	void flush() { packet_entrypoint_t::flush(); }

protected:
	void set_bpf(const std::string &bpf);

	pcap_t *d_pcap;
};

#endif // __REASS_PCAP_READER_H__
