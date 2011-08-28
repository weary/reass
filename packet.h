/*
 * Copyright 2011 Hylke Vellinga
 */


#ifndef __REASS_PACKET_H__
#define __REASS_PACKET_H__

#include <pcap.h>
#include <fstream>
#include <vector>
#include <string.h>
#include "free_list.h"

#define MAX_LAYERS 8

enum layer_types
{
	layer_ethernet, // ether_header
	layer_ipv4, // iphdr
	layer_ipv6, // ip6_hdr
	layer_tcp, // tcphdr
	layer_udp, // udphdr
	layer_icmp,
	layer_data
};

struct layer_t
{
	layer_types type;
	const u_char *begin;
	const u_char *end;
	size_t size() const { return end-begin; }
};
std::ostream &operator <<(std::ostream &os, const layer_t &l);

// note: packet_t's get recycled, never delete, use ->release()
struct packet_t : public free_list_member_t<packet_t>
{
	packet_t(packet_t *&free_head);
	~packet_t();

	void init(uint64_t packetnr, int linktype, const struct pcap_pkthdr *hdr, const u_char *data);

	void parse_ethernet(u_char *begin, u_char *end);
	void parse_ipv4(u_char *begin, u_char *end);
	void parse_ipv6(u_char *begin, u_char *end);
	void parse_tcp(u_char *begin, u_char *end);
	void parse_udp(u_char *begin, u_char *end);

	void print(std::ostream &os) const;

	layer_t *layer(int n)
 	{
		if (n < 0)
			return (-n <= (int)d_layercount ? &d_layers[d_layercount+n] : NULL);
		else
			return (n < (int)d_layercount ? &d_layers[n] : NULL);
	}

	const layer_t *layer(int n) const
	{
		return const_cast<packet_t *>(this)->layer(n);
	}

#ifdef DEBUG // for non-debug, baseclass provides
	void release()
	{
		::memset(d_pcap.data(), 'X', d_pcap.size());
		::memset(d_layers, 'X', MAX_LAYERS*sizeof(layer_t));
		free_list_member_t<packet_t>::release();
	}
#endif //DEBUG

protected:
	void add_layer(layer_types, u_char *begin, u_char *end);

	uint64_t d_packetnr;
	struct timeval d_ts;
	uint32_t d_caplen, d_len, d_layercount;
	std::vector<u_char> d_pcap; // contains at least caplen bytes
	layer_t d_layers[MAX_LAYERS];
};

std::ostream &operator <<(std::ostream &os, const packet_t &p);

#endif // __REASS_PACKET_H__

