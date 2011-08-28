/*
 * Copyright 2011 Hylke Vellinga
 */


#ifndef __REASS_PACKET_H__
#define __REASS_PACKET_H__

#include <pcap.h>
#include <fstream>
#include <vector>
#include <string.h>

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

// note: packet_t's get recycled, never delete, use ->free()
struct packet_t
{
	packet_t(packet_t *&free_head);
	~packet_t();

	void set(uint64_t packetnr, int linktype, const struct pcap_pkthdr *hdr, const u_char *data);

	void free()
	{
#ifdef DEBUG
		::memset(d_pcap.data(), 'X', d_pcap.size());
		::memset(d_layers.data(), 'X', d_layers.size()*sizeof(layer_t));
#endif //DEBUG
		d_free_next = d_free_head;
		d_free_head = this;
	}

	void parse_ethernet(u_char *begin, u_char *end);
	void parse_ipv4(u_char *begin, u_char *end);
	void parse_ipv6(u_char *begin, u_char *end);
	void parse_tcp(u_char *begin, u_char *end);
	void parse_udp(u_char *begin, u_char *end);

	void dump(std::ostream &os) const;

	layer_t *layer(int n)
 	{
		if (n < 0)
			return (-n <= (int)d_layercount ? &d_layers[d_layercount+n] : NULL);
		else
			return (n < (int)d_layercount ? &d_layers[n] : NULL);
	}

protected:
	void add_layer(layer_types, u_char *begin, u_char *end);

	packet_t *&d_free_head;
	packet_t *d_free_next;

	uint64_t d_packetnr;
	struct timeval d_ts;
	uint32_t d_caplen, d_len, d_layercount;
	std::vector<u_char> d_pcap; // contains at least caplen bytes
	std::vector<layer_t> d_layers;
};

std::ostream &operator <<(std::ostream &os, const packet_t &p);

#endif // __REASS_PACKET_H__

