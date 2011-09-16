/*
 * Copyright 2011 Hylke Vellinga
 */


#ifndef __REASS_PACKET_H__
#define __REASS_PACKET_H__

#include <pcap.h>
#include <fstream>
#include <vector>
#include <string.h>
#include <stdint.h>
#include "free_list.h"

#define MAX_LAYERS 8

enum layer_type
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
	const u_char *begin() const { return d_begin; }
	const u_char *end() const { return d_end; }
	const u_char *data() const { return begin(); }
	layer_type type() const { return d_type; }
	size_t size() const { return d_end-d_begin; }

	void set(const u_char *begin, const u_char *end, layer_type type)
	{
		d_begin = begin;
		d_end = end;
		d_type = type;
	}

protected:
	friend class packet_t;

	const u_char *d_begin;
	const u_char *d_end;
	layer_type d_type;
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

	layer_t *layer(int n);
	const layer_t *layer(int n) const;
	const layer_t *next(const layer_t *layer) const; // move away from ethernet
	const layer_t *prev(const layer_t *layer) const; // move towards ethernet


#ifdef DEBUG // for non-debug, baseclass provides
	void release()
	{
		assert(is_initialised()); // only free once
		::memset(d_pcap.data(), 'Y', d_pcap.size());
		::memset(d_layers, 'Y', MAX_LAYERS*sizeof(layer_t));
		//d_packetnr = (uint64_t)-1;
		d_is_initialised = 2;
		free_list_member_t<packet_t>::release();
	}

	bool is_initialised() const { return d_is_initialised == 1; }
#endif //DEBUG

	uint64_t packetnr() const { return d_packetnr; }
	timeval ts() const { return d_pckthdr.ts; }

	const u_char *data() const { return d_pcap.data(); }
	const pcap_pkthdr &pckthdr() const { return d_pckthdr; }

	void add_layer(layer_type, const u_char *begin, const u_char *end);
protected:
	uint64_t d_packetnr;
	struct pcap_pkthdr d_pckthdr; // contains ts/caplen/len
	uint32_t d_layercount;
	std::vector<u_char> d_pcap; // contains at least caplen bytes
	layer_t d_layers[MAX_LAYERS];
#ifdef DEBUG
	int d_is_initialised;
#endif
};

inline layer_t *packet_t::layer(int n)
{
	if (n < 0)
		return (-n <= (int)d_layercount ? &d_layers[d_layercount+n] : NULL);
	else
		return (n < (int)d_layercount ? &d_layers[n] : NULL);
}

inline const layer_t *packet_t::next(const layer_t *layer) const // move away from ethernet
{
	assert(layer >= d_layers && layer <= d_layers + d_layercount - 1);
	return (layer == d_layers + d_layercount - 1 ? NULL : layer + 1);
}

inline const layer_t *packet_t::prev(const layer_t *layer) const // move towards ethernet
{
	assert(layer >= d_layers && layer <= d_layers + d_layercount - 1);
	return (layer == d_layers ? NULL : layer - 1);
}

inline const layer_t *packet_t::layer(int n) const
{
	return const_cast<packet_t *>(this)->layer(n);
}

std::ostream &operator <<(std::ostream &os, const packet_t &p);

#endif // __REASS_PACKET_H__

